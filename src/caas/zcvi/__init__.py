"""
Zero-Trust Verification API (ZCVI)

Produces Compliance Proof Bundles (CPBs) for offline validation by third-party auditors.
Includes audit records, policy commitments, Merkle proofs, and anchoring references.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
import json
from enum import Enum

from ..cal import AuditRecord, AuditLedger, MerkleProof
from ..pac import CanonicalPolicy, PolicyCompiler
from ..aap import ProcessedAuditEvent


class ProofBundleType(Enum):
    """Types of compliance proof bundles."""
    SINGLE_RECORD = "single_record"
    BATCH_RECORDS = "batch_records"
    TIME_RANGE = "time_range"
    TENANT_SCOPE = "tenant_scope"


@dataclass
class AnchoringReference:
    """Reference to external anchoring system (e.g., blockchain, timestamp service)."""
    anchor_type: str  # "blockchain", "timestamp_service", "notary"
    anchor_id: str
    timestamp: datetime
    anchor_hash: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "anchor_type": self.anchor_type,
            "anchor_id": self.anchor_id,
            "timestamp": self.timestamp.isoformat(),
            "anchor_hash": self.anchor_hash,
            "metadata": self.metadata,
        }


@dataclass
class ComplianceProofBundle:
    """
    Complete compliance proof bundle for offline validation.
    
    Contains all necessary information for a third-party auditor to verify:
    - Record integrity (hash chains)
    - Policy bindings (cryptographic commitments)
    - Inclusion proofs (Merkle trees)
    - External anchoring (optional)
    """
    bundle_id: str
    bundle_type: ProofBundleType
    created_at: datetime
    records: List[AuditRecord]
    policy_commitments: Dict[str, str]  # policy_id -> commitment_hash
    merkle_proofs: List[MerkleProof]
    anchoring_refs: List[AnchoringReference] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert bundle to dictionary for serialization."""
        return {
            "bundle_id": self.bundle_id,
            "bundle_type": self.bundle_type.value,
            "created_at": self.created_at.isoformat(),
            "records": [r.to_dict() for r in self.records],
            "policy_commitments": self.policy_commitments,
            "merkle_proofs": [
                {
                    "leaf_hash": p.leaf_hash,
                    "root_hash": p.root_hash,
                    "proof_hashes": p.proof_hashes,
                }
                for p in self.merkle_proofs
            ],
            "anchoring_refs": [ref.to_dict() for ref in self.anchoring_refs],
            "metadata": self.metadata,
        }
    
    def to_json(self) -> str:
        """Convert bundle to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    def verify_integrity(self) -> bool:
        """
        Verify the integrity of the proof bundle.
        
        Returns:
            True if all verifications pass
        """
        # Verify hash chain
        for i, record in enumerate(self.records):
            # Check record hash
            if record.record_hash != record.compute_hash():
                return False
            
            # Check chain link
            if i > 0:
                if record.previous_hash != self.records[i - 1].record_hash:
                    return False
        
        # Verify Merkle proofs
        for proof in self.merkle_proofs:
            if not proof.verify():
                return False
        
        return True


class VerificationAPI:
    """
    Zero-Trust Verification API for generating compliance proof bundles.
    
    Provides methods to create CPBs for various use cases:
    - Single record verification
    - Batch record verification
    - Time range verification
    - Tenant-scoped verification
    """
    
    def __init__(self, ledger: AuditLedger, policy_compiler: PolicyCompiler):
        """
        Initialize the verification API.
        
        Args:
            ledger: Cryptographic audit ledger
            policy_compiler: Policy compiler for commitments
        """
        self.ledger = ledger
        self.policy_compiler = policy_compiler
        self.anchoring_refs: List[AnchoringReference] = []
    
    def create_single_record_bundle(
        self, 
        record_id: str,
        include_merkle_proof: bool = True
    ) -> Optional[ComplianceProofBundle]:
        """
        Create a proof bundle for a single record.
        
        Args:
            record_id: Record identifier
            include_merkle_proof: Whether to include Merkle proof
            
        Returns:
            ComplianceProofBundle if record exists
        """
        record = self.ledger.get_record(record_id)
        if not record:
            return None
        
        # Collect policy commitments
        policy_commitments = {}
        if record.policy_commitment:
            policy_commitments["policy"] = record.policy_commitment
        
        # Generate Merkle proof if requested
        merkle_proofs = []
        if include_merkle_proof:
            proof = self.ledger.generate_inclusion_proof(record_id)
            if proof:
                merkle_proofs.append(proof)
        
        # Create bundle
        bundle = ComplianceProofBundle(
            bundle_id=f"bundle-{record_id}",
            bundle_type=ProofBundleType.SINGLE_RECORD,
            created_at=datetime.utcnow(),
            records=[record],
            policy_commitments=policy_commitments,
            merkle_proofs=merkle_proofs,
            anchoring_refs=self._get_relevant_anchors([record]),
            metadata={
                "record_count": 1,
                "has_merkle_proof": len(merkle_proofs) > 0,
            }
        )
        
        return bundle
    
    def create_batch_bundle(
        self, 
        record_ids: List[str],
        include_merkle_proofs: bool = True
    ) -> Optional[ComplianceProofBundle]:
        """
        Create a proof bundle for multiple records.
        
        Args:
            record_ids: List of record identifiers
            include_merkle_proofs: Whether to include Merkle proofs
            
        Returns:
            ComplianceProofBundle with all found records
        """
        records = []
        for record_id in record_ids:
            record = self.ledger.get_record(record_id)
            if record:
                records.append(record)
        
        if not records:
            return None
        
        # Collect policy commitments
        policy_commitments = {}
        for record in records:
            if record.policy_commitment:
                policy_commitments[record.record_id] = record.policy_commitment
        
        # Generate Merkle proofs if requested
        merkle_proofs = []
        if include_merkle_proofs:
            for record_id in record_ids:
                proof = self.ledger.generate_inclusion_proof(record_id)
                if proof:
                    merkle_proofs.append(proof)
        
        # Create bundle
        bundle = ComplianceProofBundle(
            bundle_id=f"bundle-batch-{datetime.utcnow().timestamp()}",
            bundle_type=ProofBundleType.BATCH_RECORDS,
            created_at=datetime.utcnow(),
            records=records,
            policy_commitments=policy_commitments,
            merkle_proofs=merkle_proofs,
            anchoring_refs=self._get_relevant_anchors(records),
            metadata={
                "record_count": len(records),
                "requested_count": len(record_ids),
                "has_merkle_proofs": len(merkle_proofs) > 0,
            }
        )
        
        return bundle
    
    def create_time_range_bundle(
        self,
        start_time: datetime,
        end_time: datetime,
        tenant_id: Optional[str] = None,
        include_merkle_proofs: bool = False
    ) -> ComplianceProofBundle:
        """
        Create a proof bundle for records in a time range.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            tenant_id: Optional tenant filter
            include_merkle_proofs: Whether to include Merkle proofs
            
        Returns:
            ComplianceProofBundle with matching records
        """
        # Filter records by time range
        records = []
        for record in self.ledger.records:
            if start_time <= record.timestamp <= end_time:
                if tenant_id is None or record.tenant_id == tenant_id:
                    records.append(record)
        
        # Collect policy commitments
        policy_commitments = {}
        for record in records:
            if record.policy_commitment:
                policy_commitments[record.record_id] = record.policy_commitment
        
        # Generate Merkle proofs if requested
        merkle_proofs = []
        if include_merkle_proofs:
            for record in records:
                proof = self.ledger.generate_inclusion_proof(record.record_id)
                if proof:
                    merkle_proofs.append(proof)
        
        # Create bundle
        bundle = ComplianceProofBundle(
            bundle_id=f"bundle-timerange-{start_time.timestamp()}-{end_time.timestamp()}",
            bundle_type=ProofBundleType.TIME_RANGE,
            created_at=datetime.utcnow(),
            records=records,
            policy_commitments=policy_commitments,
            merkle_proofs=merkle_proofs,
            anchoring_refs=self._get_relevant_anchors(records),
            metadata={
                "record_count": len(records),
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "tenant_id": tenant_id,
                "has_merkle_proofs": len(merkle_proofs) > 0,
            }
        )
        
        return bundle
    
    def create_tenant_bundle(
        self,
        tenant_id: str,
        include_merkle_proofs: bool = False
    ) -> ComplianceProofBundle:
        """
        Create a proof bundle for all records of a tenant.
        
        Args:
            tenant_id: Tenant identifier
            include_merkle_proofs: Whether to include Merkle proofs
            
        Returns:
            ComplianceProofBundle with tenant's records
        """
        # Filter records by tenant
        records = [r for r in self.ledger.records if r.tenant_id == tenant_id]
        
        # Collect policy commitments
        policy_commitments = {}
        for record in records:
            if record.policy_commitment:
                policy_commitments[record.record_id] = record.policy_commitment
        
        # Generate Merkle proofs if requested
        merkle_proofs = []
        if include_merkle_proofs:
            for record in records:
                proof = self.ledger.generate_inclusion_proof(record.record_id)
                if proof:
                    merkle_proofs.append(proof)
        
        # Create bundle
        bundle = ComplianceProofBundle(
            bundle_id=f"bundle-tenant-{tenant_id}",
            bundle_type=ProofBundleType.TENANT_SCOPE,
            created_at=datetime.utcnow(),
            records=records,
            policy_commitments=policy_commitments,
            merkle_proofs=merkle_proofs,
            anchoring_refs=self._get_relevant_anchors(records),
            metadata={
                "record_count": len(records),
                "tenant_id": tenant_id,
                "has_merkle_proofs": len(merkle_proofs) > 0,
            }
        )
        
        return bundle
    
    def add_anchoring_reference(self, anchor: AnchoringReference) -> None:
        """
        Add an external anchoring reference.
        
        Args:
            anchor: Anchoring reference to add
        """
        self.anchoring_refs.append(anchor)
    
    def _get_relevant_anchors(
        self, 
        records: List[AuditRecord]
    ) -> List[AnchoringReference]:
        """
        Get anchoring references relevant to the given records.
        
        Args:
            records: List of audit records
            
        Returns:
            List of relevant anchoring references
        """
        if not records:
            return []
        
        # Get time range of records
        min_time = min(r.timestamp for r in records)
        max_time = max(r.timestamp for r in records)
        
        # Find anchors in the time range
        relevant = [
            anchor for anchor in self.anchoring_refs
            if min_time <= anchor.timestamp <= max_time
        ]
        
        return relevant
    
    def verify_bundle(self, bundle: ComplianceProofBundle) -> Dict[str, Any]:
        """
        Verify a compliance proof bundle.
        
        Args:
            bundle: Proof bundle to verify
            
        Returns:
            Dictionary with verification results
        """
        results = {
            "bundle_id": bundle.bundle_id,
            "verification_time": datetime.utcnow().isoformat(),
            "integrity_check": False,
            "chain_verification": False,
            "merkle_verification": False,
            "policy_verification": False,
            "errors": [],
        }
        
        # Check integrity
        try:
            results["integrity_check"] = bundle.verify_integrity()
        except Exception as e:
            results["errors"].append(f"Integrity check failed: {e}")
        
        # Verify hash chain
        chain_valid = True
        for i, record in enumerate(bundle.records):
            if record.record_hash != record.compute_hash():
                chain_valid = False
                results["errors"].append(f"Hash mismatch for record {record.record_id}")
            
            if i > 0:
                if record.previous_hash != bundle.records[i - 1].record_hash:
                    chain_valid = False
                    results["errors"].append(f"Chain break at record {record.record_id}")
        
        results["chain_verification"] = chain_valid
        
        # Verify Merkle proofs
        merkle_valid = True
        for proof in bundle.merkle_proofs:
            if not proof.verify():
                merkle_valid = False
                results["errors"].append(f"Merkle proof failed for {proof.leaf_hash}")
        
        results["merkle_verification"] = merkle_valid
        
        # Verify policy commitments
        policy_valid = True
        for record_id, commitment in bundle.policy_commitments.items():
            # In a real system, we would verify against known policies
            if not commitment or len(commitment) != 64:
                policy_valid = False
                results["errors"].append(f"Invalid policy commitment for {record_id}")
        
        results["policy_verification"] = policy_valid
        
        # Overall result
        results["valid"] = (
            results["integrity_check"] and
            results["chain_verification"] and
            (len(bundle.merkle_proofs) == 0 or results["merkle_verification"]) and
            results["policy_verification"]
        )
        
        return results
