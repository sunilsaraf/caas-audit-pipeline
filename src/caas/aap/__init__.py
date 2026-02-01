"""
Adaptive Audit Pipeline (AAP)

Multi-level audit pipeline with configurable fidelity levels.
Supports dynamic configuration based on policy criticality, tenant, bucket, or object class.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import uuid

from ..cei import ComplianceEvent, EventType
from ..pac import CanonicalPolicy
from ..cal import AuditRecord, AuditLedger


class AuditFidelity(Enum):
    """Audit fidelity levels."""
    METADATA_ONLY = "metadata_only"  # Only metadata, no chaining
    CHAINED = "chained"  # Hash-chained records
    POLICY_BOUND = "policy_bound"  # Includes policy commitments
    MERKLE_PROOF = "merkle_proof"  # Full Merkle tree proofs


class PolicyCriticality(Enum):
    """Policy criticality levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditConfiguration:
    """Configuration for audit pipeline."""
    default_fidelity: AuditFidelity = AuditFidelity.CHAINED
    tenant_configs: Dict[str, AuditFidelity] = field(default_factory=dict)
    bucket_configs: Dict[str, AuditFidelity] = field(default_factory=dict)
    criticality_configs: Dict[PolicyCriticality, AuditFidelity] = field(
        default_factory=lambda: {
            PolicyCriticality.LOW: AuditFidelity.METADATA_ONLY,
            PolicyCriticality.MEDIUM: AuditFidelity.CHAINED,
            PolicyCriticality.HIGH: AuditFidelity.POLICY_BOUND,
            PolicyCriticality.CRITICAL: AuditFidelity.MERKLE_PROOF,
        }
    )
    
    def get_fidelity(
        self, 
        tenant_id: str, 
        bucket: str, 
        criticality: Optional[PolicyCriticality] = None
    ) -> AuditFidelity:
        """
        Determine audit fidelity based on context.
        
        Args:
            tenant_id: Tenant identifier
            bucket: Bucket name
            criticality: Policy criticality level
            
        Returns:
            Appropriate audit fidelity level
        """
        # Check tenant-specific config
        if tenant_id in self.tenant_configs:
            return self.tenant_configs[tenant_id]
        
        # Check bucket-specific config
        bucket_key = f"{tenant_id}/{bucket}"
        if bucket_key in self.bucket_configs:
            return self.bucket_configs[bucket_key]
        
        # Check criticality-based config
        if criticality and criticality in self.criticality_configs:
            return self.criticality_configs[criticality]
        
        # Return default
        return self.default_fidelity


@dataclass
class ProcessedAuditEvent:
    """Represents a processed audit event with selected fidelity."""
    event: ComplianceEvent
    fidelity: AuditFidelity
    audit_record: Optional[AuditRecord]
    policy_commitment: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


class AdaptiveAuditPipeline:
    """
    Adaptive audit pipeline with multi-level fidelity support.
    
    The pipeline:
    1. Receives compliance events
    2. Determines appropriate audit fidelity
    3. Creates audit records with selected fidelity level
    4. Routes records to the audit ledger
    """
    
    def __init__(
        self, 
        ledger: AuditLedger,
        config: Optional[AuditConfiguration] = None
    ):
        """
        Initialize the adaptive audit pipeline.
        
        Args:
            ledger: Cryptographic audit ledger
            config: Audit configuration (uses defaults if not provided)
        """
        self.ledger = ledger
        self.config = config or AuditConfiguration()
        self.processed_events: List[ProcessedAuditEvent] = []
        self.event_handlers: List[Callable[[ProcessedAuditEvent], None]] = []
    
    def register_handler(
        self, 
        handler: Callable[[ProcessedAuditEvent], None]
    ) -> None:
        """
        Register a handler for processed events.
        
        Args:
            handler: Callback function
        """
        self.event_handlers.append(handler)
    
    def process_event(
        self, 
        event: ComplianceEvent,
        policy: Optional[CanonicalPolicy] = None,
        criticality: Optional[PolicyCriticality] = None
    ) -> ProcessedAuditEvent:
        """
        Process a compliance event through the adaptive pipeline.
        
        Args:
            event: Compliance event to process
            policy: Associated policy (if applicable)
            criticality: Policy criticality level
            
        Returns:
            ProcessedAuditEvent with applied fidelity
        """
        # Determine appropriate fidelity
        fidelity = self.config.get_fidelity(
            event.tenant_id, 
            event.bucket, 
            criticality
        )
        
        # Create audit record based on fidelity
        audit_record = None
        policy_commitment = None
        
        if fidelity == AuditFidelity.METADATA_ONLY:
            # Minimal record - metadata only
            audit_record = self._create_metadata_record(event)
            
        elif fidelity == AuditFidelity.CHAINED:
            # Hash-chained record
            audit_record = self._create_chained_record(event)
            
        elif fidelity == AuditFidelity.POLICY_BOUND:
            # Include policy commitment
            if policy:
                policy_commitment = policy.commitment_hash
            audit_record = self._create_policy_bound_record(event, policy_commitment)
            
        elif fidelity == AuditFidelity.MERKLE_PROOF:
            # Full record with Merkle tree support
            if policy:
                policy_commitment = policy.commitment_hash
            audit_record = self._create_merkle_record(event, policy_commitment)
        
        # Append to ledger if record was created
        if audit_record:
            self.ledger.append(audit_record)
        
        # Create processed event
        processed = ProcessedAuditEvent(
            event=event,
            fidelity=fidelity,
            audit_record=audit_record,
            policy_commitment=policy_commitment
        )
        
        self.processed_events.append(processed)
        
        # Call registered handlers
        for handler in self.event_handlers:
            try:
                handler(processed)
            except Exception as e:
                print(f"Handler error: {e}")
        
        return processed
    
    def _create_metadata_record(self, event: ComplianceEvent) -> AuditRecord:
        """Create a metadata-only audit record."""
        return AuditRecord(
            record_id=str(uuid.uuid4()),
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type.value,
            tenant_id=event.tenant_id,
            bucket=event.bucket,
            object_key=event.object_key,
            metadata={
                "fidelity": AuditFidelity.METADATA_ONLY.value,
                "principal": event.principal,
            }
        )
    
    def _create_chained_record(self, event: ComplianceEvent) -> AuditRecord:
        """Create a hash-chained audit record."""
        return AuditRecord(
            record_id=str(uuid.uuid4()),
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type.value,
            tenant_id=event.tenant_id,
            bucket=event.bucket,
            object_key=event.object_key,
            metadata={
                "fidelity": AuditFidelity.CHAINED.value,
                "principal": event.principal,
                "event_metadata": event.metadata,
            }
        )
    
    def _create_policy_bound_record(
        self, 
        event: ComplianceEvent,
        policy_commitment: Optional[str]
    ) -> AuditRecord:
        """Create a policy-bound audit record."""
        return AuditRecord(
            record_id=str(uuid.uuid4()),
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type.value,
            tenant_id=event.tenant_id,
            bucket=event.bucket,
            object_key=event.object_key,
            policy_commitment=policy_commitment,
            metadata={
                "fidelity": AuditFidelity.POLICY_BOUND.value,
                "principal": event.principal,
                "event_metadata": event.metadata,
            }
        )
    
    def _create_merkle_record(
        self, 
        event: ComplianceEvent,
        policy_commitment: Optional[str]
    ) -> AuditRecord:
        """Create a full audit record with Merkle tree support."""
        return AuditRecord(
            record_id=str(uuid.uuid4()),
            event_id=event.event_id,
            timestamp=event.timestamp,
            event_type=event.event_type.value,
            tenant_id=event.tenant_id,
            bucket=event.bucket,
            object_key=event.object_key,
            policy_commitment=policy_commitment,
            metadata={
                "fidelity": AuditFidelity.MERKLE_PROOF.value,
                "principal": event.principal,
                "event_metadata": event.metadata,
                "supports_merkle_proof": True,
            }
        )
    
    def update_configuration(self, config: AuditConfiguration) -> None:
        """
        Update pipeline configuration.
        
        Args:
            config: New audit configuration
        """
        self.config = config
    
    def set_tenant_fidelity(self, tenant_id: str, fidelity: AuditFidelity) -> None:
        """
        Set fidelity level for a specific tenant.
        
        Args:
            tenant_id: Tenant identifier
            fidelity: Audit fidelity level
        """
        self.config.tenant_configs[tenant_id] = fidelity
    
    def set_bucket_fidelity(
        self, 
        tenant_id: str, 
        bucket: str, 
        fidelity: AuditFidelity
    ) -> None:
        """
        Set fidelity level for a specific bucket.
        
        Args:
            tenant_id: Tenant identifier
            bucket: Bucket name
            fidelity: Audit fidelity level
        """
        bucket_key = f"{tenant_id}/{bucket}"
        self.config.bucket_configs[bucket_key] = fidelity
    
    def get_processed_events(self) -> List[ProcessedAuditEvent]:
        """Get all processed events."""
        return self.processed_events.copy()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get pipeline statistics.
        
        Returns:
            Dictionary with processing statistics
        """
        fidelity_counts = {}
        for processed in self.processed_events:
            fidelity = processed.fidelity.value
            fidelity_counts[fidelity] = fidelity_counts.get(fidelity, 0) + 1
        
        return {
            "total_processed": len(self.processed_events),
            "fidelity_distribution": fidelity_counts,
            "ledger_record_count": self.ledger.get_record_count(),
        }
