"""
Cryptographic Audit Ledger (CAL)

Immutable, append-only audit ledger using hash chaining and Merkle aggregation.
Provides tamper-evident records and efficient inclusion proofs.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
import hashlib
import json
import math


@dataclass
class AuditRecord:
    """Represents a single audit record."""
    record_id: str
    event_id: str
    timestamp: datetime
    event_type: str
    tenant_id: str
    bucket: str
    object_key: Optional[str] = None
    policy_commitment: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    previous_hash: Optional[str] = None
    record_hash: Optional[str] = None
    
    def compute_hash(self) -> str:
        """Compute hash of this record."""
        data = {
            "record_id": self.record_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "bucket": self.bucket,
            "object_key": self.object_key,
            "policy_commitment": self.policy_commitment,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
        }
        json_data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_data.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "record_id": self.record_id,
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "tenant_id": self.tenant_id,
            "bucket": self.bucket,
            "object_key": self.object_key,
            "policy_commitment": self.policy_commitment,
            "metadata": self.metadata,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


class MerkleNode:
    """Represents a node in a Merkle tree."""
    
    def __init__(self, hash_value: str, left: Optional['MerkleNode'] = None, 
                 right: Optional['MerkleNode'] = None):
        self.hash = hash_value
        self.left = left
        self.right = right
    
    def is_leaf(self) -> bool:
        """Check if this is a leaf node."""
        return self.left is None and self.right is None


@dataclass
class MerkleProof:
    """Represents a Merkle inclusion proof."""
    leaf_hash: str
    root_hash: str
    proof_hashes: List[Tuple[str, str]]  # (hash, position: 'left' or 'right')
    
    def verify(self) -> bool:
        """Verify the Merkle proof."""
        current_hash = self.leaf_hash
        
        for proof_hash, position in self.proof_hashes:
            if position == 'left':
                combined = proof_hash + current_hash
            else:
                combined = current_hash + proof_hash
            
            current_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        return current_hash == self.root_hash


class MerkleTree:
    """Merkle tree implementation for efficient inclusion proofs."""
    
    def __init__(self, leaves: List[str]):
        """
        Build a Merkle tree from leaf hashes.
        
        Args:
            leaves: List of leaf hash values
        """
        self.leaves = leaves
        self.root = self._build_tree(leaves)
    
    def _build_tree(self, hashes: List[str]) -> Optional[MerkleNode]:
        """Build Merkle tree from list of hashes."""
        if not hashes:
            return None
        
        if len(hashes) == 1:
            return MerkleNode(hashes[0])
        
        # Build current level
        nodes = [MerkleNode(h) for h in hashes]
        
        # Build tree bottom-up
        while len(nodes) > 1:
            next_level = []
            
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                
                if i + 1 < len(nodes):
                    right = nodes[i + 1]
                else:
                    # Duplicate last node if odd number
                    right = nodes[i]
                
                # Combine hashes
                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                parent = MerkleNode(parent_hash, left, right)
                next_level.append(parent)
            
            nodes = next_level
        
        return nodes[0]
    
    def get_root_hash(self) -> str:
        """Get the Merkle root hash."""
        return self.root.hash if self.root else ""
    
    def generate_proof(self, leaf_hash: str) -> Optional[MerkleProof]:
        """
        Generate a Merkle inclusion proof for a leaf.
        
        Args:
            leaf_hash: Hash of the leaf to prove
            
        Returns:
            MerkleProof if leaf exists, None otherwise
        """
        if leaf_hash not in self.leaves:
            return None
        
        leaf_index = self.leaves.index(leaf_hash)
        proof_hashes = []
        
        # Get proof path
        current_level = [MerkleNode(h) for h in self.leaves]
        current_index = leaf_index
        
        while len(current_level) > 1:
            next_level = []
            
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    right = current_level[i]
                
                # If current node is part of the proof path
                if i == current_index or i + 1 == current_index:
                    if i == current_index:
                        # Current is left, need right sibling
                        if i + 1 < len(current_level) and right != left:
                            proof_hashes.append((right.hash, 'right'))
                        current_index = i // 2
                    else:
                        # Current is right, need left sibling
                        proof_hashes.append((left.hash, 'left'))
                        current_index = i // 2
                
                combined = left.hash + right.hash
                parent_hash = hashlib.sha256(combined.encode()).hexdigest()
                next_level.append(MerkleNode(parent_hash, left, right))
            
            current_level = next_level
        
        return MerkleProof(
            leaf_hash=leaf_hash,
            root_hash=self.get_root_hash(),
            proof_hashes=proof_hashes
        )


class AuditLedger:
    """
    Immutable, append-only audit ledger with hash chaining and Merkle trees.
    
    The ledger:
    1. Maintains hash chain for sequential integrity
    2. Builds Merkle trees for efficient inclusion proofs
    3. Provides tamper-evident guarantees
    """
    
    def __init__(self):
        self.records: List[AuditRecord] = []
        self.record_index: Dict[str, int] = {}  # record_id -> index
        self.merkle_trees: List[MerkleTree] = []  # Periodic Merkle trees
        self.tree_batch_size = 100  # Build tree every N records
    
    def append(self, record: AuditRecord) -> str:
        """
        Append a record to the ledger.
        
        Args:
            record: Audit record to append
            
        Returns:
            Hash of the appended record
        """
        # Set previous hash for chain
        if self.records:
            record.previous_hash = self.records[-1].record_hash
        else:
            record.previous_hash = "0" * 64  # Genesis hash
        
        # Compute and set record hash
        record.record_hash = record.compute_hash()
        
        # Append to ledger
        self.records.append(record)
        self.record_index[record.record_id] = len(self.records) - 1
        
        # Build Merkle tree if batch is complete
        if len(self.records) % self.tree_batch_size == 0:
            self._build_merkle_tree()
        
        return record.record_hash
    
    def _build_merkle_tree(self) -> None:
        """Build a Merkle tree for the latest batch of records."""
        start_idx = len(self.merkle_trees) * self.tree_batch_size
        end_idx = start_idx + self.tree_batch_size
        
        batch_records = self.records[start_idx:end_idx]
        leaf_hashes = [r.record_hash for r in batch_records]
        
        tree = MerkleTree(leaf_hashes)
        self.merkle_trees.append(tree)
    
    def get_record(self, record_id: str) -> Optional[AuditRecord]:
        """
        Retrieve a record by ID.
        
        Args:
            record_id: Record identifier
            
        Returns:
            AuditRecord if found, None otherwise
        """
        idx = self.record_index.get(record_id)
        if idx is not None:
            return self.records[idx]
        return None
    
    def verify_chain_integrity(self) -> bool:
        """
        Verify the integrity of the hash chain.
        
        Returns:
            True if chain is intact, False if tampered
        """
        for i, record in enumerate(self.records):
            # Check hash computation
            expected_hash = record.compute_hash()
            if record.record_hash != expected_hash:
                return False
            
            # Check chain link
            if i > 0:
                if record.previous_hash != self.records[i - 1].record_hash:
                    return False
            else:
                if record.previous_hash != "0" * 64:
                    return False
        
        return True
    
    def generate_inclusion_proof(self, record_id: str) -> Optional[MerkleProof]:
        """
        Generate a Merkle inclusion proof for a record.
        
        Args:
            record_id: Record identifier
            
        Returns:
            MerkleProof if record exists and is in a completed batch
        """
        idx = self.record_index.get(record_id)
        if idx is None:
            return None
        
        # Find which tree contains this record
        tree_index = idx // self.tree_batch_size
        
        if tree_index >= len(self.merkle_trees):
            # Record not yet in a completed Merkle tree
            return None
        
        record = self.records[idx]
        tree = self.merkle_trees[tree_index]
        
        return tree.generate_proof(record.record_hash)
    
    def get_record_count(self) -> int:
        """Get total number of records in the ledger."""
        return len(self.records)
    
    def get_latest_record(self) -> Optional[AuditRecord]:
        """Get the most recent record."""
        return self.records[-1] if self.records else None
