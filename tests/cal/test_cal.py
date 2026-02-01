"""
Unit tests for Cryptographic Audit Ledger (CAL)
"""

import pytest
from datetime import datetime
import uuid

from caas.cal import (
    AuditRecord, AuditLedger, MerkleTree, MerkleProof, MerkleNode
)


class TestAuditRecord:
    """Test AuditRecord class."""
    
    def test_record_creation(self):
        """Test creating an audit record."""
        record = AuditRecord(
            record_id=str(uuid.uuid4()),
            event_id="evt-123",
            timestamp=datetime.utcnow(),
            event_type="object.create",
            tenant_id="tenant-1",
            bucket="test-bucket",
            object_key="test.txt"
        )
        
        assert record.record_id is not None
        assert record.event_id == "evt-123"
        assert record.tenant_id == "tenant-1"
    
    def test_record_hash_computation(self):
        """Test computing record hash."""
        record = AuditRecord(
            record_id="rec-123",
            event_id="evt-123",
            timestamp=datetime(2024, 1, 1, 12, 0, 0),
            event_type="object.create",
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        hash1 = record.compute_hash()
        hash2 = record.compute_hash()
        
        # Hash should be deterministic
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256
    
    def test_record_to_dict(self):
        """Test converting record to dictionary."""
        record_id = str(uuid.uuid4())
        timestamp = datetime.utcnow()
        
        record = AuditRecord(
            record_id=record_id,
            event_id="evt-123",
            timestamp=timestamp,
            event_type="object.create",
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        record_dict = record.to_dict()
        
        assert record_dict["record_id"] == record_id
        assert record_dict["event_id"] == "evt-123"
        assert record_dict["tenant_id"] == "tenant-1"


class TestMerkleTree:
    """Test MerkleTree class."""
    
    def test_single_leaf_tree(self):
        """Test Merkle tree with single leaf."""
        leaves = ["hash1"]
        tree = MerkleTree(leaves)
        
        assert tree.get_root_hash() == "hash1"
    
    def test_two_leaf_tree(self):
        """Test Merkle tree with two leaves."""
        leaves = ["hash1", "hash2"]
        tree = MerkleTree(leaves)
        
        root = tree.get_root_hash()
        assert root is not None
        assert len(root) == 64  # SHA-256
    
    def test_multiple_leaf_tree(self):
        """Test Merkle tree with multiple leaves."""
        leaves = ["hash1", "hash2", "hash3", "hash4"]
        tree = MerkleTree(leaves)
        
        root = tree.get_root_hash()
        assert root is not None
        assert len(root) == 64
    
    def test_generate_proof(self):
        """Test generating Merkle proof."""
        leaves = ["hash1", "hash2", "hash3", "hash4"]
        tree = MerkleTree(leaves)
        
        proof = tree.generate_proof("hash2")
        
        assert proof is not None
        assert proof.leaf_hash == "hash2"
        assert proof.root_hash == tree.get_root_hash()
    
    def test_proof_for_nonexistent_leaf(self):
        """Test generating proof for non-existent leaf."""
        leaves = ["hash1", "hash2"]
        tree = MerkleTree(leaves)
        
        proof = tree.generate_proof("hash3")
        
        assert proof is None


class TestMerkleProof:
    """Test MerkleProof class."""
    
    def test_proof_verification(self):
        """Test verifying a Merkle proof."""
        leaves = ["hash1", "hash2", "hash3", "hash4"]
        tree = MerkleTree(leaves)
        
        # Generate and verify proof for each leaf
        for leaf in leaves:
            proof = tree.generate_proof(leaf)
            assert proof is not None
            assert proof.verify() is True


class TestAuditLedger:
    """Test AuditLedger class."""
    
    def test_ledger_creation(self):
        """Test creating an audit ledger."""
        ledger = AuditLedger()
        
        assert ledger.get_record_count() == 0
        assert ledger.get_latest_record() is None
    
    def test_append_single_record(self):
        """Test appending a single record."""
        ledger = AuditLedger()
        
        record = AuditRecord(
            record_id="rec-1",
            event_id="evt-1",
            timestamp=datetime.utcnow(),
            event_type="object.create",
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        record_hash = ledger.append(record)
        
        assert record_hash is not None
        assert ledger.get_record_count() == 1
        assert record.previous_hash == "0" * 64  # Genesis hash
    
    def test_append_multiple_records(self):
        """Test appending multiple records and hash chaining."""
        ledger = AuditLedger()
        
        # Append first record
        record1 = AuditRecord(
            record_id="rec-1",
            event_id="evt-1",
            timestamp=datetime.utcnow(),
            event_type="object.create",
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        hash1 = ledger.append(record1)
        
        # Append second record
        record2 = AuditRecord(
            record_id="rec-2",
            event_id="evt-2",
            timestamp=datetime.utcnow(),
            event_type="object.update",
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        hash2 = ledger.append(record2)
        
        # Verify chain
        assert record2.previous_hash == hash1
        assert ledger.get_record_count() == 2
    
    def test_get_record(self):
        """Test retrieving a record by ID."""
        ledger = AuditLedger()
        
        record = AuditRecord(
            record_id="rec-1",
            event_id="evt-1",
            timestamp=datetime.utcnow(),
            event_type="object.create",
            tenant_id="tenant-1",
            bucket="test-bucket"
        )
        
        ledger.append(record)
        retrieved = ledger.get_record("rec-1")
        
        assert retrieved is not None
        assert retrieved.record_id == "rec-1"
        assert retrieved.event_id == "evt-1"
    
    def test_get_nonexistent_record(self):
        """Test retrieving a non-existent record."""
        ledger = AuditLedger()
        
        retrieved = ledger.get_record("nonexistent")
        
        assert retrieved is None
    
    def test_verify_chain_integrity(self):
        """Test verifying ledger chain integrity."""
        ledger = AuditLedger()
        
        # Append several records
        for i in range(5):
            record = AuditRecord(
                record_id=f"rec-{i}",
                event_id=f"evt-{i}",
                timestamp=datetime.utcnow(),
                event_type="object.create",
                tenant_id="tenant-1",
                bucket="test-bucket"
            )
            ledger.append(record)
        
        # Verify integrity
        assert ledger.verify_chain_integrity() is True
    
    def test_detect_tampered_record(self):
        """Test detecting a tampered record."""
        ledger = AuditLedger()
        
        # Append records
        for i in range(3):
            record = AuditRecord(
                record_id=f"rec-{i}",
                event_id=f"evt-{i}",
                timestamp=datetime.utcnow(),
                event_type="object.create",
                tenant_id="tenant-1",
                bucket="test-bucket"
            )
            ledger.append(record)
        
        # Tamper with a record
        ledger.records[1].event_type = "object.delete"  # Change event type
        
        # Verify integrity should fail
        assert ledger.verify_chain_integrity() is False
    
    def test_merkle_tree_generation(self):
        """Test automatic Merkle tree generation."""
        ledger = AuditLedger()
        ledger.tree_batch_size = 10
        
        # Append enough records to trigger tree generation
        for i in range(10):
            record = AuditRecord(
                record_id=f"rec-{i}",
                event_id=f"evt-{i}",
                timestamp=datetime.utcnow(),
                event_type="object.create",
                tenant_id="tenant-1",
                bucket="test-bucket"
            )
            ledger.append(record)
        
        # Should have one Merkle tree
        assert len(ledger.merkle_trees) == 1
    
    def test_generate_inclusion_proof(self):
        """Test generating Merkle inclusion proof."""
        ledger = AuditLedger()
        ledger.tree_batch_size = 5
        
        # Append records
        for i in range(5):
            record = AuditRecord(
                record_id=f"rec-{i}",
                event_id=f"evt-{i}",
                timestamp=datetime.utcnow(),
                event_type="object.create",
                tenant_id="tenant-1",
                bucket="test-bucket"
            )
            ledger.append(record)
        
        # Generate proof for a record
        proof = ledger.generate_inclusion_proof("rec-2")
        
        assert proof is not None
        assert proof.verify() is True
    
    def test_get_latest_record(self):
        """Test getting the latest record."""
        ledger = AuditLedger()
        
        # Append records
        for i in range(3):
            record = AuditRecord(
                record_id=f"rec-{i}",
                event_id=f"evt-{i}",
                timestamp=datetime.utcnow(),
                event_type="object.create",
                tenant_id="tenant-1",
                bucket="test-bucket"
            )
            ledger.append(record)
        
        latest = ledger.get_latest_record()
        
        assert latest is not None
        assert latest.record_id == "rec-2"
