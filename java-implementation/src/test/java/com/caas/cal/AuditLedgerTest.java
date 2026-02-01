package com.caas.cal;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Cryptographic Audit Ledger (CAL)
 */
class AuditLedgerTest {

    @Test
    void testLedgerCreation() {
        AuditLedger ledger = new AuditLedger();
        
        assertEquals(0, ledger.getRecordCount());
        assertNull(ledger.getLatestRecord());
    }

    @Test
    void testAppendSingleRecord() {
        AuditLedger ledger = new AuditLedger();
        
        AuditRecord record = new AuditRecord(
            "rec-1",
            "evt-1",
            Instant.now(),
            "object.create",
            "tenant-1",
            "test-bucket"
        );
        
        String recordHash = ledger.append(record);
        
        assertNotNull(recordHash);
        assertEquals(1, ledger.getRecordCount());
        assertEquals("0".repeat(64), record.getPreviousHash()); // Genesis hash
    }

    @Test
    void testAppendMultipleRecords() {
        AuditLedger ledger = new AuditLedger();
        
        // Append first record
        AuditRecord record1 = new AuditRecord(
            "rec-1",
            "evt-1",
            Instant.now(),
            "object.create",
            "tenant-1",
            "test-bucket"
        );
        String hash1 = ledger.append(record1);
        
        // Append second record
        AuditRecord record2 = new AuditRecord(
            "rec-2",
            "evt-2",
            Instant.now(),
            "object.update",
            "tenant-1",
            "test-bucket"
        );
        String hash2 = ledger.append(record2);
        
        // Verify chain
        assertEquals(hash1, record2.getPreviousHash());
        assertEquals(2, ledger.getRecordCount());
    }

    @Test
    void testGetRecord() {
        AuditLedger ledger = new AuditLedger();
        
        AuditRecord record = new AuditRecord(
            "rec-1",
            "evt-1",
            Instant.now(),
            "object.create",
            "tenant-1",
            "test-bucket"
        );
        
        ledger.append(record);
        AuditRecord retrieved = ledger.getRecord("rec-1");
        
        assertNotNull(retrieved);
        assertEquals("rec-1", retrieved.getRecordId());
        assertEquals("evt-1", retrieved.getEventId());
    }

    @Test
    void testGetNonexistentRecord() {
        AuditLedger ledger = new AuditLedger();
        
        AuditRecord retrieved = ledger.getRecord("nonexistent");
        
        assertNull(retrieved);
    }

    @Test
    void testVerifyChainIntegrity() {
        AuditLedger ledger = new AuditLedger();
        
        // Append several records
        for (int i = 0; i < 5; i++) {
            AuditRecord record = new AuditRecord(
                "rec-" + i,
                "evt-" + i,
                Instant.now(),
                "object.create",
                "tenant-1",
                "test-bucket"
            );
            ledger.append(record);
        }
        
        // Verify integrity
        assertTrue(ledger.verifyChainIntegrity());
    }

    @Test
    void testDetectTamperedRecord() {
        AuditLedger ledger = new AuditLedger();
        
        // Append records
        for (int i = 0; i < 3; i++) {
            AuditRecord record = new AuditRecord(
                "rec-" + i,
                "evt-" + i,
                Instant.now(),
                "object.create",
                "tenant-1",
                "test-bucket"
            );
            ledger.append(record);
        }
        
        // Tamper with a record
        ledger.getRecords().get(1).setEventType("object.delete");
        
        // Verify integrity should fail
        assertFalse(ledger.verifyChainIntegrity());
    }

    @Test
    void testMerkleTreeGeneration() {
        AuditLedger ledger = new AuditLedger();
        ledger.setTreeBatchSize(10);
        
        // Append enough records to trigger tree generation
        for (int i = 0; i < 10; i++) {
            AuditRecord record = new AuditRecord(
                "rec-" + i,
                "evt-" + i,
                Instant.now(),
                "object.create",
                "tenant-1",
                "test-bucket"
            );
            ledger.append(record);
        }
        
        // Should have triggered tree generation (internal state check via proof generation)
        MerkleProof proof = ledger.generateInclusionProof("rec-5");
        assertNotNull(proof);
    }

    @Test
    void testMerkleTreeProof() {
        MerkleTree tree = new MerkleTree(Arrays.asList("hash1", "hash2", "hash3", "hash4"));
        
        MerkleProof proof = tree.generateProof("hash2");
        
        assertNotNull(proof);
        assertEquals("hash2", proof.getLeafHash());
        assertTrue(proof.verify());
    }

    @Test
    void testGetLatestRecord() {
        AuditLedger ledger = new AuditLedger();
        
        // Append records
        for (int i = 0; i < 3; i++) {
            AuditRecord record = new AuditRecord(
                "rec-" + i,
                "evt-" + i,
                Instant.now(),
                "object.create",
                "tenant-1",
                "test-bucket"
            );
            ledger.append(record);
        }
        
        AuditRecord latest = ledger.getLatestRecord();
        
        assertNotNull(latest);
        assertEquals("rec-2", latest.getRecordId());
    }
}
