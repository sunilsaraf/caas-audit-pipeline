package com.caas.cal;

import java.util.*;

/**
 * Immutable, append-only audit ledger with hash chaining and Merkle trees.
 */
public class AuditLedger {
    private final List<AuditRecord> records;
    private final Map<String, Integer> recordIndex;
    private final List<MerkleTree> merkleTrees;
    private int treeBatchSize;

    private static final String GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    public AuditLedger() {
        this.records = new ArrayList<>();
        this.recordIndex = new HashMap<>();
        this.merkleTrees = new ArrayList<>();
        this.treeBatchSize = 100;
    }

    /**
     * Append a record to the ledger.
     *
     * @param record Audit record to append
     * @return Hash of the appended record
     */
    public String append(AuditRecord record) {
        // Set previous hash for chain
        if (!records.isEmpty()) {
            record.setPreviousHash(records.get(records.size() - 1).getRecordHash());
        } else {
            record.setPreviousHash(GENESIS_HASH);
        }

        // Compute and set record hash
        record.setRecordHash(record.computeHash());

        // Append to ledger
        records.add(record);
        recordIndex.put(record.getRecordId(), records.size() - 1);

        // Build Merkle tree if batch is complete
        if (records.size() % treeBatchSize == 0) {
            buildMerkleTree();
        }

        return record.getRecordHash();
    }

    private void buildMerkleTree() {
        int startIdx = merkleTrees.size() * treeBatchSize;
        int endIdx = Math.min(startIdx + treeBatchSize, records.size());

        List<String> leafHashes = new ArrayList<>();
        for (int i = startIdx; i < endIdx; i++) {
            leafHashes.add(records.get(i).getRecordHash());
        }

        MerkleTree tree = new MerkleTree(leafHashes);
        merkleTrees.add(tree);
    }

    public AuditRecord getRecord(String recordId) {
        Integer idx = recordIndex.get(recordId);
        if (idx != null) {
            return records.get(idx);
        }
        return null;
    }

    /**
     * Verify the integrity of the hash chain.
     *
     * @return true if chain is intact, false if tampered
     */
    public boolean verifyChainIntegrity() {
        for (int i = 0; i < records.size(); i++) {
            AuditRecord record = records.get(i);

            // Check hash computation
            String expectedHash = record.computeHash();
            if (!record.getRecordHash().equals(expectedHash)) {
                return false;
            }

            // Check chain link
            if (i > 0) {
                if (!record.getPreviousHash().equals(records.get(i - 1).getRecordHash())) {
                    return false;
                }
            } else {
                if (!record.getPreviousHash().equals(GENESIS_HASH)) {
                    return false;
                }
            }
        }

        return true;
    }

    public MerkleProof generateInclusionProof(String recordId) {
        Integer idx = recordIndex.get(recordId);
        if (idx == null) {
            return null;
        }

        // Find which tree contains this record
        int treeIndex = idx / treeBatchSize;

        if (treeIndex >= merkleTrees.size()) {
            // Record not yet in a completed Merkle tree
            return null;
        }

        AuditRecord record = records.get(idx);
        MerkleTree tree = merkleTrees.get(treeIndex);

        return tree.generateProof(record.getRecordHash());
    }

    public int getRecordCount() {
        return records.size();
    }

    public AuditRecord getLatestRecord() {
        return records.isEmpty() ? null : records.get(records.size() - 1);
    }

    public List<AuditRecord> getRecords() {
        return new ArrayList<>(records);
    }

    public void setTreeBatchSize(int size) {
        this.treeBatchSize = size;
    }
}
