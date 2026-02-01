package com.caas.cal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Proof element in a Merkle proof.
 */
class ProofElement {
    private String hash;
    private String position; // "left" or "right"

    public ProofElement(String hash, String position) {
        this.hash = hash;
        this.position = position;
    }

    public String getHash() {
        return hash;
    }

    public String getPosition() {
        return position;
    }
}

/**
 * Represents a Merkle inclusion proof.
 */
public class MerkleProof {
    private String leafHash;
    private String rootHash;
    private List<ProofElement> proofHashes;

    public MerkleProof(String leafHash, String rootHash, List<ProofElement> proofHashes) {
        this.leafHash = leafHash;
        this.rootHash = rootHash;
        this.proofHashes = proofHashes;
    }

    /**
     * Verify the Merkle proof.
     *
     * @return true if proof is valid
     */
    public boolean verify() {
        String currentHash = leafHash;

        for (ProofElement element : proofHashes) {
            String combined;
            if ("left".equals(element.getPosition())) {
                combined = element.getHash() + currentHash;
            } else {
                combined = currentHash + element.getHash();
            }

            currentHash = sha256(combined);
        }

        return currentHash.equals(rootHash);
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder();
            for (byte b : hash) {
                result.append(String.format("%02x", b));
            }
            return result.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    // Getters
    public String getLeafHash() {
        return leafHash;
    }

    public String getRootHash() {
        return rootHash;
    }

    public List<ProofElement> getProofHashes() {
        return proofHashes;
    }
}
