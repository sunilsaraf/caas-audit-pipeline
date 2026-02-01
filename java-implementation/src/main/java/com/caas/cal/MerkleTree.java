package com.caas.cal;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a node in a Merkle tree.
 */
class MerkleNode {
    private String hash;
    private MerkleNode left;
    private MerkleNode right;

    public MerkleNode(String hash) {
        this(hash, null, null);
    }

    public MerkleNode(String hash, MerkleNode left, MerkleNode right) {
        this.hash = hash;
        this.left = left;
        this.right = right;
    }

    public boolean isLeaf() {
        return left == null && right == null;
    }

    public String getHash() {
        return hash;
    }

    public MerkleNode getLeft() {
        return left;
    }

    public MerkleNode getRight() {
        return right;
    }
}

/**
 * Merkle tree implementation for efficient inclusion proofs.
 */
public class MerkleTree {
    private List<String> leaves;
    private MerkleNode root;

    public MerkleTree(List<String> leaves) {
        this.leaves = new ArrayList<>(leaves);
        this.root = buildTree(new ArrayList<>(leaves));
    }

    private MerkleNode buildTree(List<String> hashes) {
        if (hashes.isEmpty()) {
            return null;
        }

        if (hashes.size() == 1) {
            return new MerkleNode(hashes.get(0));
        }

        // Build current level
        List<MerkleNode> nodes = new ArrayList<>();
        for (String hash : hashes) {
            nodes.add(new MerkleNode(hash));
        }

        // Build tree bottom-up
        while (nodes.size() > 1) {
            List<MerkleNode> nextLevel = new ArrayList<>();

            for (int i = 0; i < nodes.size(); i += 2) {
                MerkleNode left = nodes.get(i);
                MerkleNode right;

                if (i + 1 < nodes.size()) {
                    right = nodes.get(i + 1);
                } else {
                    // Duplicate last node if odd number
                    right = nodes.get(i);
                }

                // Combine hashes
                String combined = left.getHash() + right.getHash();
                String parentHash = sha256(combined);
                nextLevel.add(new MerkleNode(parentHash, left, right));
            }

            nodes = nextLevel;
        }

        return nodes.get(0);
    }

    public String getRootHash() {
        return root != null ? root.getHash() : "";
    }

    public MerkleProof generateProof(String leafHash) {
        if (!leaves.contains(leafHash)) {
            return null;
        }

        int leafIndex = leaves.indexOf(leafHash);
        List<ProofElement> proofHashes = new ArrayList<>();

        // Get proof path
        List<MerkleNode> currentLevel = new ArrayList<>();
        for (String hash : leaves) {
            currentLevel.add(new MerkleNode(hash));
        }
        int currentIndex = leafIndex;

        while (currentLevel.size() > 1) {
            List<MerkleNode> nextLevel = new ArrayList<>();

            for (int i = 0; i < currentLevel.size(); i += 2) {
                MerkleNode left = currentLevel.get(i);
                MerkleNode right;

                if (i + 1 < currentLevel.size()) {
                    right = currentLevel.get(i + 1);
                } else {
                    right = currentLevel.get(i);
                }

                // If current node is part of the proof path
                if (i == currentIndex || i + 1 == currentIndex) {
                    if (i == currentIndex) {
                        // Current is left, need right sibling
                        if (i + 1 < currentLevel.size() && right != left) {
                            proofHashes.add(new ProofElement(right.getHash(), "right"));
                        }
                        currentIndex = i / 2;
                    } else {
                        // Current is right, need left sibling
                        proofHashes.add(new ProofElement(left.getHash(), "left"));
                        currentIndex = i / 2;
                    }
                }

                String combined = left.getHash() + right.getHash();
                String parentHash = sha256(combined);
                nextLevel.add(new MerkleNode(parentHash, left, right));
            }

            currentLevel = nextLevel;
        }

        return new MerkleProof(leafHash, getRootHash(), proofHashes);
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
}
