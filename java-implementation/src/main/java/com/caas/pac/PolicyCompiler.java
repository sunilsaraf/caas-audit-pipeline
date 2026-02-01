package com.caas.pac;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.*;

/**
 * Compiles policies into canonical form with cryptographic commitments.
 */
public class PolicyCompiler {
    private final Map<String, CanonicalPolicy> compiledPolicies;
    private final Map<String, List<String>> policyVersions;
    private static final Gson gson = new Gson();

    public PolicyCompiler() {
        this.compiledPolicies = new HashMap<>();
        this.policyVersions = new HashMap<>();
    }

    /**
     * Compile a policy into canonical form.
     *
     * @param policy Policy to compile
     * @return CanonicalPolicy with cryptographic commitment
     */
    public CanonicalPolicy compile(Policy policy) {
        // Normalize policy structure
        Map<String, Object> normalized = normalizePolicy(policy);

        // Generate canonical form (deterministic JSON)
        String canonicalForm = gson.toJson(normalized);

        // Calculate cryptographic commitment
        String commitmentHash = calculateCommitment(canonicalForm);

        // Create canonical policy
        CanonicalPolicy canonicalPolicy = new CanonicalPolicy(
            policy.getPolicyId(),
            policy.getVersion(),
            canonicalForm,
            commitmentHash,
            Instant.now(),
            policy
        );

        // Store compiled policy
        compiledPolicies.put(policy.getPolicyId(), canonicalPolicy);

        // Track versions
        policyVersions.computeIfAbsent(policy.getPolicyId(), k -> new ArrayList<>())
                     .add(policy.getVersion());

        return canonicalPolicy;
    }

    private Map<String, Object> normalizePolicy(Policy policy) {
        Map<String, Object> normalized = new LinkedHashMap<>();
        normalized.put("PolicyId", policy.getPolicyId());
        normalized.put("Version", policy.getVersion());
        normalized.put("Name", policy.getName());

        List<Map<String, Object>> normalizedStmts = new ArrayList<>();
        
        for (PolicyStatement stmt : policy.getStatements()) {
            Map<String, Object> normalizedStmt = new LinkedHashMap<>();
            normalizedStmt.put("Sid", stmt.getSid());
            normalizedStmt.put("Effect", stmt.getEffect().getValue());

            // Sort actions
            List<String> actions = new ArrayList<>();
            for (PolicyAction action : stmt.getActions()) {
                actions.add(action.getValue());
            }
            Collections.sort(actions);
            normalizedStmt.put("Actions", actions);

            // Sort resources
            List<String> resources = new ArrayList<>(stmt.getResources());
            Collections.sort(resources);
            normalizedStmt.put("Resources", resources);

            // Add optional fields if present
            if (!stmt.getPrincipals().isEmpty()) {
                List<String> principals = new ArrayList<>(stmt.getPrincipals());
                Collections.sort(principals);
                normalizedStmt.put("Principals", principals);
            }

            if (!stmt.getConditions().isEmpty()) {
                // Normalize conditions (sort keys)
                Map<String, Object> sortedConditions = new TreeMap<>(stmt.getConditions());
                normalizedStmt.put("Conditions", sortedConditions);
            }

            normalizedStmts.add(normalizedStmt);
        }

        // Sort statements by Sid
        normalizedStmts.sort(Comparator.comparing(m -> (String) m.get("Sid")));
        normalized.put("Statements", normalizedStmts);

        return normalized;
    }

    private String calculateCommitment(String canonicalForm) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonicalForm.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

    public CanonicalPolicy getPolicy(String policyId) {
        return compiledPolicies.get(policyId);
    }

    public List<String> getPolicyVersions(String policyId) {
        return policyVersions.getOrDefault(policyId, new ArrayList<>());
    }

    public boolean verifyPolicyCommitment(String policyId, String claimedHash) {
        CanonicalPolicy policy = getPolicy(policyId);
        if (policy == null) {
            return false;
        }
        return policy.getCommitmentHash().equals(claimedHash);
    }
}
