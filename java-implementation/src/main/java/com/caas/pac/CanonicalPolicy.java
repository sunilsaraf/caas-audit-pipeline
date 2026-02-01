package com.caas.pac;

import java.time.Instant;

/**
 * Represents a canonicalized policy.
 */
public class CanonicalPolicy {
    private String policyId;
    private String version;
    private String canonicalForm;
    private String commitmentHash;
    private Instant createdAt;
    private Policy originalPolicy;

    public CanonicalPolicy(String policyId, String version, String canonicalForm,
                          String commitmentHash, Instant createdAt, Policy originalPolicy) {
        this.policyId = policyId;
        this.version = version;
        this.canonicalForm = canonicalForm;
        this.commitmentHash = commitmentHash;
        this.createdAt = createdAt;
        this.originalPolicy = originalPolicy;
    }

    // Getters
    public String getPolicyId() {
        return policyId;
    }

    public String getVersion() {
        return version;
    }

    public String getCanonicalForm() {
        return canonicalForm;
    }

    public String getCommitmentHash() {
        return commitmentHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Policy getOriginalPolicy() {
        return originalPolicy;
    }
}
