package com.caas.pac;

import org.junit.jupiter.api.Test;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for Policy-to-Audit Compiler (PAC)
 */
class PolicyCompilerTest {

    @Test
    void testCompileSimplePolicy() {
        PolicyCompiler compiler = new PolicyCompiler();
        
        PolicyStatement stmt = new PolicyStatement(
            "stmt-1",
            PolicyEffect.ALLOW,
            Arrays.asList(PolicyAction.READ),
            Arrays.asList("bucket/*")
        );
        
        Policy policy = new Policy(
            "policy-1",
            "1.0",
            "Read Policy",
            Arrays.asList(stmt)
        );
        
        CanonicalPolicy canonical = compiler.compile(policy);
        
        assertEquals("policy-1", canonical.getPolicyId());
        assertEquals("1.0", canonical.getVersion());
        assertNotNull(canonical.getCommitmentHash());
        assertEquals(64, canonical.getCommitmentHash().length()); // SHA-256
    }

    @Test
    void testCanonicalFormDeterministic() {
        PolicyCompiler compiler = new PolicyCompiler();
        
        // Create two identical policies with different ordering
        PolicyStatement stmt1 = new PolicyStatement(
            "stmt-1",
            PolicyEffect.ALLOW,
            Arrays.asList(PolicyAction.READ, PolicyAction.WRITE),
            Arrays.asList("bucket/a", "bucket/b")
        );
        
        PolicyStatement stmt2 = new PolicyStatement(
            "stmt-1",
            PolicyEffect.ALLOW,
            Arrays.asList(PolicyAction.WRITE, PolicyAction.READ), // Different order
            Arrays.asList("bucket/b", "bucket/a") // Different order
        );
        
        Policy policy1 = new Policy("policy-1", "1.0", "Test", Arrays.asList(stmt1));
        Policy policy2 = new Policy("policy-2", "1.0", "Test", Arrays.asList(stmt2));
        
        CanonicalPolicy canonical1 = compiler.compile(policy1);
        CanonicalPolicy canonical2 = compiler.compile(policy2);
        
        // Canonical forms should be identical (normalized)
        assertEquals(canonical1.getCanonicalForm(), canonical2.getCanonicalForm());
        assertEquals(canonical1.getCommitmentHash(), canonical2.getCommitmentHash());
    }

    @Test
    void testGetPolicy() {
        PolicyCompiler compiler = new PolicyCompiler();
        
        PolicyStatement stmt = new PolicyStatement(
            "stmt-1",
            PolicyEffect.ALLOW,
            Arrays.asList(PolicyAction.READ),
            Arrays.asList("*")
        );
        
        Policy policy = new Policy("policy-1", "1.0", "Test Policy", Arrays.asList(stmt));
        
        CanonicalPolicy canonical = compiler.compile(policy);
        CanonicalPolicy retrieved = compiler.getPolicy("policy-1");
        
        assertNotNull(retrieved);
        assertEquals(canonical.getPolicyId(), retrieved.getPolicyId());
        assertEquals(canonical.getCommitmentHash(), retrieved.getCommitmentHash());
    }

    @Test
    void testPolicyVersions() {
        PolicyCompiler compiler = new PolicyCompiler();
        
        PolicyStatement stmt = new PolicyStatement(
            "stmt-1",
            PolicyEffect.ALLOW,
            Arrays.asList(PolicyAction.READ),
            Arrays.asList("*")
        );
        
        // Compile version 1.0
        Policy policyV1 = new Policy("policy-1", "1.0", "Test", Arrays.asList(stmt));
        compiler.compile(policyV1);
        
        // Compile version 2.0
        Policy policyV2 = new Policy("policy-1", "2.0", "Test", Arrays.asList(stmt));
        compiler.compile(policyV2);
        
        var versions = compiler.getPolicyVersions("policy-1");
        
        assertEquals(2, versions.size());
        assertTrue(versions.contains("1.0"));
        assertTrue(versions.contains("2.0"));
    }

    @Test
    void testVerifyPolicyCommitment() {
        PolicyCompiler compiler = new PolicyCompiler();
        
        PolicyStatement stmt = new PolicyStatement(
            "stmt-1",
            PolicyEffect.ALLOW,
            Arrays.asList(PolicyAction.READ),
            Arrays.asList("*")
        );
        
        Policy policy = new Policy("policy-1", "1.0", "Test", Arrays.asList(stmt));
        CanonicalPolicy canonical = compiler.compile(policy);
        
        // Verify with correct hash
        assertTrue(compiler.verifyPolicyCommitment("policy-1", canonical.getCommitmentHash()));
        
        // Verify with wrong hash
        assertFalse(compiler.verifyPolicyCommitment("policy-1", "0".repeat(64)));
        
        // Verify non-existent policy
        assertFalse(compiler.verifyPolicyCommitment("policy-999", canonical.getCommitmentHash()));
    }
}
