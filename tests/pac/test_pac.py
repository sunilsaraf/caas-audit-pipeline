"""
Unit tests for Policy-to-Audit Compiler (PAC)
"""

import pytest
from datetime import datetime

from caas.pac import (
    Policy, PolicyStatement, PolicyEffect, PolicyAction,
    PolicyCompiler, CanonicalPolicy
)


class TestPolicy:
    """Test Policy and PolicyStatement classes."""
    
    def test_policy_statement_creation(self):
        """Test creating a policy statement."""
        stmt = PolicyStatement(
            sid="statement-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ, PolicyAction.WRITE],
            resources=["bucket/path/*"],
            principals=["user@example.com"]
        )
        
        assert stmt.sid == "statement-1"
        assert stmt.effect == PolicyEffect.ALLOW
        assert len(stmt.actions) == 2
    
    def test_policy_statement_to_dict(self):
        """Test converting policy statement to dictionary."""
        stmt = PolicyStatement(
            sid="statement-1",
            effect=PolicyEffect.DENY,
            actions=[PolicyAction.DELETE],
            resources=["bucket/*"]
        )
        
        stmt_dict = stmt.to_dict()
        
        assert stmt_dict["Sid"] == "statement-1"
        assert stmt_dict["Effect"] == "Deny"
        assert PolicyAction.DELETE.value in stmt_dict["Actions"]
    
    def test_policy_creation(self):
        """Test creating a policy."""
        stmt = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ],
            resources=["*"]
        )
        
        policy = Policy(
            policy_id="policy-1",
            version="1.0",
            name="Test Policy",
            statements=[stmt]
        )
        
        assert policy.policy_id == "policy-1"
        assert policy.version == "1.0"
        assert len(policy.statements) == 1
    
    def test_policy_to_dict(self):
        """Test converting policy to dictionary."""
        stmt = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.ALL],
            resources=["*"]
        )
        
        policy = Policy(
            policy_id="policy-1",
            version="1.0",
            name="Test Policy",
            statements=[stmt],
            metadata={"owner": "admin"}
        )
        
        policy_dict = policy.to_dict()
        
        assert policy_dict["PolicyId"] == "policy-1"
        assert policy_dict["Version"] == "1.0"
        assert len(policy_dict["Statements"]) == 1
        assert policy_dict["Metadata"]["owner"] == "admin"


class TestPolicyCompiler:
    """Test PolicyCompiler class."""
    
    def test_compiler_creation(self):
        """Test creating a policy compiler."""
        compiler = PolicyCompiler()
        
        assert len(compiler.compiled_policies) == 0
        assert len(compiler.policy_versions) == 0
    
    def test_compile_simple_policy(self):
        """Test compiling a simple policy."""
        compiler = PolicyCompiler()
        
        stmt = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ],
            resources=["bucket/*"]
        )
        
        policy = Policy(
            policy_id="policy-1",
            version="1.0",
            name="Read Policy",
            statements=[stmt]
        )
        
        canonical = compiler.compile(policy)
        
        assert canonical.policy_id == "policy-1"
        assert canonical.version == "1.0"
        assert canonical.commitment_hash is not None
        assert len(canonical.commitment_hash) == 64  # SHA-256
    
    def test_canonical_form_deterministic(self):
        """Test that canonical form is deterministic for same policy."""
        compiler = PolicyCompiler()
        
        # Create two statements with different ordering that should normalize to same form
        stmt1 = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ, PolicyAction.WRITE],
            resources=["bucket/a", "bucket/b"]
        )
        
        stmt2 = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.WRITE, PolicyAction.READ],  # Different order
            resources=["bucket/b", "bucket/a"]  # Different order
        )
        
        # Create same policy twice with same ID
        policy1 = Policy(
            policy_id="policy-test",
            version="1.0",
            name="Test",
            statements=[stmt1]
        )
        
        canonical1 = compiler.compile(policy1)
        
        # Compile again with reordered actions/resources
        policy2 = Policy(
            policy_id="policy-test",
            version="1.0",
            name="Test",
            statements=[stmt2]
        )
        
        canonical2 = compiler.compile(policy2)
        
        # Canonical forms should be identical (normalized) when policy content is same
        assert canonical1.canonical_form == canonical2.canonical_form
        assert canonical1.commitment_hash == canonical2.commitment_hash
    
    def test_get_policy(self):
        """Test retrieving a compiled policy."""
        compiler = PolicyCompiler()
        
        stmt = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ],
            resources=["*"]
        )
        
        policy = Policy(
            policy_id="policy-1",
            version="1.0",
            name="Test Policy",
            statements=[stmt]
        )
        
        canonical = compiler.compile(policy)
        retrieved = compiler.get_policy("policy-1")
        
        assert retrieved is not None
        assert retrieved.policy_id == canonical.policy_id
        assert retrieved.commitment_hash == canonical.commitment_hash
    
    def test_policy_versions(self):
        """Test tracking policy versions."""
        compiler = PolicyCompiler()
        
        stmt = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ],
            resources=["*"]
        )
        
        # Compile version 1.0
        policy_v1 = Policy(
            policy_id="policy-1",
            version="1.0",
            name="Test Policy",
            statements=[stmt]
        )
        compiler.compile(policy_v1)
        
        # Compile version 2.0
        policy_v2 = Policy(
            policy_id="policy-1",
            version="2.0",
            name="Test Policy",
            statements=[stmt]
        )
        compiler.compile(policy_v2)
        
        versions = compiler.get_policy_versions("policy-1")
        
        assert len(versions) == 2
        assert "1.0" in versions
        assert "2.0" in versions
    
    def test_verify_policy_commitment(self):
        """Test verifying policy commitment."""
        compiler = PolicyCompiler()
        
        stmt = PolicyStatement(
            sid="stmt-1",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ],
            resources=["*"]
        )
        
        policy = Policy(
            policy_id="policy-1",
            version="1.0",
            name="Test Policy",
            statements=[stmt]
        )
        
        canonical = compiler.compile(policy)
        
        # Verify with correct hash
        assert compiler.verify_policy_commitment(
            "policy-1", 
            canonical.commitment_hash
        ) is True
        
        # Verify with wrong hash
        assert compiler.verify_policy_commitment(
            "policy-1", 
            "0" * 64
        ) is False
        
        # Verify non-existent policy
        assert compiler.verify_policy_commitment(
            "policy-999", 
            canonical.commitment_hash
        ) is False
    
    def test_multiple_statements_normalization(self):
        """Test normalizing policies with multiple statements."""
        compiler = PolicyCompiler()
        
        # Create policy with statements in different order
        stmt1 = PolicyStatement(
            sid="stmt-b",
            effect=PolicyEffect.ALLOW,
            actions=[PolicyAction.READ],
            resources=["bucket/*"]
        )
        
        stmt2 = PolicyStatement(
            sid="stmt-a",
            effect=PolicyEffect.DENY,
            actions=[PolicyAction.DELETE],
            resources=["bucket/sensitive/*"]
        )
        
        policy = Policy(
            policy_id="policy-1",
            version="1.0",
            name="Multi-statement Policy",
            statements=[stmt1, stmt2]
        )
        
        canonical = compiler.compile(policy)
        
        # Canonical form should have statements sorted by Sid
        import json
        canonical_dict = json.loads(canonical.canonical_form)
        
        assert canonical_dict["Statements"][0]["Sid"] == "stmt-a"
        assert canonical_dict["Statements"][1]["Sid"] == "stmt-b"
