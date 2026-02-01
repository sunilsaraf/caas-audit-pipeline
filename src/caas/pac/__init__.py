"""
Policy-to-Audit Compiler (PAC)

Canonicalizes and versions policies, eliminating semantic ambiguities and 
calculating cryptographic commitments bound to audit records.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import json
import hashlib
from enum import Enum


class PolicyEffect(Enum):
    """Policy effect types."""
    ALLOW = "Allow"
    DENY = "Deny"


class PolicyAction(Enum):
    """Policy action types."""
    READ = "s3:GetObject"
    WRITE = "s3:PutObject"
    DELETE = "s3:DeleteObject"
    LIST = "s3:ListBucket"
    ALL = "s3:*"


@dataclass
class PolicyStatement:
    """Represents a single policy statement."""
    sid: str
    effect: PolicyEffect
    actions: List[PolicyAction]
    resources: List[str]
    principals: Optional[List[str]] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "Sid": self.sid,
            "Effect": self.effect.value,
            "Actions": [action.value for action in self.actions],
            "Resources": self.resources,
            "Principals": self.principals,
            "Conditions": self.conditions,
        }


@dataclass
class Policy:
    """Represents a compliance policy."""
    policy_id: str
    version: str
    name: str
    statements: List[PolicyStatement]
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "PolicyId": self.policy_id,
            "Version": self.version,
            "Name": self.name,
            "Statements": [stmt.to_dict() for stmt in self.statements],
            "Metadata": self.metadata,
        }


@dataclass
class CanonicalPolicy:
    """Represents a canonicalized policy."""
    policy_id: str
    version: str
    canonical_form: str
    commitment_hash: str
    created_at: datetime
    original_policy: Policy
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "canonical_form": self.canonical_form,
            "commitment_hash": self.commitment_hash,
            "created_at": self.created_at.isoformat(),
        }


class PolicyCompiler:
    """
    Compiles policies into canonical form with cryptographic commitments.
    
    The compiler:
    1. Normalizes policy structure
    2. Eliminates semantic ambiguities
    3. Assigns version numbers
    4. Calculates cryptographic commitments (hashes)
    """
    
    def __init__(self):
        self.compiled_policies: Dict[str, CanonicalPolicy] = {}
        self.policy_versions: Dict[str, List[str]] = {}  # policy_id -> list of versions
    
    def compile(self, policy: Policy) -> CanonicalPolicy:
        """
        Compile a policy into canonical form.
        
        Args:
            policy: Policy to compile
            
        Returns:
            CanonicalPolicy with cryptographic commitment
        """
        # Normalize policy structure
        normalized = self._normalize_policy(policy)
        
        # Generate canonical form (deterministic JSON)
        canonical_form = json.dumps(normalized, sort_keys=True, indent=None)
        
        # Calculate cryptographic commitment
        commitment_hash = self._calculate_commitment(canonical_form)
        
        # Create canonical policy
        canonical_policy = CanonicalPolicy(
            policy_id=policy.policy_id,
            version=policy.version,
            canonical_form=canonical_form,
            commitment_hash=commitment_hash,
            created_at=datetime.utcnow(),
            original_policy=policy,
        )
        
        # Store compiled policy
        self.compiled_policies[policy.policy_id] = canonical_policy
        
        # Track versions
        if policy.policy_id not in self.policy_versions:
            self.policy_versions[policy.policy_id] = []
        self.policy_versions[policy.policy_id].append(policy.version)
        
        return canonical_policy
    
    def _normalize_policy(self, policy: Policy) -> Dict[str, Any]:
        """
        Normalize policy structure to eliminate ambiguities.
        
        Args:
            policy: Policy to normalize
            
        Returns:
            Normalized policy dictionary
        """
        normalized = {
            "PolicyId": policy.policy_id,
            "Version": policy.version,
            "Name": policy.name,
            "Statements": [],
        }
        
        # Normalize each statement
        for stmt in policy.statements:
            normalized_stmt = {
                "Sid": stmt.sid,
                "Effect": stmt.effect.value,
                "Actions": sorted([action.value for action in stmt.actions]),
                "Resources": sorted(stmt.resources),
            }
            
            # Add optional fields if present
            if stmt.principals:
                normalized_stmt["Principals"] = sorted(stmt.principals)
            
            if stmt.conditions:
                # Normalize conditions (sort keys)
                normalized_stmt["Conditions"] = {
                    k: stmt.conditions[k] for k in sorted(stmt.conditions.keys())
                }
            
            normalized["Statements"].append(normalized_stmt)
        
        # Sort statements by Sid for deterministic ordering
        normalized["Statements"] = sorted(
            normalized["Statements"], 
            key=lambda x: x["Sid"]
        )
        
        return normalized
    
    def _calculate_commitment(self, canonical_form: str) -> str:
        """
        Calculate cryptographic commitment (hash) for the canonical form.
        
        Args:
            canonical_form: Canonical JSON string
            
        Returns:
            SHA-256 hash as hex string
        """
        return hashlib.sha256(canonical_form.encode()).hexdigest()
    
    def get_policy(self, policy_id: str) -> Optional[CanonicalPolicy]:
        """
        Retrieve a compiled policy by ID.
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            CanonicalPolicy if found, None otherwise
        """
        return self.compiled_policies.get(policy_id)
    
    def get_policy_versions(self, policy_id: str) -> List[str]:
        """
        Get all versions of a policy.
        
        Args:
            policy_id: Policy identifier
            
        Returns:
            List of version strings
        """
        return self.policy_versions.get(policy_id, [])
    
    def verify_policy_commitment(
        self, 
        policy_id: str, 
        claimed_hash: str
    ) -> bool:
        """
        Verify that a policy's commitment hash matches the claimed hash.
        
        Args:
            policy_id: Policy identifier
            claimed_hash: Claimed commitment hash
            
        Returns:
            True if hashes match, False otherwise
        """
        policy = self.get_policy(policy_id)
        if not policy:
            return False
        
        return policy.commitment_hash == claimed_hash
