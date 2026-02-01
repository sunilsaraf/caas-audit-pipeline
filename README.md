# CaaS Audit Pipeline

Compliance-as-a-Service for Object Storage Using Cryptographically Verifiable Audit Pipelines.

## Overview

This repository implements a comprehensive Compliance-as-a-Service (CaaS) architecture for object storage systems. The implementation provides cryptographically verifiable audit trails with support for:

- **Immutable audit records** with hash chaining
- **Policy binding** with cryptographic commitments
- **Merkle tree-based inclusion proofs** for efficient verification
- **Multi-level audit fidelity** (metadata-only, chained, policy-bound, Merkle proofs)
- **Zero-trust verification** with offline validation support

## Architecture Components

The CaaS architecture consists of five core components:

### 1. Compliance Event Interceptor (CEI)
Intercepts compliance-relevant events before state mutation in the object storage control plane. Ensures completeness by capturing all mutation events.

**Key Features:**
- Event interception and queuing
- Completeness verification
- Event filtering by tenant, bucket, and type
- Handler registration for event processing

### 2. Policy-to-Audit Compiler (PAC)
Canonicalizes and versions policies, eliminating semantic ambiguities and calculating cryptographic commitments bound to audit records.

**Key Features:**
- Policy normalization and canonicalization
- Deterministic policy serialization
- Cryptographic commitment (SHA-256) calculation
- Policy versioning and retrieval

### 3. Adaptive Audit Pipeline (AAP)
Multi-level audit pipeline supporting configurable fidelity levels based on policy criticality, tenant, or bucket.

**Audit Fidelity Levels:**
- `METADATA_ONLY`: Basic metadata without chaining
- `CHAINED`: Hash-chained records
- `POLICY_BOUND`: Includes policy commitments
- `MERKLE_PROOF`: Full Merkle tree support

### 4. Cryptographic Audit Ledger (CAL)
Immutable, append-only audit ledger using hash chaining and Merkle aggregation for tamper-evident records.

**Key Features:**
- Sequential hash chaining for integrity
- Merkle tree construction for efficient proofs
- Tamper detection and verification
- Inclusion proof generation

### 5. Zero-Trust Verification API (ZCVI)
Produces Compliance Proof Bundles (CPBs) containing all necessary information for offline validation by third-party auditors.

**Key Features:**
- Single record and batch proof bundles
- Time range and tenant-scoped bundles
- Merkle inclusion proofs
- External anchoring support (blockchain, timestamp services)

## Implementations

This repository provides two complete implementations:

### Python Implementation

Located in the `src/caas/` directory with the following structure:
```
src/caas/
├── cei/          # Compliance Event Interceptor
├── pac/          # Policy-to-Audit Compiler
├── aap/          # Adaptive Audit Pipeline
├── cal/          # Cryptographic Audit Ledger
└── zcvi/         # Zero-Trust Verification API
```

**Installation:**
```bash
pip install -r requirements.txt
pip install -e .
```

**Running Tests:**
```bash
pytest tests/
```

### Java Implementation

Located in the `java-implementation/` directory with Maven project structure:
```
java-implementation/
└── src/
    ├── main/java/com/caas/
    │   ├── cei/     # Compliance Event Interceptor
    │   ├── pac/     # Policy-to-Audit Compiler
    │   ├── aap/     # Adaptive Audit Pipeline (partial)
    │   ├── cal/     # Cryptographic Audit Ledger
    │   └── zcvi/    # Zero-Trust Verification API (partial)
    └── test/java/com/caas/
```

**Building:**
```bash
cd java-implementation
mvn clean install
```

**Running Tests:**
```bash
mvn test
```

## Usage Examples

### Python Example

```python
from datetime import datetime
from caas.cei import ComplianceEvent, EventType, EventInterceptor
from caas.pac import Policy, PolicyStatement, PolicyEffect, PolicyAction, PolicyCompiler
from caas.cal import AuditLedger
from caas.aap import AdaptiveAuditPipeline, PolicyCriticality

# Initialize components
ledger = AuditLedger()
compiler = PolicyCompiler()
pipeline = AdaptiveAuditPipeline(ledger)

# Create and compile a policy
stmt = PolicyStatement(
    sid="stmt-1",
    effect=PolicyEffect.ALLOW,
    actions=[PolicyAction.READ, PolicyAction.WRITE],
    resources=["bucket/*"]
)
policy = Policy(
    policy_id="policy-1",
    version="1.0",
    name="Access Policy",
    statements=[stmt]
)
canonical_policy = compiler.compile(policy)

# Intercept and process an event
interceptor = EventInterceptor()
event = ComplianceEvent(
    event_id="evt-123",
    event_type=EventType.OBJECT_CREATE,
    timestamp=datetime.utcnow(),
    tenant_id="tenant-1",
    bucket="my-bucket"
)
interceptor.intercept(event)

# Process through adaptive pipeline
processed = pipeline.process_event(
    event,
    policy=canonical_policy,
    criticality=PolicyCriticality.HIGH
)

# Verify ledger integrity
assert ledger.verify_chain_integrity()

# Generate compliance proof bundle
from caas.zcvi import VerificationAPI
api = VerificationAPI(ledger, compiler)
bundle = api.create_single_record_bundle(
    record_id=processed.audit_record.record_id,
    include_merkle_proof=True
)

# Verify bundle
verification_result = api.verify_bundle(bundle)
print(f"Bundle valid: {verification_result['valid']}")
```

### Java Example

```java
import com.caas.cei.*;
import com.caas.pac.*;
import com.caas.cal.*;
import java.time.Instant;
import java.util.*;

// Initialize components
AuditLedger ledger = new AuditLedger();
PolicyCompiler compiler = new PolicyCompiler();

// Create and compile a policy
PolicyStatement stmt = new PolicyStatement(
    "stmt-1",
    PolicyEffect.ALLOW,
    Arrays.asList(PolicyAction.READ, PolicyAction.WRITE),
    Arrays.asList("bucket/*")
);
Policy policy = new Policy(
    "policy-1",
    "1.0",
    "Access Policy",
    Arrays.asList(stmt)
);
CanonicalPolicy canonicalPolicy = compiler.compile(policy);

// Intercept an event
EventInterceptor interceptor = new EventInterceptor();
ComplianceEvent event = new ComplianceEvent(
    "evt-123",
    EventType.OBJECT_CREATE,
    Instant.now(),
    "tenant-1",
    "my-bucket"
);
interceptor.intercept(event);

// Create and append audit record
AuditRecord record = new AuditRecord(
    UUID.randomUUID().toString(),
    event.getEventId(),
    event.getTimestamp(),
    event.getEventType().getValue(),
    event.getTenantId(),
    event.getBucket()
);
record.setPolicyCommitment(canonicalPolicy.getCommitmentHash());
ledger.append(record);

// Verify ledger integrity
boolean isValid = ledger.verifyChainIntegrity();
System.out.println("Ledger valid: " + isValid);
```

## Security Guarantees

The CaaS architecture provides the following security guarantees:

1. **Immutability**: Records cannot be modified without detection via hash chain verification
2. **Completeness**: All events are captured and counted for verification
3. **Policy Binding**: Audit records are cryptographically bound to policy commitments
4. **Tamper Evidence**: Any modification to records breaks the hash chain
5. **Efficient Verification**: Merkle proofs allow log(n) verification complexity
6. **Zero-Trust**: Proof bundles can be validated offline without trusting the audit system

## Testing

Both implementations include comprehensive unit tests:

**Python:**
- `tests/cei/` - Event interceptor tests
- `tests/pac/` - Policy compiler tests
- `tests/cal/` - Audit ledger tests

**Java:**
- JUnit 5 tests for all components
- Run with `mvn test`

## Contributing

Contributions are welcome! Please ensure all tests pass before submitting pull requests.

## License

This project is provided as-is for research and implementation purposes.
