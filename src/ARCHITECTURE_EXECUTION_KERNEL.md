# Capability-Secured Inference Execution Kernel

## Architecture Overview

This system has evolved from a multi-backend chat framework into a **capability-secured execution kernel for distributed inference**.

## Core Separation of Concerns

### 1. WHO Can Execute (Authorization)
**TokenAuthority** (`token_authority.h/cpp`)
- The ONLY entity that can mint capability tokens
- Cryptographic proof required for token generation
- Revocation and audit trail support
- Delegation via CapabilityGrant

```cpp
TokenAuthority::instance().mintRemoteCloudCapability(proof);
```

### 2. WHAT Will Execute (Intent)
**ExecutionPlan** (`execution_plan.h/cpp`)
- Immutable description of execution steps
- No authority - just routing logic
- Can be inspected, validated, serialized

```cpp
ExecutionPlan plan = PlanCompiler::compile(request, mode);
```

### 3. HOW to Decide (Policy)
**ExecutionPolicyRouter** (`execution_policy.h/cpp`)
- Policy evaluation without authority
- Recommends execution path
- Observable decision logging

```cpp
ExecutionPath path = policyRouter.decideExecutionPath(...);
```

### 4. WHERE to Route (Gateway)
**InferenceGateway** (`inference_gateway.h/cpp`)
- Single ingress point
- Coordinates authority + plan + policy
- No direct backend access

```cpp
InferenceResponse response = InferenceGateway::instance().execute(request);
```

## Enforcement Topology

```
User Code
    ↓
RAWRXD_INFERENCE() [macro - convenience]
    ↓
InferenceGateway::execute() [single ingress]
    ↓
┌─────────────────────────────────────────┐
│  1. Validate Request                    │
│  2. Compile ExecutionPlan                 │
│  3. Query ExecutionPolicyRouter           │
│  4. Request Capability from TokenAuthority│
│  5. Execute via PlanExecutor              │
└─────────────────────────────────────────┘
    ↓
PlanExecutor::execute(plan, capability)
    ↓
CapabilityControlledBackend [verifies token]
    ↓
Backend Execution
```

## Key Architectural Properties

### Compile-Time Enforcement
- Backends require `ExecutionCapability` to construct
- Tokens are non-copyable, non-forgeable
- Direct backend instantiation is a compile-time error

### Separation of Authority
- **TokenAuthority**: Only mints tokens
- **ExecutionPlan**: Only describes intent
- **PolicyRouter**: Only evaluates rules
- **InferenceGateway**: Only coordinates

### No Monolithic God Object
Each component has a single responsibility:
- No component has both authority and execution
- No component has both policy and routing
- No component has both planning and capability

## Usage Examples

### Basic Inference (User Code)
```cpp
auto response = RAWRXD_INFERENCE(model, prompt);
```

### Custom Policy (Advanced)
```cpp
InferenceRequest req;
req.model = "gpt-4";
req.prompt = "Hello";
req.runtimeMode = RuntimeMode::HybridControlled;
req.allowRemote = true;

auto response = InferenceGateway::instance().execute(req);
// Logs: [Router] -> REMOTE_CLOUD [HybridControlled: cloud permitted]
```

### Direct Plan Execution (Internal)
```cpp
auto plan = PlanCompiler::compileWithCloudFallback(model, prompt);
auto cap = TokenAuthority::instance().mintRemoteCloudCapability(proof);
auto result = PlanExecutor().execute(plan, cap);
```

## Security Properties

1. **Unforgeable Tokens**: 64-bit random nonces + signing
2. **Non-Transferable**: Tokens bound to request context
3. **Revocable**: TokenAuthority can revoke any token
4. **Auditable**: Every mint and execution is logged
5. **Composability**: Grants can delegate with restrictions

## Migration Path

Old code:
```cpp
CloudApiClient client;  // Compile error now
client.generate(prompt, config);
```

New code:
```cpp
auto response = RAWRXD_INFERENCE("gpt-4", prompt);
// Or with explicit control:
auto response = InferenceGateway::instance().execute(request);
```

## Future Extensions

- **Multi-Step Plans**: Chain multiple backends
- **A/B Testing**: Compare backend outputs
- **Circuit Breakers**: Automatic fallback on failure
- **Cost Tracking**: Per-request cost attribution
- **Distributed Execution**: Cross-node capability delegation

## Enforcement Strength Classification

| Layer | Strength | Mechanism |
|-------|----------|-----------|
| Macros | Weak | Convention |
| Runtime Policy | Medium | Checks |
| Gateway Routing | Strong | Single ingress |
| Capability Tokens | **Hard** | Compile-time + crypto |
| Execution Plan | **Hard** | Type separation |
| Token Authority | **Hard** | Singleton + proof |

**Result**: Capability-secured execution kernel with structural guarantees.
