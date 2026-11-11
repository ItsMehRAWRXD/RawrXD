# RawrXD L4.3.1 Adaptive Policy Engine Summary

## Overview

L4.3.1 implements the **Adaptive Policy Engine** - a constrained optimization layer that consumes TensorProfile maps and emits compression decisions. This is a **pure policy layer** that never touches the validated L4.2 execution path.

## Architecture

```
                 ┌─────────────────────┐
                 │   Tensor Profiler    │
                 │     (L4.3.0)        │
                 └──────────┬──────────┘
                            │
                            ▼
                  TensorProfile[]
                            │
                            ▼
                 ┌─────────────────────┐
                 │  Adaptive Policy     │
                 │     (L4.3.1)        │
                 └──────────┬──────────┘
                            │
                            ▼
                  CompressionPolicy[]
                            │
                            ▼
                 ┌─────────────────────┐
                 │   Tensor Runtime    │
                 │     (L4.2 Frozen)     │
                 └──────────┬──────────┘
                            │
                            ▼
                 Fused GEMM / Attention
```

## Key Design Principle

> **Optimization policy can evolve without invalidating numerical execution.**

The policy engine is completely decoupled from execution:
- Consumes `TensorProfile` (read-only)
- Produces `CompressionPolicy` (immutable decisions)
- L4.2 runtime consumes policies without modification

## Components

### 1. CompressionPolicy

Immutable decision for a single tensor:
```cpp
struct CompressionPolicy {
    std::string tensor_name;
    CompressionType codec;              // Selected codec
    float expected_compression_ratio;
    float expected_quantization_error;
    float expected_quality_cost;
    size_t memory_saved_bytes;
    float decode_latency_ms;
    
    struct Rationale {
        float sensitivity_score;
        std::string primary_reason;     // "sensitivity", "forced", "budget"
    };
};
```

### 2. OptimizationConstraints

Defines the optimization problem:
```cpp
struct OptimizationConstraints {
    float target_compression_ratio;     // e.g., 5.0 = 5:1
    float min_cosine_similarity;      // L4.2.3 gate: ≥0.999
    float max_rmse;                   // L4.2.3 gate: ≤0.01
    float max_quality_degradation;    // Acceptable loss
    
    // Overrides
    std::map<std::string, CompressionType> forced_codecs;
    std::vector<std::string> protected_tensors;
};
```

### 3. PolicyResolver

Maps sensitivity to codec selection:
```cpp
class PolicyResolver {
    CompressionPolicy ResolveTensor(const TensorProfile& profile,
                                     const OptimizationConstraints& constraints);
    
    // Selection logic:
    // sensitivity ≤ 0.25 → Q4_0
    // sensitivity ≤ 0.50 → Q5_0
    // sensitivity ≤ 0.75 → Q6_K
    // sensitivity > 0.75 → Q8_0
};
```

### 4. BudgetOptimizer

Constrained optimization solver:
```cpp
class BudgetOptimizer {
    // Strategies:
    std::vector<CompressionPolicy> MaximizeCompression(...);
    std::vector<CompressionPolicy> MinimizeQualityLoss(...);
    std::vector<CompressionPolicy> BalancedOptimization(...);
    
    // Validation:
    bool CheckConstraints(const std::vector<CompressionPolicy>& policies,
                          const OptimizationConstraints& constraints);
};
```

**Optimization Problem:**
```
maximize:   memory_saved
subject to: total_error ≤ gate
            cosine ≥ gate
            size ≤ budget
```

### 5. AdaptivePolicyEngine

High-level orchestration:
```cpp
class AdaptivePolicyEngine {
    std::vector<CompressionPolicy> GeneratePolicy(
        const std::vector<TensorProfile>& profiles,
        const OptimizationConstraints& constraints,
        OptimizationObjective objective
    );
    
    // Presets:
    static OptimizationConstraints Preset_MaximumCompression();
    static OptimizationConstraints Preset_MaximumQuality();
    static OptimizationConstraints Preset_Balanced();
};
```

## Files Created

| File | Purpose |
|------|---------|
| `kernels/adaptive_policy_engine.h` | Policy engine framework |
| `kernels/adaptive_policy_engine.cpp` | Implementation |
| `tests/adaptive_policy_engine_test.cpp` | 26 test cases |

## Example Policy Output

```json
{
  "model": "ministral3",
  "policies": [
    {
      "tensor": "blk.0.attn.q.weight",
      "codec": "Q6_K",
      "ratio": 4.8,
      "error": 0.001,
      "memory_saved": 5242880,
      "rationale": {
        "sensitivity": 0.73,
        "reason": "sensitivity"
      }
    },
    {
      "tensor": "blk.0.ffn.down.weight",
      "codec": "Q4_0",
      "ratio": 6.4,
      "error": 0.004,
      "memory_saved": 7864320,
      "rationale": {
        "sensitivity": 0.18,
        "reason": "sensitivity"
      }
    }
  ]
}
```

## Test Coverage

### Unit Tests (24)
- CompressionPolicy validation
- OptimizationConstraints defaults
- PolicyResolver codec selection
- PolicyResolver forced/protected tensors
- BudgetOptimizer metrics calculation
- BudgetOptimizer constraint checking
- BudgetOptimizer maximize/minimize strategies
- AdaptivePolicyEngine initialization
- AdaptivePolicyEngine presets
- Utility functions (JSON, memory savings, L4.2.3 gates)

### Integration Tests (2)
- Full policy workflow
- Constrained optimization

## Usage Example

```cpp
#include "kernels/adaptive_policy_engine.h"

// Initialize engine
AdaptivePolicyEngine engine;
engine.Initialize("ministral3");

// Get profiles from L4.3.0
std::vector<TensorProfile> profiles = profiler.GetProfiles();

// Define constraints
OptimizationConstraints constraints;
constraints.target_compression_ratio = 5.0f;
constraints.min_cosine_similarity = 0.999f;  // L4.2.3 gate
constraints.max_rmse = 0.01f;                // L4.2.3 gate

// Generate policy
auto policies = engine.GeneratePolicy(
    profiles,
    constraints,
    OptimizationObjective::BALANCED
);

// Validate against L4.2.3 gates
if (engine.ValidatePolicies(policies, constraints)) {
    // Export for L4.2 runtime
    engine.ExportPolicyJSON("compression_policy.json");
    
    // Print summary
    engine.PrintPolicySummary();
}
```

## Presets

| Preset | Target Ratio | Min Cosine | Max RMSE | Use Case |
|--------|--------------|------------|----------|----------|
| MaximumCompression | 8.0:1 | 0.99 | 0.02 | Edge deployment |
| Balanced | 5.0:1 | 0.999 | 0.01 | General use |
| MaximumQuality | 2.0:1 | 0.9999 | 0.001 | Quality-critical |

## L4.2.3 Gate Validation

Every policy is validated against L4.2.3 gates:
```cpp
bool ValidateAgainstL4_2_3_Gates(const std::vector<CompressionPolicy>& policies) {
    for (const auto& policy : policies) {
        float estimated_cosine = 1.0f - policy.expected_quantization_error;
        
        // STANDARD gate
        if (estimated_cosine < 0.999f) return false;
        if (policy.expected_quantization_error > 0.01f) return false;
    }
    return true;
}
```

## Policy Application (L4.3.2)

```cpp
class PolicyApplicator {
    bool LoadPolicy(const std::vector<CompressionPolicy>& policy);
    bool ApplyToGGUF(const std::string& input_gguf,
                     const std::string& output_gguf);
    bool ValidateApplication(...);
};
```

## Build Commands

```bash
# Compile policy engine
g++ -std=c++17 -O2 -mavx2 -mfma \
    -I. kernels/adaptive_policy_engine.cpp \
    -c -o adaptive_policy_engine.o

# Compile tests
g++ -std=c++17 -O2 -mavx2 -mfma \
    -I. tests/adaptive_policy_engine_test.cpp \
    adaptive_policy_engine.o \
    -o adaptive_policy_engine_test.exe

# Run tests
./adaptive_policy_engine_test.exe
```

## Status

- ✅ Header created
- ✅ Implementation complete
- ✅ Tests created (26 cases)
- ⏳ Build and run pending
- ⏳ L4.3.2 Policy Application ready

## Architectural Significance

L4.3.1 completes the **compiler-style optimization pipeline**:

```
GGUF Model (uniform Q4)
    │
    ▼
L4.3.0 Tensor Profiler
    │
    ▼
Sensitivity Analysis
    │
    ▼
L4.3.1 Adaptive Policy Engine
    │
    ▼
CompressionPolicy[] (mixed codecs)
    │
    ▼
L4.2 Compression ABI
    │
    ▼
Fused Quant GEMM (validated execution)
```

The policy engine transforms uniform compression into **adaptive, per-tensor optimization** while preserving all L4.2 correctness guarantees.

## Next Steps: L4.3.2 Policy Application

- Load policy JSON
- Recompress GGUF tensors according to policy
- Validate against original model
- End-to-end quality validation
