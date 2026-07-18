# Reference Workloads Documentation
## RawrXD Sovereign vs Ollama Benchmark Suite

**Version**: 1.0.0  
**Date**: 2026-07-07  
**Total Prompts**: 40 across 8 categories

---

## Overview

This directory contains versioned, reproducible prompt suites for the benchmark suite. Each workload is designed to test specific capabilities of agentic AI systems while maintaining consistency across runs.

---

## Directory Structure

```
workloads/
├── workloads_v1.0.0.json    # Current version
├── workloads_v1.0.0.sha256  # SHA256 checksum
├── README.md                # This file
└── CHANGELOG.md            # Version history
```

---

## Categories

### 1. Chat (5 prompts)
**Purpose**: General conversation and Q&A capabilities

| ID | Name | Difficulty | Expected Tokens |
|----|------|------------|-----------------|
| chat_001 | Explain Concept | medium | 200 |
| chat_002 | Compare Technologies | medium | 250 |
| chat_003 | Technical Deep Dive | hard | 300 |
| chat_004 | Best Practices | medium | 220 |
| chat_005 | Architecture Decision | hard | 280 |

**Use Cases**: Response quality, coherence, depth scoring

---

### 2. Coding (5 prompts)
**Purpose**: Code generation, debugging, and optimization

| ID | Name | Difficulty | Expected Tokens |
|----|------|------------|-----------------|
| code_001 | Implement Algorithm | medium | 150 |
| code_002 | Debug Code | medium | 180 |
| code_003 | Optimize Performance | medium | 160 |
| code_004 | Design Pattern | hard | 250 |
| code_005 | Refactor Legacy | medium | 200 |

**Use Cases**: Code correctness, structure, actionability

---

### 3. Agentic (5 prompts)
**Purpose**: Agent reasoning, planning, and decision-making

| ID | Name | Difficulty | Expected Tokens |
|----|------|------------|-----------------|
| agent_001 | Plan Task | hard | 300 |
| agent_002 | Decision Analysis | hard | 280 |
| agent_003 | Resource Allocation | medium | 250 |
| agent_004 | Troubleshoot System | hard | 260 |
| agent_005 | Design Review | medium | 220 |

**Use Cases**: Planning depth, decision quality, actionability

---

### 4. Swarm (5 prompts)
**Purpose**: Multi-agent coordination and consensus

| ID | Name | Difficulty | Expected Tokens |
|----|------|------------|-----------------|
| swarm_001 | Coordinate Agents | hard | 320 |
| swarm_002 | Consensus Building | hard | 280 |
| swarm_003 | Task Distribution | hard | 300 |
| swarm_004 | Conflict Resolution | medium | 260 |
| swarm_005 | Load Balancing | medium | 270 |

**Use Cases**: Swarm throughput, coordination efficiency

---

### 5. Long Context (5 prompts)
**Purpose**: Context window and coherence testing

| ID | Name | Difficulty | Context Tokens | Expected Tokens |
|----|------|------------|----------------|-----------------|
| context_001 | Summarize Document | hard | 6000 | 400 |
| context_002 | Extract Information | hard | 8000 | 350 |
| context_003 | Maintain Coherence | hard | 10000 | 200 |
| context_004 | Cross-Reference | hard | 7000 | 380 |
| context_005 | Analyze Trends | hard | 9000 | 420 |

**Use Cases**: Context fidelity, long-range dependencies

---

### 6. Autonomous (5 prompts)
**Purpose**: Self-directed execution and goal decomposition

| ID | Name | Difficulty | Expected Tokens |
|----|------|------------|-----------------|
| auto_001 | Self-Directed Task | hard | 340 |
| auto_002 | Error Recovery | hard | 280 |
| auto_003 | Exploration | hard | 360 |
| auto_004 | Iterative Refinement | hard | 320 |
| auto_005 | Goal Decomposition | medium | 300 |

**Use Cases**: Autonomous runtime, self-correction

---

### 7. Recovery (5 prompts)
**Purpose**: Error handling and resilience

| ID | Name | Difficulty | Expected Tokens |
|----|------|------------|-----------------|
| recovery_001 | Handle Failure | hard | 280 |
| recovery_002 | Self-Correction | medium | 180 |
| recovery_003 | Circuit Breaker | medium | 260 |
| recovery_004 | Retry Strategy | medium | 220 |
| recovery_005 | Graceful Degradation | medium | 240 |

**Use Cases**: Recovery success rate, resilience scoring

---

### 8. Stress (5 prompts)
**Purpose**: High-throughput stress testing

| ID | Name | Difficulty | Expected Tokens |
|----|------|------------|-----------------|
| stress_001 | Rapid Fire | easy | 100 |
| stress_002 | Quick Response | easy | 80 |
| stress_003 | Fast Answer | easy | 90 |
| stress_004 | Rapid Calculation | easy | 100 |
| stress_005 | Quick Definition | easy | 85 |

**Use Cases**: Warmup, stress overload, TPS measurement

---

## Usage

### Loading Workloads

```cpp
// Load specific version
auto suite = WorkloadLoader::LoadVersion("workloads/", "1.0.0");

// Load latest version
auto suite = WorkloadLoader::LoadLatest("workloads/");

// Initialize workload manager
WorkloadProfileManager manager;
manager.Initialize("workloads/workloads_v1.0.0.json");
```

### Using Workloads in Benchmarks

```cpp
// Get workload for a category
WorkloadConfig workload = manager.GetWorkload("coding", 512);

// Get shuffled workload with fixed seed
WorkloadConfig shuffled = manager.GetShuffledWorkload("agentic", 512, 42);

// Get warmup prompts
WorkloadConfig warmup = manager.GetWarmupPrompts();
```

---

## Versioning

### Schema
- **Major**: Breaking changes to prompt structure
- **Minor**: New prompts added, existing unchanged
- **Patch**: Text corrections, metadata updates

### Compatibility
| Workload Version | Benchmark Suite Version |
|------------------|------------------------|
| 1.0.0 | 2.0.0+ |

---

## Reproducibility

### Fixed Parameters
- **Seed**: 42 (for prompt shuffling)
- **Temperature**: 0.0 (deterministic output)
- **Runs per prompt**: 10 (recommended)
- **Order**: Shuffled with fixed seed

### Verification
```bash
# Calculate SHA256
sha256sum workloads_v1.0.0.json

# Verify against manifest
cat workloads_v1.0.0.sha256
```

---

## Prompt Design Principles

1. **Deterministic**: Same input should produce similar output structure
2. **Measurable**: Output can be automatically evaluated
3. **Representative**: Covers real-world use cases
4. **Isolated**: Each prompt tests specific capabilities
5. **Versioned**: Changes tracked and documented

---

## Quality Metrics

Each prompt includes expected quality criteria:

- **Structure Score**: Proper formatting (headings, lists, code blocks)
- **Correctness Score**: Factual accuracy
- **Depth Score**: Reasoning thoroughness
- **Coherence Score**: Logical flow
- **Actionability Score**: Concrete, actionable output

---

## Contributing

To add new prompts:

1. Follow the JSON schema in `workloads_v1.0.0.json`
2. Include all required fields (id, name, prompt, expected_tokens, difficulty)
3. Add optional context_tokens for long-context prompts
4. Update total_prompts in metadata
5. Increment version according to schema
6. Update CHANGELOG.md
7. Recalculate SHA256

---

## References

- Benchmark Suite: `../benchmark_suite_v2.cpp`
- Workload Loader: `../include/workload_loader.hpp`
- Manifest System: `../include/benchmark_manifest.hpp`

---

## License

Copyright (c) 2026 RawrXD Team. All rights reserved.
