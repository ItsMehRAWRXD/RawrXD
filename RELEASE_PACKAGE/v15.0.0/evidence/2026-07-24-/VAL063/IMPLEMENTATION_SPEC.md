# VAL-063 Implementation Specification
## Gateway Architecture v1.0
## Date: 2026-07-24

---

## Core Constraint

**VAL-063 wraps the certified v1.0 runtime without modification.**

`
RawrXD Certification v1.0 (frozen)
        │
        ├── VAL-050 → VAL-060 execution substrate
        │       └── CERTIFIED, IMMUTABLE
        │
        └── VAL-063 Gateway Layer (new)
                ├── Wraps v1.0 substrate
                ├── Generates witnesses
                └── Produces evidence
`

---

## Canonical Execution Witness

### ExecutionWitness Structure

`cpp
struct ExecutionWitness {
    // Identity
    UUID execution_id;           // v4 UUID for correlation
    
    // Input Identity
    Hash256 input_hash;          // SHA256(prompt + config)
    Hash256 model_hash;          // SHA256(GGUF file)
    Hash256 runtime_hash;        // SHA256(rawrxd.exe)
    
    // Timing
    uint64_t start_timestamp;    // Unix nanoseconds
    uint64_t end_timestamp;        // Unix nanoseconds
    
    // Stage Witnesses
    std::vector<StageWitness> stages;
    
    // Output Identity
    Hash256 final_output_hash;   // SHA256(generated text)
    
    // Validation
    bool deterministic;          // Replay produced identical output
    bool correlated;             // All stages share execution_id
};

struct StageWitness {
    std::string stage_name;      // e.g., "cli", "tokenizer", "forward"
    Hash256 stage_hash;          // Stage-specific witness hash
    uint64_t timestamp;          // When stage completed
    std::string artifact_path;   // Path to witness JSON
};
`

### Witness Correlation Chain

`
execution_id
    │
    ├── cli.json              ← VAL-063.1
    ├── tensors.json          ← VAL-063.2
    ├── tokenizer.json        ← VAL-063.3
    ├── forward.json          ← VAL-063.4
    ├── logits.json           ← VAL-063.5
    ├── sampler.json          ← VAL-063.6
    ├── emission.json         ← VAL-063.7
    ├── stream.json           ← VAL-063.8
    ├── replay.json           ← VAL-063.9
    ├── correlation.json      ← VAL-063.10
    ├── errors.json           ← VAL-063.11
    ├── streaming_contract.json ← VAL-063.12
    └── backpressure.json     ← VAL-063.12A ⭐ NEW
`

---

## Implementation Phases

### Phase 1 — Execution Binding

#### VAL-063.1: CLI Gateway
`cpp
// src/gateway/inference_gateway.hpp
class InferenceGateway {
public:
    ExecutionWitness Execute(const ExecutionRequest& request);
    
private:
    UUID GenerateExecutionId();
    void WriteCliWitness(const UUID& execution_id, const ExecutionRequest& request);
};
`

**Witness**: witnesses/cli.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "cli",
  "input_hash": "sha256:abc...",
  "model_path": "D:/ministral3_q4_0.gguf",
  "model_hash": "sha256:E73056A...",
  "runtime_hash": "sha256:99F6510...",
  "config": {
    "seed": 42,
    "temperature": 0.0,
    "top_k": 1,
    "max_tokens": 32
  },
  "timestamp": 1721827200000000000,
  "status": "initialized"
}
`

#### VAL-063.2: GGUF Loader Binding
**Witness**: witnesses/tensors.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "tensors",
  "tensor_manifest": [
    {"name": "token_embd", "shape": [32000, 4096], "dtype": "Q4_K"},
    {"name": "layers.0.attention.wq", "shape": [4096, 4096], "dtype": "Q4_K"},
    // ... all tensors
  ],
  "tensor_manifest_hash": "sha256:def...",
  "timestamp": 1721827200100000000,
  "status": "loaded"
}
`

#### VAL-063.3: Tokenizer Binding
**Witness**: witnesses/tokenizer.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "tokenizer",
  "vocab_size": 32000,
  "bos_token_id": 1,
  "eos_token_id": 2,
  "vocab_hash": "sha256:ghi...",
  "timestamp": 1721827200200000000,
  "status": "initialized"
}
`

### Phase 2 — Real Generation Path

#### VAL-063.4: Forward Execution
**Witness**: witnesses/forward.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "forward",
  "layer_count": 32,
  "hidden_dim": 4096,
  "execution_time_ms": 12.4,
  "timestamp": 1721827201000000000,
  "status": "completed"
}
`

#### VAL-063.5: Logits Generation
**Witness**: witnesses/logits.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "logits",
  "shape": [1, 1, 32000],
  "logits_checksum": "sha256:jkl...",
  "timestamp": 1721827201100000000,
  "status": "produced"
}
`

#### VAL-063.6: Sampler Binding
**Witness**: witnesses/sampler.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "sampler",
  "seed": 42,
  "temperature": 0.0,
  "top_k": 1,
  "selected_token_id": 1234,
  "timestamp": 1721827201200000000,
  "status": "sampled"
}
`

#### VAL-063.7: Token Emission
**Witness**: witnesses/emission.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "emission",
  "token_id": 1234,
  "token_text": "hello",
  "position": 0,
  "timestamp": 1721827201300000000,
  "status": "emitted"
}
`

#### VAL-063.8: Streaming
**Witness**: witnesses/stream.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "stream",
  "events": [
    {"id": 0, "text": "The", "position": 0, "latency_ms": 8.4},
    {"id": 1, "text": "quick", "position": 1, "latency_ms": 7.2},
    // ... all tokens
  ],
  "timestamp": 1721827202000000000,
  "status": "completed"
}
`

#### VAL-063.9: Replay
**Witness**: witnesses/replay.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "replay",
  "replay_execution_id": "uuid-v4-replay",
  "original_output_hash": "sha256:mno...",
  "replay_output_hash": "sha256:mno...",
  "bitwise_match": true,
  "deterministic": true,
  "timestamp": 1721827203000000000,
  "status": "verified"
}
`

### Phase 3 — Platform Guarantees

#### VAL-063.10: Witness Correlation
**Witness**: witnesses/correlation.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "correlation",
  "correlation_chain": {
    "input_hash": "sha256:abc...",
    "model_hash": "sha256:E73056A...",
    "tensor_manifest_hash": "sha256:def...",
    "token_sequence_hash": "sha256:pqr...",
    "output_hash": "sha256:mno..."
  },
  "chain_integrity": "verified",
  "all_stages_present": true,
  "execution_consistent": true,
  "timestamp": 1721827204000000000,
  "status": "verified"
}
`

#### VAL-063.11: Error Boundaries
**Witness**: witnesses/errors.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "errors",
  "error_tests": [
    {
      "test": "invalid_gguf",
      "input": "corrupted.gguf",
      "expected": "clean_error",
      "actual": "clean_error",
      "crash": false,
      "diagnostic_emitted": true,
      "status": "PASS"
    },
    {
      "test": "missing_tensor",
      "input": "incomplete.gguf",
      "expected": "diagnostic",
      "actual": "diagnostic",
      "crash": false,
      "diagnostic_emitted": true,
      "status": "PASS"
    },
    {
      "test": "oom_condition",
      "input": "huge_context",
      "expected": "controlled_recovery",
      "actual": "controlled_recovery",
      "crash": false,
      "recovery_possible": true,
      "status": "PASS"
    }
  ],
  "timestamp": 1721827205000000000,
  "status": "verified"
}
`

#### VAL-063.12: Streaming Contract
**Witness**: witnesses/streaming_contract.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "streaming_contract",
  "abi_version": "1.0",
  "event_schema": {
    "event": "token",
    "id": "uint64",
    "text": "string",
    "position": "uint64",
    "latency_ms": "float64",
    "timestamp": "ISO8601",
    "execution_id": "UUID"
  },
  "contract_validated": true,
  "timestamp": 1721827206000000000,
  "status": "validated"
}
`

#### VAL-063.12A: Backpressure Safety ⭐ NEW
**Witness**: witnesses/backpressure.json
`json
{
  "execution_id": "uuid-v4",
  "stage": "backpressure",
  "producer": "inference_gateway",
  "consumer": "test_consumer",
  "buffer": {
    "type": "bounded",
    "capacity": 1024,
    "high_watermark": 768,
    "low_watermark": 256
  },
  "guarantees": {
    "ordered": true,
    "duplicate_tokens": 0,
    "dropped_tokens": 0,
    "consumer_backpressure_supported": true,
    "producer_blocking_behavior": "yield_after_high_watermark"
  },
  "test_scenarios": [
    {
      "scenario": "slow_consumer",
      "consumer_delay_ms": 100,
      "tokens_produced": 100,
      "tokens_received": 100,
      "tokens_dropped": 0,
      "backpressure_triggered": true,
      "status": "PASS"
    },
    {
      "scenario": "fast_consumer",
      "consumer_delay_ms": 0,
      "tokens_produced": 100,
      "tokens_received": 100,
      "tokens_dropped": 0,
      "backpressure_triggered": false,
      "status": "PASS"
    }
  ],
  "timestamp": 1721827207000000000,
  "status": "verified"
}
`

---

## Gateway Source Structure

`
src/gateway/
├── inference_gateway.hpp       ← Main gateway interface
├── inference_gateway.cpp       ← Implementation
├── inference_attestor.hpp      ← Witness generation
├── inference_attestor.cpp      ← Witness implementation
├── evidence_writer.hpp         ← JSON witness writer
├── evidence_writer.cpp         ← Writer implementation
├── execution_witness.hpp       ← Canonical witness structures
├── execution_types.hpp         ← Hash256, UUID, etc.
└── CMakeLists.txt              ← Build configuration
`

---

## Build Integration

`cmake
# src/gateway/CMakeLists.txt
add_library(rawrxd_gateway STATIC
    inference_gateway.cpp
    inference_attestor.cpp
    evidence_writer.cpp
)

target_link_libraries(rawrxd_gateway
    rawrxd_core          # v1.0 certified substrate
    nlohmann_json::json
)

# CLI executable links gateway
add_executable(rawrxd_cli
    cli_main.cpp
)

target_link_libraries(rawrxd_cli
    rawrxd_gateway
)
`

---

## Evidence Output Structure

`
VAL063/
├── specification.md              ← VAL-063 spec
├── result.json                   ← Overall result
├── manifest.json                 ← Witness manifest
└── witnesses/
    ├── cli.json                  ← VAL-063.1
    ├── tensors.json              ← VAL-063.2
    ├── tokenizer.json            ← VAL-063.3
    ├── forward.json              ← VAL-063.4
    ├── logits.json               ← VAL-063.5
    ├── sampler.json              ← VAL-063.6
    ├── emission.json             ← VAL-063.7
    ├── stream.json               ← VAL-063.8
    ├── replay.json               ← VAL-063.9
    ├── correlation.json          ← VAL-063.10
    ├── errors.json               ← VAL-063.11
    ├── streaming_contract.json   ← VAL-063.12
    └── backpressure.json         ← VAL-063.12A ⭐
`

---

## Success Criteria

`json
{
  "gate": "VAL-063",
  "name": "CLI Inference Gateway Binding",
  "version": "1.1",
  "status": "PASS",
  "subtests": {
    "VAL-063.1": "PASS",   "VAL-063.2": "PASS",   "VAL-063.3": "PASS",
    "VAL-063.4": "PASS",   "VAL-063.5": "PASS",   "VAL-063.6": "PASS",
    "VAL-063.7": "PASS",   "VAL-063.8": "PASS",   "VAL-063.9": "PASS",
    "VAL-063.10": "PASS",  "VAL-063.11": "PASS",  "VAL-063.12": "PASS",
    "VAL-063.12A": "PASS"
  },
  "deterministic": true,
  "replayable": true,
  "streaming_contract": "validated",
  "error_boundaries": "controlled",
  "witness_correlation": "verified",
  "backpressure_safety": "verified"
}
`

---

*Implementation Date: 2026-07-24*  
*Target: RawrXD Certification v1.1*
