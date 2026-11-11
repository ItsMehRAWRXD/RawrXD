# VAL-063 Implementation Gates
## Execution Roadmap
## Date: 2026-07-24

---

## Implementation Philosophy

`
v1.0 Certified Runtime
        │
        │ immutable substrate
        ▼
VAL-063 Gateway Layer (non-invasive wrapper)
        │
        ├── execution identity
        ├── witness generation
        ├── streaming contract
        ├── replay verification
        └── operational safety
`

**Constraint**: VAL-063 wraps the certified v1.0 runtime without modification.

---

## Gate A — Identity Infrastructure ⭐ FIRST

**Files**:
`
src/gateway/
├── execution_types.hpp       ← Hash256, UUID, Timestamp
├── execution_witness.hpp     ← ExecutionWitness, StageWitness
└── evidence_writer.hpp       ← JSON serialization
`

**Required Primitives**:
| Primitive | Purpose | Implementation |
|-----------|---------|----------------|
| UUID v4 | execution_id | std::uuid or platform |
| SHA-256 | All hashes | OpenSSL or platform |
| Timestamp | Timing | std::chrono::nanoseconds |
| JSON | Witness format | nlohmann/json |
| Manifest | Witness index | Custom struct |

**ExecutionWitness v1.1** (with configuration_hash):
`cpp
struct ExecutionWitness {
    // Identity
    UUID execution_id;              // v4 UUID for correlation
    
    // Input Identity (decomposed)
    Hash256 prompt_hash;            // SHA256(prompt text)
    Hash256 configuration_hash;     // SHA256(config: seed, temp, top_k, etc.)
    Hash256 input_hash;             // SHA256(prompt + config combined)
    
    // Runtime Identity
    Hash256 model_hash;             // SHA256(GGUF file)
    Hash256 runtime_hash;           // SHA256(rawrxd.exe)
    
    // Timing
    uint64_t start_timestamp;       // Unix nanoseconds
    uint64_t end_timestamp;         // Unix nanoseconds
    
    // Stage Witnesses
    std::vector<StageWitness> stages;
    
    // Output Identity
    Hash256 final_output_hash;      // SHA256(generated text)
    
    // Validation
    bool deterministic;             // Replay produced identical output
    bool correlated;                // All stages share execution_id
};

struct StageWitness {
    std::string stage_name;         // e.g., "cli", "tokenizer", "forward"
    Hash256 stage_hash;             // Stage-specific witness hash
    uint64_t timestamp;             // When stage completed
    std::string artifact_path;      // Path to witness JSON
};
`

**Identity Chain**:
`
prompt_hash
      +
configuration_hash
      +
model_hash
      +
runtime_hash
      =
execution identity
`

This distinguishes:
- Same prompt, different sampler → different execution
- Same model, different context length → different execution
- Same runtime, different quantization → different execution

---

## Gate B — Gateway Binding

**Files**:
`
src/gateway/
├── inference_gateway.hpp       ← Main interface
└── inference_gateway.cpp       ← Implementation
`

**Interface**:
`cpp
class InferenceGateway {
public:
    struct ExecutionRequest {
        std::string prompt;
        Configuration config;        // seed, temperature, top_k, etc.
        std::string model_path;
        std::string runtime_path;
    };
    
    struct ExecutionResult {
        ExecutionWitness witness;
        std::string generated_text;
        bool success;
        std::string error_message;
    };
    
    // Main entry point
    ExecutionResult Execute(const ExecutionRequest& request);
    
    // Replay for VAL-063.9
    ExecutionResult Replay(const ExecutionWitness& original);
    
private:
    UUID GenerateExecutionId();
    void WriteStageWitness(const std::string& stage_name, 
                          const Hash256& stage_hash,
                          const std::string& artifact_path);
    ExecutionWitness FinalizeWitness();
};
`

**Responsibilities**:
`
Execute(request)
    │
    ├── create execution_id
    ├── hash prompt → prompt_hash
    ├── hash config → configuration_hash
    ├── combine → input_hash
    ├── hash model file → model_hash
    ├── hash runtime file → runtime_hash
    │
    ├── call v1.0 runtime (certified substrate)
    │       └── actual inference execution
    │
    ├── collect stage witnesses
    │       ├── cli.json
    │       ├── tensors.json
    │       ├── tokenizer.json
    │       ├── forward.json
    │       ├── logits.json
    │       ├── sampler.json
    │       ├── emission.json
    │       └── stream.json
    │
    ├── hash output → final_output_hash
    │
    └── emit evidence package
            ├── manifest.json
            ├── witnesses/*.json
            └── result.json
`

**No inference logic belongs here** — only witness generation.

---

## Gate C — Streaming Adapter

**Files**:
`
src/gateway/
├── token_event_queue.hpp       ← Bounded queue
└── token_event_queue.cpp       ← Implementation
`

**Bounded Queue Abstraction**:
`cpp
class TokenEventQueue {
public:
    struct Config {
        size_t capacity = 1024;           // Max events
        size_t high_watermark = 768;      // Block producer
        size_t low_watermark = 256;       // Resume producer
    };
    
    TokenEventQueue(const Config& config);
    
    // Producer (Inference Thread)
    bool Push(const TokenEvent& event);  // Returns false if blocked
    void Close();                         // Signal end of stream
    
    // Consumer (Client Thread)
    std::optional<TokenEvent> Pop();      // Returns nullopt if empty
    bool IsClosed() const;
    
    // VAL-063.12A Evidence
    struct BackpressureMetrics {
        size_t events_produced;
        size_t events_consumed;
        size_t events_dropped;
        size_t producer_blocks;
        bool ordered_delivery;
    };
    BackpressureMetrics GetMetrics() const;
    
private:
    std::queue<TokenEvent> buffer_;
    std::mutex mutex_;
    std::condition_variable producer_cv_;
    std::condition_variable consumer_cv_;
    Config config_;
    bool closed_ = false;
    BackpressureMetrics metrics_;
};
`

**Backpressure Behavior**:
`
Producer (Inference)
       │
       ▼ push(event)
       │
       ├── buffer.size() < high_watermark?
       │       │
       │       YES → accept, notify consumer
       │       │
       │       NO → block on producer_cv_
       │              (yield producer thread)
       │
Consumer (Client)
       │
       ▼ pop()
       │
       ├── buffer not empty?
       │       │
       │       YES → return event
       │       │
       │       NO → wait on consumer_cv_
       │
       └── buffer.size() <= low_watermark?
               │
               YES → notify producer (resume)
`

**VAL-063.12A Evidence Generation**:
`json
{
  "execution_id": "uuid-v4",
  "stage": "backpressure",
  "queue_config": {
    "capacity": 1024,
    "high_watermark": 768,
    "low_watermark": 256
  },
  "metrics": {
    "events_produced": 100,
    "events_consumed": 100,
    "events_dropped": 0,
    "producer_blocks": 12,
    "ordered_delivery": true
  },
  "test_scenarios": [
    {
      "scenario": "slow_consumer",
      "consumer_delay_ms": 100,
      "events_produced": 100,
      "events_consumed": 100,
      "events_dropped": 0,
      "producer_blocks": 12,
      "status": "PASS"
    }
  ],
  "guarantees": {
    "ordered": true,
    "duplicate_tokens": 0,
    "dropped_tokens": 0,
    "consumer_backpressure_supported": true
  }
}
`

---

## Gate D — Replay Harness

**Files**:
`
src/gateway/
├── replay_harness.hpp          ← Replay orchestration
└── replay_harness.cpp          ← Implementation
`

**Replay Verification**:
`cpp
class ReplayHarness {
public:
    struct ReplayResult {
        bool success;
        bool deterministic;           // output_hash matches
        std::string original_output;
        std::string replay_output;
        ExecutionWitness replay_witness;
    };
    
    // VAL-063.9: Replay original execution
    ReplayResult Replay(const ExecutionWitness& original);
    
    // Compare outputs
    bool VerifyDeterminism(const Hash256& original_hash,
                           const Hash256& replay_hash);
};
`

**Replay Process**:
`
Original Execution:
  prompt_hash: sha256("The quick brown fox")
  configuration_hash: sha256({seed:42, temp:0.0, top_k:1})
  model_hash: sha256(ministral3_q4_0.gguf)
  runtime_hash: sha256(rawrxd.exe)
  output_hash: sha256(" jumps over...")

Replay Execution:
  Same prompt_hash
  Same configuration_hash
  Same model_hash
  Same runtime_hash
  → output_hash should match

Result:
  deterministic = (original_output_hash == replay_output_hash)
`

**Witness**:
`json
{
  "execution_id": "uuid-v4-replay",
  "original_execution_id": "uuid-v4",
  "stage": "replay",
  "original_output_hash": "sha256:abc...",
  "replay_output_hash": "sha256:abc...",
  "bitwise_match": true,
  "deterministic": true,
  "timestamp": 1721827203000000000,
  "status": "verified"
}
`

---

## Implementation Order

`
Gate A ───────────────────────────────────────────────►
  │ Identity Infrastructure
  │   ├── execution_types.hpp
  │   ├── execution_witness.hpp
  │   └── evidence_writer.hpp
  │
  ▼
Gate B ───────────────────────────────────────────────►
  │ Gateway Binding
  │   ├── inference_gateway.hpp
  │   └── inference_gateway.cpp
  │
  ▼
Gate C ───────────────────────────────────────────────►
  │ Streaming Adapter
  │   ├── token_event_queue.hpp
  │   └── token_event_queue.cpp
  │
  ▼
Gate D ───────────────────────────────────────────────►
  │ Replay Harness
  │   ├── replay_harness.hpp
  │   └── replay_harness.cpp
  │
  ▼
VAL-063 Complete
`

---

## Build Integration

`cmake
# src/gateway/CMakeLists.txt

# Gate A: Identity Infrastructure
add_library(gateway_types STATIC
    execution_types.cpp
    execution_witness.cpp
    evidence_writer.cpp
)

target_link_libraries(gateway_types
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto  # For SHA-256
)

# Gate B: Gateway Binding
add_library(gateway_core STATIC
    inference_gateway.cpp
)

target_link_libraries(gateway_core
    gateway_types
    rawrxd_core          # v1.0 certified substrate
)

# Gate C: Streaming Adapter
add_library(gateway_streaming STATIC
    token_event_queue.cpp
)

target_link_libraries(gateway_streaming
    gateway_types
)

# Gate D: Replay Harness
add_library(gateway_replay STATIC
    replay_harness.cpp
)

target_link_libraries(gateway_replay
    gateway_core
)

# CLI executable
add_executable(rawrxd_cli
    cli_main.cpp
)

target_link_libraries(rawrxd_cli
    gateway_core
    gateway_streaming
    gateway_replay
)
`

---

## Success Criteria by Gate

### Gate A Success
- [ ] UUID generation works
- [ ] SHA-256 hashing works
- [ ] JSON serialization works
- [ ] ExecutionWitness can be constructed
- [ ] Witness can be written to disk

### Gate B Success
- [ ] InferenceGateway::Execute() runs
- [ ] All 13 stage witnesses generated
- [ ] Manifest.json created
- [ ] No modification to v1.0 runtime

### Gate C Success
- [ ] TokenEventQueue bounded buffer works
- [ ] Producer blocks at high watermark
- [ ] Consumer resumes at low watermark
- [ ] Zero tokens dropped
- [ ] Ordered delivery maintained
- [ ] VAL-063.12A evidence generated

### Gate D Success
- [ ] ReplayHarness::Replay() runs
- [ ] Original and replay outputs match
- [ ] Determinism verified
- [ ] VAL-063.9 witness generated

---

*Implementation Date: 2026-07-24*  
*Target: RawrXD Certification v1.1*
