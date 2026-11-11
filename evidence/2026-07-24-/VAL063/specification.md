# VAL-063: CLI Inference Gateway Binding
## Specification v1.1 (Enhanced)
## Date: 2026-07-24
## Status: PENDING (Target: RawrXD Certification v1.1)

---

## Overview

VAL-063 validates the end-to-end inference path from awrxd.exe CLI through the inference engine to emitted tokens. This gate closes the remaining integration boundary identified in RawrXD Certification v1.0.

**Certification Statement**: v1.0 proves "RawrXD can correctly execute transformer workloads." v1.1 proves "RawrXD can expose that execution as a deterministic inference service."

---

## Scope

`
rawrxd.exe
    ↓
CLI argument parsing
    ↓
GGUF loader (validated in v1.0)
    ↓
Tensor view resolution
    ↓
Tokenizer initialization
    ↓
Transformer forward pass
    ↓
Logits generation
    ↓
Sampler (temperature/top_k/top_p)
    ↓
Token emission
    ↓
Streamed output
    ↓
Witness correlation (end-to-end proof)
`

---

## Core Proof Requirements (VAL-063.1 to VAL-063.9)

### VAL-063.1: CLI Load
- **Test**: awrxd.exe --model model.gguf --prompt "test"
- **Verify**: Process launches without crash
- **Witness**: witnesses/cli.json

### VAL-063.2: Tensor View Resolution
- **Test**: GGUF tensors map to runtime tensor views
- **Verify**: All required tensors present (token_embed, layers, output_norm, output)
- **Witness**: witnesses/tensors.json

### VAL-063.3: Tokenizer Initialization
- **Test**: Tokenizer loads from GGUF or external file
- **Verify**: Vocabulary size matches model config
- **Witness**: witnesses/tokenizer.json

### VAL-063.4: Forward Pass Execution
- **Test**: Single forward pass with dummy input
- **Verify**: No crash, logits shape correct
- **Witness**: witnesses/forward.json

### VAL-063.5: Logits Production
- **Test**: Logits tensor produced with correct dimensions
- **Verify**: [batch, seq_len, vocab_size] shape
- **Witness**: witnesses/logits.json

### VAL-063.6: Sampler Selection
- **Test**: Sampler selects token from logits
- **Verify**: Temperature=0 produces deterministic output
- **Witness**: witnesses/sampler.json

### VAL-063.7: Token Emission
- **Test**: Token decoded to string
- **Verify**: Output matches expected format
- **Witness**: witnesses/emission.json

### VAL-063.8: Streamed Output
- **Test**: Full generation with streaming
- **Verify**: Output matches deterministic witness
- **Witness**: witnesses/stream.json

### VAL-063.9: Replay Reproduction
- **Test**: Same seed/config produces identical output
- **Verify**: Bitwise match between runs
- **Witness**: witnesses/replay.json

---

## Enhanced Proof Requirements (VAL-063.10 to VAL-063.12)

### VAL-063.10: Witness Chain Correlation ⭐ NEW
**Purpose**: Prove all stages belong to the same execution path.

**Test**: Single execution generates correlated witnesses across all stages.

**Verification**:
`json
{
  "gate": "VAL-063.10",
  "name": "End-to-End Witness Correlation",
  "execution_id": "uuid-v4",
  "correlation_chain": {
    "model_hash": "sha256:E73056A...",
    "prompt_hash": "sha256:abc123...",
    "tensor_manifest_hash": "sha256:def456...",
    "token_sequence_hash": "sha256:ghi789...",
    "output_hash": "sha256:jkl012..."
  },
  "chain_integrity": "verified",
  "status": "PASS"
}
`

**Prevents**: Component passing without actual runtime connection.

### VAL-063.11: Error Boundary Validation ⭐ NEW
**Purpose**: Production inference needs failure correctness.

**Test Matrix**:
| Input | Expected Behavior | Witness |
|-------|-----------------|---------|
| Invalid GGUF | Clean error, no crash | witnesses/errors_invalid_gguf.json |
| Missing tensor | Diagnostic emitted | witnesses/errors_missing_tensor.json |
| Bad tokenizer | Diagnostic emitted | witnesses/errors_bad_tokenizer.json |
| OOM condition | Controlled recovery | witnesses/errors_oom.json |
| Corrupted weights | Graceful degradation | witnesses/errors_corrupted.json |

**Success Criteria**:
`json
{
  "failure_mode": "controlled",
  "crash": false,
  "diagnostic_emitted": true,
  "recovery_possible": true,
  "status": "PASS"
}
`

### VAL-063.12: Streaming Contract ⭐ NEW
**Purpose**: Define streaming ABI for IDE integration.

**Streaming Event Schema**:
`json
{
  "event": "token",
  "id": 1234,
  "text": "hello",
  "position": 42,
  "latency_ms": 8.4,
  "timestamp": "2026-07-24T12:00:00Z",
  "execution_id": "uuid"
}
`

**Test**: Verify ordered token delivery
`
rawrxd.exe
    |
    v
stream interface
    |
    v
consumer receives ordered tokens
`

**Witness**: witnesses/streaming_contract.json

**Enables**:
- Ghost text
- Monaco streaming
- Agent loops
- Tool invocation
- Multi-agent orchestration

---

## Evidence Structure

`
VAL063/
├── specification.md              ← This file
├── result.json                   ← Overall VAL-063 result
├── manifest.json                 ← Witness manifest with hashes
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
    ├── correlation.json          ← VAL-063.10 ⭐
    ├── errors.json               ← VAL-063.11 ⭐
    └── streaming_contract.json   ← VAL-063.12 ⭐
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
    "VAL-063.1": "PASS",
    "VAL-063.2": "PASS",
    "VAL-063.3": "PASS",
    "VAL-063.4": "PASS",
    "VAL-063.5": "PASS",
    "VAL-063.6": "PASS",
    "VAL-063.7": "PASS",
    "VAL-063.8": "PASS",
    "VAL-063.9": "PASS",
    "VAL-063.10": "PASS",
    "VAL-063.11": "PASS",
    "VAL-063.12": "PASS"
  },
  "deterministic": true,
  "replayable": true,
  "streaming_contract": "validated",
  "error_boundaries": "controlled",
  "witness_correlation": "verified"
}
`

---

## Integration with v1.0

VAL-063 extends RawrXD Certification v1.0 without modification:

`
RawrXD Certification v1.0
        │
        ├── 47 gates PASS ✅
        ├── Replay verified ✅
        └── GGUF→logits PENDING
                │
                └── VAL-063 (v1.1)
                      │
                      ├── Core: VAL-063.1-9
                      ├── Correlation: VAL-063.10 ⭐
                      ├── Errors: VAL-063.11 ⭐
                      └── Streaming: VAL-063.12 ⭐
                                │
                                └── RawrXD Certification v1.1
                                      (End-to-End Inference Platform)
`

---

## Post-v1.1 Roadmap

After VAL-063 passes, next gates become product-grade certification:

| Gate | Description | Target |
|------|-------------|--------|
| VAL-064 | API/SDK Contract | v1.2 |
| VAL-065 | Multi-model Lifecycle | v1.2 |
| VAL-066 | Hot Reload / Model Swap | v1.2 |
| VAL-067 | Production Observability | v1.3 |
| VAL-068 | Release Candidate Freeze | v1.3 |

---

## Implementation Notes

1. **Non-blocking**: VAL-063 can be implemented independently
2. **Additive only**: No changes to v1.0 evidence
3. **Separate milestone**: v1.1 certification requires VAL-063 PASS
4. **Replay compatible**: Uses same Verify-Certification.ps1 framework
5. **Enhanced coverage**: 12 subtests (was 9, now 12)

---

*Specification Date: 2026-07-24*  
*Version: 1.1 (Enhanced)*  
*Target Certification: RawrXD v1.1*
