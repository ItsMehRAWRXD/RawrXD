# Replay Verifier Specification
## RawrXD Certification Replay System

### Purpose
Convert evidence package from recorded snapshot to independently executable proof.

### Verification Chain
```
verify_certification.exe evidence/2026-07-24-/
    |
    +-- [1] Verify commit hash against git
    |
    +-- [2] Verify binary SHA256 matches file
    |
    +-- [3] Verify model SHA256 matches file
    |
    +-- [4] Execute inference with recorded config
    |
    +-- [5] Capture actual tokens
    |
    +-- [6] Compare against tokens.json
    |
    +-- [7] Verify latency within bounds
    |
    +-- [8] Emit CERTIFIED/FAILED
```

### Measured vs Declared
| Value | Current | Target |
|-------|---------|--------|
| tokens_per_second | Declared (4000) | Measured from execution |
| latency_ms | Declared (8) | Measured from execution |
| coverage_percent | Declared (85.3) | Measured from tool output |
| deterministic output | Declared | Verified by comparison |

### Success Criteria
- All SHA256 hashes match
- Inference executes without error
- Token count matches witness
- Latency within 10% of recorded
- Output is deterministic (same seed = same tokens)
