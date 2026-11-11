# RawrXD 25-gate acceptance ledger

The machine-readable source of truth is [RAWRXD_25_GATE_ACCEPTANCE.json](RAWRXD_25_GATE_ACCEPTANCE.json). It defines 25 ordered completion gates across provenance, numerical correctness, full-model behavior, multi-GPU, REAP, and IDE integration. **All gates start PENDING**; the repository contains diagnostic tools, not released certifications.

## How evidence is evaluated

Use a private evidence directory with zero or one JSON file for each gate, named `G01.json` through `G25.json`. Run:

```powershell
python tools/test_audit_rawrxd_25_gates.py
python tools/audit_rawrxd_25_gates.py --manifest docs/RAWRXD_25_GATE_ACCEPTANCE.json --evidence-dir F:\rawrxd\evidence\RAW_COMPLETION_001 --output F:\rawrxd\evidence\RAW_COMPLETION_AUDIT_001.json
```

The structural checker refuses missing/malformed receipts, mismatched IDs, non-PASS checks, nonzero exits, and absent SHA-256-format hashes. It requires every receipt to contain these fields: `gate_id`, `status`, `certified=false`, `exit_code=0`, `command`, `model_sha256`, `binary_sha256`, `source_sha256`, `evidence_sha256`, and nonempty `checks` containing explicit PASS names.

**Critical:** this checker does *not* validate that a listed hash identifies a genuine binary, model, execution, or numeric artifact. A JSON file can be forged. Therefore even 25 structurally complete receipts yield `EVIDENCE_COMPLETE_UNVERIFIED`, `certified=false`, `promote=0`, and `tip_climb=HOLD`. A human reviewer and independent hardware/model/output attestation must verify the backing artifacts before any release decision. The `PENDING` declarations in the manifest must not be edited to `PASS` to imitate certification.

## First gating sequence

Gate G01 must freeze the source, model and binary identities before comparative runs. G02 and G03 require independently compiled GGML decoder parity, not merely another transcription in Python. G04 requires captured same-expert quantized inputs and the normalized input vector. G05 requires a completed GPU post-SwiGLU activation witness with stable ownership. G06 requires the completed one-expert GPU down vector and elementwise oracle comparison. G07–G10 expand coverage, repeatability, transfers and tolerance governance. G11–G25 remain blocked until their respective end-to-end receipts exist.

Current PR #62 has source for scalar oracles, input capture, aggregate repeatability and test harnesses. There is no verified real-model GPU per-expert parity receipt. Prior GitHub Actions jobs have failed without accessible step logs. Run the local test harness before claiming any numerical gate. Do not upload model weights, private evidence, or executable bundles to a public PR.

```ini
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED_GATES=0
GPU0_PARITY=NOT_CERTIFIED
```
