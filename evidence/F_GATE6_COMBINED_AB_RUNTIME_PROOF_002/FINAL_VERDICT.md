# Gate 6 Combined A/B Runtime Proof

Date: 2026-11-02

Candidate binary: `F:/rawrxd/build_ghosttext_boundary/bin/RawrXD-Win32IDE-Native.exe`

Candidate SHA-256: `B10BF30BBBDCB41A43F366BF3D39E9EDF42EA75ABE8F1DE5EF20B3020C3E4BEC`

Frozen authority SHA-256: `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145`

## Same-run evidence

- Native focus before typing: active HWND `2231514`; focused class `RichEdit20A`, control ID `1001`.
- Model selector visibly and natively selected: `Local models / Ollama / qwen3:8b`.
- Request A: ID 1, triggered `04:04:58`, route `qwen3:8b`, delayed completion.
- Request B: ID 2, triggered `04:04:59`, route `qwen3:8b`.
- A response: `04:05:05`, success `1`, 4 bytes, generation current `0`, render decision eligible `0`.
- B response: `04:05:11`, success `1`, 512 bytes, render decision eligible `1`, rendered.
- The debug pane exposed the rendered B completion in the central editor.
- Candidate process was test-owned and forcibly cleaned after the run; no other RawrXD process was terminated.
- Final ordering run used `RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS=30000` and `RAWRXD_GHOSTTEXT_TEST_DELAY_B_MS=50`.
- Final trace: B rendered at `04:10:29`; A completed at `04:10:58` and was rejected.

## Verdict

`COMBINED_AB_RUNTIME=PASS`

`EDITOR_FOCUS=PASS`

`QWEN3_8B_ROUTING=PASS`

`AB_OVERLAP=PASS`

`B_BEFORE_A=PASS`

`B_RENDER=PASS`

`LATE_A_REJECTION=PASS`

`CANDIDATE_INTEGRITY=PASS`

`FROZEN_AUTHORITY=UNCHANGED`

This receipt does not certify the product or authorize promotion. `PROMOTE=0`, `CERTIFIED=0`, and `TIP_CLIMB=HOLD` remain in force.
