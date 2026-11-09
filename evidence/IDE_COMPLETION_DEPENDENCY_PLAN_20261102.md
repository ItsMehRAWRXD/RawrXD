# IDE completion dependency plan

## Critical path

```text
authoritative source graph
  -> ExtensionHost launch repair
  -> candidate-only Win32IDE relink
  -> GUI smoke receipts
  -> model discovery/selection/stream/cancel
  -> GhostText accept/reject
  -> agent tool permissions + file edit/build/test/repair
  -> workspace/settings restart restore
  -> Deep2 CPU/GPU/K2 parity
  -> host stability + certification
  -> promotion decision (still held)
```

## Work queue

| ID | Action | Authority | Regression/evidence |
|---|---|---|---|
| P1 | Select one authoritative IDE target and document source graph | Source-only | CMake configure graph; target/source manifest |
| P2 | Trace ExtensionHost child creation, failure path, and lifecycle | Source-only | static call-site report; no PASS claim |
| P3 | Implement minimal ExtensionHost repair if source confirms defect | Source-only, candidate build only | unit/fixture test; candidate SHA |
| P4 | Run GUI feature matrix on candidate after authorization | Candidate + host gate | editor/model/terminal/debugger/agent/restart receipts |
| P5 | Close real model streaming/cancellation/GhostText loop | Candidate + local model | model name, prompt, streamed output, acceptance receipt |
| P6 | Complete agent tool matrix and 1–16 swarm cancellation/idle-stop | Candidate + host gate | exact file diffs, build/test logs, stop receipt |
| P7 | Resolve K2/GPU parity and dual-GPU binding | Authorization + host RAM/stability | token/logit parity and device-binding receipts |
| P8 | Drain remaining audit residuals | Source-only until runtime is required | updated `AUDIT_002` matrix and hashes |
| P9 | Clean offline build/install/first-run certification | Promotion-only boundary | clean-build hash and installation receipt |

## Explicitly gated operations

The following remain unauthorized or blocked: frozen-tip replacement, candidate absorb, R28 APPLY, promotion, heavy runtime testing before host stability clearance, and any claim that a different binary's PASS applies to the frozen authority.

## Rollback

All implementation work must remain on a candidate branch/build directory. Preserve the frozen executable and existing evidence. Roll back by discarding only the candidate build/output or reverting the isolated source change after capturing the failure receipt; never overwrite `TIP_FREEZE_001`.

