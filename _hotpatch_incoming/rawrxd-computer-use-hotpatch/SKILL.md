---
name: rawrxd-computer-use-hotpatch
description: Fail-closed Windows GUI acceptance workflow for RawrXD native IDE model routing and GhostText.
---

# RawrXD Computer-Use Hotpatch

## Scope
Operate on the user's own Windows workstation. This is a reproducible replacement workflow, not recovered proprietary computer-use code. Do not assert GUI PASS from build logs or model output text alone.

## Preconditions
- Windows PowerShell 5.1+; IDE executable exists.
- User-authorized local GUI session with desktop unlocked.
- Ollama endpoint and model names configured locally.
- Evidence directory writable. Preserve existing evidence and do not overwrite certification.

## Workflow
1. Run `scripts/Start-RawrXDAcceptance.ps1 -ExePath 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe' -ExpectedSha256 '<sha>'`.
2. Confirm launched process and capture a screenshot from the active desktop using an authorized GUI tool. If no GUI automation interface is available, have the user operate the UI and capture screenshots manually.
3. Select model A in the GUI. Submit a unique marker in **agent mode**. Capture selected GUI model, resolved agent model, actual outbound Ollama `model` field, request ID, and response association. Repeat with model B without restarting.
4. Trigger GhostText with each selected model. Record actual Ollama `model` field and request ID. Do not infer identity from response content.
5. Start a long generation, cancel, submit a new unique marker. Verify no stale chunks or prompt corruption. Keep timestamps and raw logs.
6. Write `routing-evidence.json` using the provided template; run `scripts/Test-RawrXDEvidence.ps1`.
7. Never change `PROMOTE=0`, `CERTIFIED=0`, `T25=HELD` automatically. Promotion requires separate authorized certification decision.

## Ollama identity capture
Preferred: instrument RawrXD's outgoing HTTP request path immediately before send, logging timestamp, request ID, request kind (chat/agent/ghosttext), GUI selected model, resolved model, and JSON `model` value. Redact prompt content and credentials. Alternative: use a locally controlled loopback HTTP proxy *only when the IDE is explicitly configured to use it*. A generic Ollama server log or the displayed answer is insufficient to prove which request originated from which UI action.

## Hotpatch discipline
- Make minimal source edits on a dedicated branch and save `git diff` before/after.
- Rebuild, hash the executable, and re-run the full acceptance matrix after each change.
- Do not inject into processes, modify binary memory, bypass security checks, or claim test results without observed evidence.
- Stop on hash mismatch, process failure, unavailable GUI, missing model identity, or stale-output leakage.

## Pass criteria
For both model A and model B: selected model == expected resolved model == outbound Ollama JSON model for agent and GhostText requests; exact request correlation; no duplicate/stale output; cancellation recovery PASS. All evidence must refer to the exact executable SHA.
