# RawrXD ScreenPilot E2E Final Integration Drop

This package is the follow-through audit and production wiring kit for the
supplied 30k-line ScreenPilot HTML.

## Start here

1. Read `SCREENPILOT_LOCAL_AGENT_E2E_FINAL_AUDIT.md`.
2. Apply `integration/ide_chatbot_screenpilot_final.patch`, or replace the
   current HTML with `web/ide_chatbot_screenpilot_final.html`.
3. Add `rawrxd_screenpilot_e2e` to the RawrXD CMake tree.
4. Follow `integration/RAW_RXD_INTEGRATION_MAP.cpp.txt`.
5. Run `python tests/static_audit.py`.
6. Build the shipping IDE.
7. Run `tests/certify_screenpilot_e2e.ps1`.
8. Run `tests/certify_mutation.ps1`.
9. Perform the approval-denial gate from `tests/approval_gate_prompt.txt`.
10. Launch the shipping IDE with no smoke environment variables and manually
    prove send/receive + tool receipts after panel load.

## Production path

```text
http://127.0.0.1:11435/screenpilot
  -> existing RawrXD LocalServer
  -> /api/v1/screenpilot/agent/run
  -> canonical Agent Coordinator
  -> canonical Tool Authority
  -> Deep2/local model + approved tools
  -> NDJSON stream
  -> ScreenPilot UI
```

The temporary standalone :11437 subprocess bridge is not the shipping target.

## Why V2 supersedes the prior finish drop

The earlier in-process adapter established the correct one-server topology, but
this audit found four additional requirements for a privileged browser agent:

- server-derived mode permissions,
- per-tool workspace enforcement,
- explicit approval for elevated operations,
- session/tool-authority handling for historical privileged browser routes.

V2 implements/contracts those requirements.

## No false receipt policy

This source drop can statically verify the generic adapter and patched HTML.
It cannot certify your actual LocalServer/coordinator mapping until it is
compiled and executed inside the RawrXD repository. The runtime scripts exist
specifically to make that boundary measurable.
