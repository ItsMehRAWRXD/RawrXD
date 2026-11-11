# Final Verdict

`PATH_ATTRIBUTION=PASS_STATIC`

The harness now distinguishes the exact candidate executable from other native IDE builds without weakening the shared-state safety rule. `PROCESS_ISOLATION` is not promoted to PASS until a physical run occurs with no conflicting process and verified ownership.

`GATE_6=HELD`, `PROMOTE=0`, `CERTIFIED=0`.
