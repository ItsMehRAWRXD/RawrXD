# AGENT_SHELL_CHANNEL_RECOVERY_001 — Assessment ack

No new technical dispatch launched (existing [Harness recovery OS forensics](553a7f51-2138-4e07-aa44-5d213d846e00) still owns recovery).

## Channel split (important)

| Channel | Status | Evidence |
|---------|--------|----------|
| Parent Cursor Agent Shell | UNRESPONSIVE (historical + post-abort probes) | empty stdout / hung terminals |
| Recovery subagent shell | PASS at 13:37:06Z | `HARNESS_RECOVERY…/SHELL_PROBE.md` — `HELLO`, EXIT=0, ~1035 ms |
| Native `cmd.exe` outside Cursor | NOT_RUN by this agent | Operator step 2–3 |

Parent Agent Shell recovery is **not** closed by subagent success. Objective of this gate remains: verified stdout + exit + timeout on the **Agent Shell** channel used for certification, or explicit classification as unresolved agent execution-channel defect with Cursor logs preserved.

## Operator sequence (unchanged)

1. Let recovery worker finish / bound-timeout — no competing shell workers.
2. Outside Cursor: `cmd.exe /d /c echo HELLO`.
3. If native OK → restart Cursor → retest Agent Shell without Tee/wrappers.
4. If Agent Shell still dead → preserve Cursor logs; classify unresolved agent channel defect.
5. Only then treat parent channel as fit for fresh same-SHA E2E certification runs.

## Boundary

Historical PRODUCT_BINARY_SEAL ChatWindow FAIL stays historical. Any receipts under `HARNESS_RECOVERY_AND_OS_FORENSICS_001\` from the recovery worker are separate same-SHA runs — do not conflate with parent-shell recovery PASS.
