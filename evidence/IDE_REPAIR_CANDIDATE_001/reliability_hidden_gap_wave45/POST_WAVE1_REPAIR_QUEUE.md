# Prioritized repair queue — AFTER Wave1

```text
ASOF_UTC=2026-11-10T08:20:00Z
PRECONDITION=WAVE1_REAL_TOOL_READ_AND_CU_E2E=PASS on ONE new candidate SHA
RC4=SEALED_IMMUTABLE
MATURITY=82%_ESTIMATE_UNCHANGED
PROMOTE=0
TIP_CLIMB=HOLD
I57_AUTO_DEFECT=0
```

Priority = dependency order for **one post-Wave1 SHA**. Historical 4DE0/CC79/47451 results do not close these rows.

| Pri | Item | Type | Owner | Why this order | Exit receipt |
|----:|------|------|-------|----------------|--------------|
| 0 | Pin post-Wave1 EXE SHA + freeze candidate identity | Process | WS01 / Cert | No cross-SHA inherit into W4/W5 | `IDENTITY_RECEIPT` on candidate |
| 1 | **W4-EXT-01** Ext host load/alive | Obligation | WS20 | Unlocks surface regression + cleanup proof | Ext start markers |
| 2 | **W4-EXT-02** Ext clean quit `FORCE_KILL=0` | Re-prove hist H-C2 | WS20 | Prior sealed FAIL; must not assume fixed | Ext quit summary FORCE_KILL=0 |
| 3 | **W4-CAN-01** Chat cancel ack (re-prove G09-class) | Obligation | WS09 | Needed before persist conjunction | cancel_requested/ack |
| 4 | **W4-MSW-01** Idle model switch | Obligation | WS15+WS03 | Independent of tools; early reliability | Backend model id change + Send |
| 5 | **W4-PER-01** Session persistence restart | Obligation | WS21 | Re-prove G11-class on new SHA | ide_session.json roundtrip |
| 6 | **W4-PER-02** Persist after cancel+model-switch | Obligation | WS21 | Conjunction of 3–5 | Restart after CAN+MSW |
| 7 | **W4-REC-01** Kill/restart no zombies | Obligation | WS23 | Re-prove G12-class | Process cleanup receipt |
| 8 | **W4-CAN-02** Mid-flight CU cancel | Obligation | WS09+WS08 | Requires Wave1 CU attach | Mid-CU cancel+cleanup |
| 9 | **W4-CAN-03** Cancel during tool-read/edit | Obligation | WS09+WS04 | Session integrity under tools | Session usable after cancel |
| 10 | **W4-MSW-02** Model switch with tools still bound | Obligation | WS15+WS04+WS08 | Registry must survive rebind | Tool call after switch |
| 11 | **W4-EXT-03** Ext healthy across tool turn | Obligation | WS20+WS05 | Ext+agent interaction | No orphan ext proc |
| 12 | **W4-REC-02/03** Tool-FAIL recovery + snapshot rollback | Obligation | WS23+WS07 | After edit path exists (Wave2 may share) | Recovery + A15-shaped receipt |
| 13 | **W5-REG-01** Four-panel conjunction | Re-prove hist H-C4 | WS10–14+WS20 | Full-feature entry | Four-panel harness |
| 14 | **W5-REG-02** Problems click-to-line | Re-prove hist H-C1 | WS12 | Hidden-gap daily driver | Problems fixture receipt |
| 15 | **W5-REG-06** Re-measure prior PASS axes | Obligation | WS23/Cert | Regression guard | G02/G07/G09/G11/G13/G14 on new SHA |
| 16 | **W5-REG-05** I57 A08–A15 daily-driver subset | Obligation | Surfaces+Agent | Product path IDE gates | Per-gate receipts |
| 17 | **W5-REG-03** Finish-25 recount | Obligation | WS25 | No invent closure | SHA-bound matrix |
| 18 | **I57 A01–A07** Build/CI/admission obligations | Obligation | WS01 | Parallelizable after identity pin | Per-gate receipts |
| 19 | **I57 A11–A14** LSP/GhostText/Browser/Debugger | Obligation | WS13–14 | After editor/surface stable | Per-gate receipts |
| 20 | **I57 B\*** compiler/slingshot | Obligation | Compiler lane | Not first daily-driver; schedule after A | Per-gate receipts |
| 21 | **I57 C\*** GPU/TPS/matrix/release | Obligation | GPU/Perf/WS24 | After correctness; hardware-gated | Per-gate receipts; C12 no synthetic |
| 22 | Open **CONFIRMED_BLOCKER** only if a Pri 1–17 run FAILs with repro | Process | Gate owner | Never bulk-fail 45 | Defect ticket + receipt |

## Explicitly deferred / not first-line after Wave1

- Bulk marking Issue #57 A/B/C as defects (`I57_AUTO_DEFECT=0`)
- Maturity climb 91→94 or 94→97 without sealed same-SHA milestone PASS
- Inheriting 4DE0 EXT/cancel/persist PASS onto repair candidate
- B13–B15 cross-platform as daily-driver blockers
- C12 150 TPS as a defect if unattainable
- Wave3 GPU dual-device before W4 reliability core
- Dashboard / Freeze Control 401 (non-IDE blocker)

## Queue summary

```text
POST_W1_P0_IDENTITY=1
POST_W1_W4_CORE_SERIAL=EXT-01,EXT-02,CAN-01,MSW-01,PER-01,PER-02,REC-01
POST_W1_W4_TOOL_COUPLED=CAN-02,CAN-03,MSW-02,EXT-03,REC-02,REC-03
POST_W1_W5_REGRESSION=REG-01,REG-02,REG-06,REG-05,REG-03 then I57 schedule
NEW_CONFIRMED_BLOCKERS_FROM_THIS_PACKET=0
OBLIGATIONS_RETAINED=45_I57 + W4/W5_gate_rows
MATURITY_CHANGE=0
```
