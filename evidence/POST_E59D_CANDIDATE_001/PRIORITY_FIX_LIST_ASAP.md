# Priority Fix List (ASAP)

ASOF_UTC=2026-11-09T01:24:30Z
PROGRESSION_AUTH=ALL_GRANTED
PROMOTE=0
CERTIFIED=0
CONTROLLING_BASELINE=55BE19B7…
ACTIVE_SHA=323A38A0849EFDE08F735EF85D97009D68C4700C9670317FCC2B630E85580E37

| Pri | Fix | Action | Status |
|-----|-----|--------|--------|
| P0 | T07 Unicode | RICHEDIT50W recreate; UTF-16 / EM_GETTEXTEX CP1200 | PASS on `323A38A0…` |
| P0 | T08 buffer sync | Save outgoing / restore incoming on tab switch | PASS PRESERVED=10 |
| P0 | T08 harness | TCM_GETITEMCOUNT `0x1304` + WM_APP+111 activate | PASS |
| P0 | Request A Cancel | Survival on progression SHA | SURVIVES=0 crash `-1073740771`; T05 NOT_RUN; DEFECT NOT_PROVEN |
| P1 | T15 autonomous edit | Approval paths + model args + disk exact | Follow-up CLOSED; do not reopen |
| P1 | T24 installer | Build/install/launch/uninstall/cleanup | NOT_RUN |
| P1 | T10 session restore | Marker in session not restored | FAIL on `323A38A0…` |
| P1 | Finish-25 closeout | Remaining gates + complete evidence | 19/25 controlling |

Order remaining: Request A cancel recovery → T10 session restore → T24 → formal Finish-25 credit on one RC.
STOP_GENERIC_SNIPPETS=1 · batches 46–120 not implemented.
