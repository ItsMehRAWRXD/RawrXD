# S014 parity regression rerun

Command:

```powershell
py -3 tools/run_parity_regression.py --root evidence/same_sha_acceptance_20261119 --positions 5 --out evidence/same_sha_acceptance_20261119/S014_qwen_report_rerun.json
```

Observed exit: `5` (`STRICT_PARITY=FAIL`). The runner compared five positions
with 151,936 elements each. All values were finite, exact top-1 agreement was
`5/5`, minimum cosine was `0.9980973923169006`, and worst maximum absolute
error was `0.93182373046875`.

The nonzero exit is the intended fail-closed result for strict parity, not a
missing-artifact or malformed-input failure.

`S014=DETERMINISTIC_RERUN_COMPLETE`
`PROMOTE=0 CERTIFIED=0 RELEASE=HELD`
