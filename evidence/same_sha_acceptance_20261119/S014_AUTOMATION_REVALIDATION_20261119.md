# S014 parity automation revalidation

Command:

```powershell
py -3 tools/run_parity_regression.py `
  --root evidence/same_sha_acceptance_20261119 `
  --positions 5 `
  --out evidence/same_sha_acceptance_20261119/S014_qwen_report_current.json
```

Observed exit: `5`, with the tool emitting `STRICT_PARITY=FAIL`.

The runner compared five positions with 151,936 elements each, verified all
values finite, and reported top-1 agreement `5/5`. Minimum cosine was
`0.9980973923169006`; worst max error was `0.93182373046875`. The nonzero exit
correctly prevents bounded agreement from being promoted to strict parity.

```ini
S014=AUTOMATION_REVALIDATED
STRUCTURAL_VALIDATION=PASS
BOUNDED_COMPARISON=PASS
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
