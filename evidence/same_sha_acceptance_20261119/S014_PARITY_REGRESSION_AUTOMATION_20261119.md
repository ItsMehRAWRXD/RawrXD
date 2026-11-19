# S014 parity regression automation

Added `tools/run_parity_regression.py`, a deterministic offline regression command that:

- requires every requested Deep2/reference position;
- rejects missing files and vector-size mismatches;
- checks finiteness, cosine, RMS, max absolute error, top-1, and top-10 overlap;
- returns exit `5` for a strict-parity failure rather than claiming bounded agreement;
- writes a machine-readable JSON report.

Command:

```powershell
py -3 tools/run_parity_regression.py --root evidence/same_sha_acceptance_20261119 --positions 5 --out evidence/same_sha_acceptance_20261119/S014_qwen_report.json
```

Observed exit: `5` (`STRICT_PARITY=FAIL`). The run compared five positions with 151,936 elements each, all finite, top-1 exact `5/5`, minimum cosine `0.9980973923169006`, and worst max error `0.93182373046875`.

```ini
REGRESSION_AUTOMATION=IMPLEMENTED
STRUCTURAL_VALIDATION=PASS
BOUNDED_COMPARISON=PASS
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
