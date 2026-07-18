# Gate D Statistical Validation Summary

**Date:** 2026-07-17 17:53:21  
**Status:** ⚠️ PARTIAL

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total Runs | 100 |
| Pass Rate | 0% |
| Mean Duration | 15.11 ms |

## Kernel Speedups (Mean)

| Kernel | Speedup | Status |
|--------|---------|--------|
| SiLU Activation | 3.11x | ✅ |
| RMS Normalization | 0.96x | ❌ |
| Softmax | 0.52x | ❌ |

## Confidence Intervals (95%)

| Kernel | Mean Cycles | CI Lower | CI Upper |
|--------|-------------|----------|----------|
| SiLU Scalar | 24301.68 | 19308.93 | 29294.43 |
| SiLU MASM | 3892.91 | 3121.36 | 4664.46 |

## Gate D Completion

⚠️ **Gate D Partial** - Additional runs or investigation required
