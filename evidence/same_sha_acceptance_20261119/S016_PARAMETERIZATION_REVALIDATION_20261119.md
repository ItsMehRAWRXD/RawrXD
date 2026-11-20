# S016 model-path parameterization revalidation

Source inspection confirms the native probe no longer contains the old
`bench_min.gguf` fallback. It resolves `RAWRXD_DEEP2_PROBE_MODEL`, then
`RAWRXD_MODEL_PATH`, and fails closed with `MODEL_PATH_UNSET` when neither is
available. The bridge initialization path also accepts
`RAWRXD_DEFAULT_DEEP2_MODEL`, then `RAWRXD_MODEL_PATH`, then the selected model.

This is a source/configuration correction. No fresh native executable or GUI
runtime acceptance was produced in this revalidation.

```ini
S016=SOURCE_REVALIDATED
HARDCODED_PROBE_PATH=ABSENT
CONFIGURABLE_MODEL_PATH=PASS
UNSET_PATH=FAIL_CLOSED
FRESH_LINK=NOT_RUN
GUI_RUNTIME=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
