# REAP CLI contract receipt — 2026-10-25

Source tree: `F:\rawrxd`

Build directory: `F:\rawrxd\build_reap`

Target: `RawrXD-CLI-V2` (`bin-msvc\rawr.exe`)

Executable SHA-256: `750C68AD7C7FE4F42D55AB5D614E43B6B91BFD08DF30E0A1BF37F14948737312`

## Verification

- MSVC x64 Release target build: PASS (`194/194`, exit 0; rebuilt after diagnostic I/O gating)
- `rawr_reap_cli_contract` CTest: PASS (`1/1`, exit 0)
- `rawr-reap-cli-contract-test`: PASS (`REAP_CLI_CONTRACT_PASS`)
- Valid `rawr reap ... --target-size 30GB --active-experts 64 --expert-budget 20GB --quality-floor 0.95`: exit 4, `REAP_RUNTIME_UNAVAILABLE`
- Valid `rawr run ... --reap ...`: exit 4, `REAP_RUNTIME_UNAVAILABLE`
- Expert budget greater than target: exit 2, `REAP_EXPERT_BUDGET_EXCEEDS_TARGET`
- Missing quality floor: exit 2, `REAP_QUALITY_FLOOR_INVALID`
- MLA diagnostic probes: opt-in through `RAWRXD_MLA_DIAGNOSTICS=1`; disabled by default so probe I/O does not serialize production decode measurements

## Admission boundary

The parser and semantic validator are implemented. The receipt reports
`transformation_enabled=false` because MLA-CERT-001, model-specific
calibration/selection, and parity-certified GGUF rewriting are not present in
the same runtime. No model was modified and no reduced checkpoint was
generated. This interface must remain blocked until those evidence gates pass.
