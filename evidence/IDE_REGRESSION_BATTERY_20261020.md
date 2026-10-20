# IDE regression battery receipt

- Native IDE route target: PASS (post-commit build and link)
- Full default CMake Release build: FAIL
- Full-build blocker: legacy `rawrxd_hexmag_repeat` MASM target; linker error `LNK1181` for `rawrxd_hexmag_repeat.dir\\Release\\RawrXD_HexMag_RepeatTuner.obj`
- CTest inventory: 14 registered tests, most executables absent from the configured output paths
- H11 target build: PASS
- H11 CTest invocation: FAIL because the registered test supplies no required model argument
- H11 manual TinyLlama invocation: FAIL closed on non-finite `blk.0.attn_output.weight` output for chunks 1, 2, 16, and 128

These are genuine current-checkout validation results. They leave the inference
regression and the default build/test wiring open. The route-menu source remains
separately build-certified in `evidence/IDE_NATIVE_ROUTE_SOURCE_CERT_20261020.md`.
