# Gate 5 — CLI Regression

All checks used the recorded binaries in `BINARY_IDENTITY.md`.

- `rawr.exe --help`: exited `2`, printed `Unknown command: --help` and usage cleanup. This is an observed unsupported-command path, not a PASS for a help command.
- `rawr-reap.exe --help`: exited `2`, printed the command usage, and shut down the stream engine.
- `rawrxd_deep2_engine.exe` with no model: exited `0`, printed usage, unloaded an empty model state, and completed normal Deep2 teardown.
- `rawrxd_health_probe.exe`: exited `0`, reported `healthy (liveness=true readiness=true)`.

Real model loading, token generation/commit, and resource behavior with a model were not run in this bounded pass. Gate 5 therefore remains `PARTIAL`, not PASS.
