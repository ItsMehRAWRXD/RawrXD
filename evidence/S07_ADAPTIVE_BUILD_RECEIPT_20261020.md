# S07 adaptive verifier build receipt — 2026-10-20

- CMake target: deep2_spec_bench
- Configuration: Release / Visual Studio 17 2022 / x64
- Build exit: 0
- Changes: explicit verifier batch/position/repair/fallback counters; adaptive disable threshold 8 → 2 zero-accept rounds
- Executable SHA-256: 2CDFAA6C4ADA3285CE190086B244ED71E1AB31864EDEF5C70E56433412A9814F
- Runtime validation: both 128-token diagnostic runs exited 0 with exact serial/spec streams, finite logits, and zero CPU calls
