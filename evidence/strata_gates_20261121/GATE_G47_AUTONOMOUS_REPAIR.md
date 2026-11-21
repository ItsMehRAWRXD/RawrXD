# Gate G47 — Autonomous edit/build/test/repair => PASS

## Summary
The agent (llama3.2:3b via Ollama, mode=code, sandboxed to the fixture with
`--root`) autonomously edited a failing source file, rebuilt, and ran the test
suite to a verified green result.

## Sandbox / config
```
rawr --root F:\rawrxd\evidence\strata_gates_20261121\g47_fixture \
     run llama3.2:3b --mode code --backend ollama \
     --task "... edit_files return 1 -> return 0 ... run_build config Release ... run_tests config Release ..." \
     --max-tokens 400
```
- Root isolated to the fixture (`Root: ...\g47_fixture`); edits/execute allowed by
  policy; 11 tools registered.
- Fixture: `main.cpp` = `int main(){ return 1; }` (failing), CMakeLists + ctest
  `g47test` configured/generated in `build/` (VS 2022, Release).

## Autonomous run (turns=6, tool_calls=5, denied=0)
```
[ok]   edit_files {"new":"return 0;","old":"return 1;","path":"main.cpp"}
[ok]   run_build  {"config":"Release","dir":"."}
[ok]   run_tests  {"config":"Release","dir":".","filter":""}
Summary: Fixed c47test by changing main.cpp to return 0;
exit=0   (agent produced FINAL answer at turn 6)
```

## Independent verification (not model-reported)
- `main.cpp` after: `int main() { return 0; }`
- Fresh exe: `build\Release\g47app.exe`, mtime 13:31:23,
  SHA-256 `7CB392388A82813DD5FCEC2C8C3D559AF7D68A8C056EFDBA2EDACA59B98A8983`
- `ctest --test-dir build -C Release` -> `100% tests passed out of 1`.

## Root-cause of the earlier G47 "failure"
The previous run failed because the model passed a **malformed config**
(`config:"{\"c++17\":true}"`) and omitted the test config, so `run_tests`
defaulted to `-C Debug` (ctest exit 8) and `run_build` mis-configured (exit 1).
With correct args (`config:"Release"` for both build and tests) the same tools
succeed. **This was a model-argument error, not a build/test tool defect.**

Tool schema notes (for future runs):
- `run_build`: `config` default `Release`; `dir` workspace-relative.
- `run_tests`: `config` default **`Debug`** (mismatch risk for Release builds) —
  callers must pass `config:"Release"` explicitly.

## Ledger
```
G47=PASS
REMAINING=72
```