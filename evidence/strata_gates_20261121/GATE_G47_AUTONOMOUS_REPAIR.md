# Gate G47 — Autonomous edit/build/test/repair => PASS

## Runtime evidence (2026-11-21)
Sandbox: `--root F:\rawrxd\evidence\strata_gates_20261121\g47_fixture`
(11 tools; edits/execute allowed; mode=code; backend=ollama, llama3.2:3b).

Fixture (failing): `int main() { return 1; }` -> ctest `0% tests passed`.

Autonomous run (turns=6, tool_calls=5, denied=0):
```
[ok] edit_files {"new":"return 0;","old":"return 1;","path":"main.cpp"}
[ok] run_build  {"config":"Release","dir":"."}
[ok] run_tests  {"config":"Release","dir":"."}
exit=0  (agent produced FINAL answer at turn 6)
```

## Independent verification (not model-reported)
- `main.cpp` after: `int main() { return 0; }`
- `ctest --test-dir build -C Release` -> `100% tests passed out of 1`.

## Root cause of the earlier G47 failure (fixed)
The first attempt failed because the model passed a malformed `config`
(`"{\"c++17\":true}"`) and omitted the test config, so `run_tests` defaulted to
`-C Debug` (ctest exit 8). With explicit `config:"Release"` on both `run_build`
and `run_tests`, the same tools converge. This was a model-argument error, not a
build/test tool defect.

## Note
The model also emitted an irrelevant `write_file` with `action:"git add"`; it
failed harmlessly and did not affect convergence. The core edit→build→test loop
and the acceptance evaluator (G48) both behaved correctly.

## Ledger
```
G47=PASS
```