# T071–T085 — backend, context, terminal, build, and debugger audit

## Authority

```ini
CLI=F:\rawrxd\build_repair_candidate\bin-msvc\rawr.exe
CLI_SHA256=706D52A24E4A688DFA0A74C20404CD49B8990AEB21815F830296D6C52FCB5847
IDE=F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe
IDE_SHA256=884D8FBC81C9960E2DB8EC9D88F7E7C29CDECA596F5960D9C5D5FEB7296704AE
PROMOTE=0
CERTIFIED=0
```

## Physical probes

### T071 — backend routing

Ollama was selected explicitly with `--backend ollama`, and the real product
receipt reported `source=ollama`, `prompt_eval_count=1113`, `eval_count=7`,
`phase=COMPLETED`, `finished=PASS`, and the requested marker
`ROUTE_T071_PASS`. This proves the Ollama route for this probe.

The explicit Deep2 probe resolved the model, opened two GPUs, reported
`DEEP2_EXEC_PATH=DUAL_SOVEREIGN` and `DEEP2_MULTI_GPU_PLAN=ACTIVE`, but did not
produce a completion receipt within the bounded observation window. The
diagnostic process was terminated and no orphan remained.

```ini
OLLAMA_ROUTE=PASS
DEEP2_PLAN=OBSERVED
DEEP2_TOKEN_COMPLETION=NOT_VERIFIED
T071=PARTIAL
```

### T073 — context overflow/truncation

The real CLI was given a 12,000-character prompt with `--context 512` and
`--max-tokens 8`. It returned `OVERFLOW_T073_PASS`, `eval_count=8`,
`finished=PASS`, and exit code 0. This demonstrates bounded handling for this
CLI/Ollama probe; it does not certify the Win32 IDE's full context assembly.

```ini
CLI_CONTEXT=512
PROMPT_BYTES=12022
OVERFLOW_PROBE=PASS
EXIT_CODE=0
T073=PASS_FOR_CLI_PROBE
```

### T076 — interactive terminal I/O

The real `rawr.exe tools run Shell --mode code --json` path executed a native
`cmd /c` command. The structured receipt reported `ok=true`, `exit_code=0`,
`duration_ms=40`, and both `T076_STDOUT` and `T076_STDERR` in the returned
output.

```ini
TOOL=Shell
MODE=code
REQUEST_ID=rawr-tools-107151420102300
OK=true
EXIT_CODE=0
STDOUT=PASS
STDERR=PASS
T076=PASS_FOR_SHELL_PROBE
```

The same candidate's embedded PowerShell console was also opened through the
native Terminal menu. A command was entered into the native terminal edit
control and executed by the native Execute button, producing the CTest output
shown below. This is physical IDE-terminal evidence, not a direct shell
substitution.

### T079 — CTest integration

```ini
IDE_TERMINAL=PowerShell
COMMAND=ctest --test-dir F:\rawrxd\build_repair_candidate -C Release --output-on-failure
TESTS_TOTAL=28
TESTS_PASSED=27
TESTS_SKIPPED=1
TESTS_FAILED=0
DISPLAYED_RESULT=100% tests passed out of 28
IDE_BINARY_SHA_AFTER=884D8FBC81C9960E2DB8EC9D88F7E7C29CDECA596F5960D9C5D5FEB7296704AE
IDE_BINARY_SIZE_AFTER=6106624
T079=PASS_FOR_NATIVE_IDE_TERMINAL
```

## Gate dispositions

```ini
T071=PARTIAL_DEEP2_COMPLETION_MISSING
T072=NOT_VERIFIED_FULL_IDE_CONTEXT_ASSEMBLY
T073=PASS_CLI_BOUNDED_PROBE
T074=PASS_BEHAVIORAL_SEE_T074_CHAT_SESSION_RESTORE_20261104
T075=NOT_VERIFIED_CURRENT_IDE_CANCEL_RECOVERY
T076=PASS_SHELL_PROBE
T077=NOT_VERIFIED_POWERSHELL_CMD_CANCEL_CLEANUP
T078=NOT_VERIFIED_NATIVE_IDE_BUILD_COMMAND
T079=PASS_NATIVE_IDE_TERMINAL_CTEST
T080=NOT_IMPLEMENTED_PRODUCTION_DIAGNOSTIC_NAVIGATION
T081=NOT_IMPLEMENTED_REAL_TARGET_ATTACH
T082=NOT_IMPLEMENTED_REAL_BREAKPOINT_STOP
T083=NOT_IMPLEMENTED_REAL_STEPPING
T084=NOT_IMPLEMENTED_REAL_STACK_VARIABLE_EVALUATION
T085=NOT_VERIFIED_DEBUGGER_CRASH_CLEANUP
```

Source inspection found simulated debugger behavior in
`src/win32app/Win32IDE_Debugger.cpp`, including expression evaluation that
returns the literal placeholder `<value>`. Those gates remain open and are
not promoted by UI state alone.

## Host diagnostics

The current CLI candidate's real `doctor` command completed with exit code 0:
Ollama was available, 44 models were reported, Git and CMake were found, the
workspace was writable, and 478 GB of free disk was reported. Deep2 was not
running during this probe.

The real `self-audit` command completed with exit code 1: 4 checks passed and
7 checks failed. The failed checks were bounded source-edit execution,
compiler/build exit, relevant automated tests, source-diff capture, commit or
safe staging, ledger persistence, and normal zero exit. This is diagnostic
evidence, not a certification pass; the dirty multi-worktree state must be
resolved by a controlled candidate workflow before those checks can close.

```ini
DOCTOR_EXIT=0
OLLAMA=AVAILABLE
OLLAMA_MODELS=44
DEEP2=NOT_RUNNING
SELF_AUDIT_PASS=4
SELF_AUDIT_FAIL=7
SELF_AUDIT_EXIT=1
```
