# RawrXD native IDE completion audit (2026-10-24)

This receipt records executable evidence from the isolated `build_win32_cert_x64`
tree. It does not promote untested UI, compiler, GPU, or language features.

## Batch A (15)

| Gate | Result | Evidence |
|---|---|---|
| Native Win32 target generated | PASS | CMake configure with `RAWRXD_BUILD_WIN32IDE=ON` |
| Compiler registry sources linked | PASS | `CompilerRegistry.cpp` and `CompilerIntegration_Real.cpp` in target |
| Compiler bridge API wired | PASS | menu, command, open/save callbacks compile |
| Unicode toolbar creation | PASS | explicit `ToolbarWindow32` class |
| Async compiler discovery | PASS | owned worker and `RAWRXD_WM_COMPILER_DETECTED` |
| Compiler shutdown ownership | PASS | worker joined during IDE shutdown |
| Build menu reuse | PASS | existing `&Build` submenu reused |
| CMake Release build | PASS | MSBuild target exit 0 |
| Executable produced | PASS | `RawrXD-Win32IDE.exe` emitted |
| Main window creation | PASS | bounded launch probe found product HWND |
| Window responsiveness at 5 s | PASS | `Process.Responding=True` |
| Single product shell | PASS | `P1_UI_WINDOW_OWNERSHIP_001` trace |
| Dock roots owned by main | PASS | explorer/editor/chat/output/terminal/status checks |
| Compiler ready trace | PASS | `compiler_integration_ready` observed in trace |
| Owned-process cleanup | PASS | probe stopped only its launched PID |

## Batch B (15)

| Gate | Result | Evidence / remaining work |
|---|---|---|
| Editor paint with document contents | PENDING | requires physical interaction and screenshot |
| Editor typing/caret | PENDING | requires GUI input test |
| File open/double-click | PENDING | runtime interaction receipt needed |
| Save/reload round-trip | PENDING | runtime interaction receipt needed |
| Problems-panel navigation | PENDING | runtime interaction receipt needed |
| PowerShell short command | PENDING | DS-02 runtime test |
| PowerShell high-volume output | PENDING | DS-03 runtime test |
| PowerShell timeout/stop | PENDING | DS-04/DS-05 runtime test |
| Debugger stepping | PENDING | DS-07/DS-08 runtime test |
| Native compiler C++20 build | PENDING | compiler command execution receipt |
| MASM frontend/link path | PENDING | source/toolchain matrix |
| Language frontend conformance | NOT_CERTIFIED | no broad conformance evidence |
| Deep2 GPU parity | NOT_CERTIFIED | separate runtime gate |
| GhostText E2E | NOT_CERTIFIED | model-backed completion not run |
| Full IDE certification | NOT_CERTIFIED | all runtime gates must pass |

## Physical launch follow-up

An independent UI launch was attempted against the same Release executable.
The process exposed a transient window titled `Building: Detecting system
compilers...` and then exited before a stable target window could be captured.
Therefore editor, PowerShell, debugger, GhostText, and native compiler UI gates
remain pending. The earlier bounded process probe remains valid only for window
creation/responsiveness during its measured interval.

## Runtime note

The screenshots showed a black editor and a later `Not Responding` surface. The
startup probe now reaches a responsive native window and the compiler-ready
marker. This narrows the remaining issue to editor paint/input or a later
interaction path; it is not evidence that those paths are complete.

## Build caveat

The existing target emits linker `/FORCE:MULTIPLE` and LNK4088 warnings. A
successful link is therefore recorded separately from runtime certification.

## Test discovery caveat

Running CTest in this isolated Win32 build tree found 51 registered tests but
none of their executables were built in that configuration (`Not Run`, exit 1).
This is recorded as unavailable test execution, not as a passing regression
matrix. The next build must explicitly build the required test targets before
using CTest as evidence.
