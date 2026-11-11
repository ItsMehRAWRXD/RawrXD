# FUNC_26C0_CALLSITE_ANALYSIS

ASOF_UTC=2026-11-03T13:20:00Z
GITHUB_COMMIT=70fe7cdaf7
CERT_EXE=F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe
CERT_EXE_SHA=3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
CHATWINDOW_REOPEN=0
TOKEN64_REOPEN=0
GHOSTTEXT_REOPEN=0
PDB_MAP_BROAD_SEARCH=COMPLETED_NO_MATCH (prior; not repeated)
DEBUGGER_INSTALL=0

## Controlling return

```
FUNC_26C0_IDENTITY=WinMain
FUNC_26C0_IDENTITY_STATUS=PROVEN
INSN_BEFORE_+0x33F9=call 0x12FB80 (message pump / runMessageLoop body)
PARTICIPATION=WINDOW_CREATION_PLUS_MESSAGE_LOOP_OWNER
APP_WNDPROC=NOT_PROVEN
CANCEL_HANDLER=NOT_PROVEN
DIALOG_DISPATCH_BODY=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
COMCTL32_CALLBACK_LINK=STACK_NESTING_ONLY
REBUILD=HELD
PROMOTE=0
NEXT_GATE=DISPATCH_PATH_WNDPROC_OR_NARROW_CANCEL_MATRIX
```

## Method

- CERT EXE only (SHA 3B720981…). No rebuild. No sealed CW/Token64/GhostText reopen.
- Static: `llvm-objdump -d -M intel` of `.pdata` range `[0x26C0..0x3763)` + binary E8 scan of `.text` for callers of `0x26C0`.
- IAT names via prior `logs\imports_iat_snippet.txt` / `imports_full.txt` (USER32 + ucrt).
- Dump residual: `logs\stack_parse_073409.txt`, `stack_parse_070906.txt` (register/stack claims fail-closed).
- Optional source correlation (no rebuild): `src\win32app\main_win32.cpp`, `Win32IDE_lifecycle.cpp`.
- Artifacts: `logs\func_26c0_full_disasm.txt`, `func_26c0_around_33f9.txt`, `func_26c0_calls.txt`, `func_26c0_callers.txt`, `func_26c0_pre_pump.txt`.

## 1) Callers of `0x26C0`

`.text` E8 scan → **exactly one** caller:

| Site | Next RVA | Dest | Enclosing `.pdata` |
|------|----------|------|--------------------|
| `0x44DF71` | `0x44DF76` | `0x26C0` | `[0x44DE70..0x44DFE1)` (CRT startup) |

Call-site ABI (Intel):

```
lea  rcx, [rip-…]        ; → ImageBase 0x140000000 = hInstance
xor  edx, edx            ; hPrevInstance = NULL
mov  r8, rax             ; lpCmdLine (from CRT)
mov  r9d, ebx            ; nCmdShow
call 0x1400026C0         ; → FUNC_26C0
mov  ebx, eax            ; capture WinMain return
```

Matches `WinMain(HINSTANCE, HINSTANCE, LPSTR, int)` and MSVC `mainCRTStartup` → WinMain pattern. No other product E8 callers.

## 2) Instruction immediately preceding return address `+0x33F9`

```
1400033EC  lea  rcx, [rsp+0xBC0]          ; this / Win32IDE* object for pump
1400033F4  call 0x14012FB80               ; FUNC message pump (prior: GetMessageA/IsDialogMessageA/TranslateMessage/DispatchMessageA)
1400033F9  mov  dword ptr [rsp+0x48], eax ; ← RET address observed on dumps
```

**What returns to `+0x33F9`:** the direct relative call to message-pump `FUNC_RVA_0x12FB80` (`runMessageLoop` body). Stack pair `+0x12FB9C` (after `GetMessageA` inside pump) then `+0x33F9` (after pump returns to WinMain) is **statically explained**.

## 3) Callees / relationship to pump `0x12FB80`

`.pdata` for subject: `[0x26C0..0x3763)` size 4259 (unchanged).

Notable callees inside FUNC_26C0 (subset):

| Target | Role (static) |
|--------|----------------|
| `0x12FB80` | Message pump — **direct call @ `0x33F4`** |
| `0x12FB30` | Show helper: `ShowWindow(hwnd@obj+0x568, SW_SHOW=5)` + `UpdateWindow` (IAT `0x491D08` / `0x491B68`) |
| `0x12F7F0` | Early UI/common-controls init path (COMCTL32 IAT involvement) |
| IAT `0x4920E8` / `0x4920E0` | `__p___argc` / `__p___argv` (health-check branch) |
| IAT `0x491CB0` | `MessageBoxA` |
| IAT `0x491CA8` | `SendMessageA` (incl. `Msg=0x10` / `WM_CLOSE` on `--open` failure path) |
| Many `0x8F80` / `0xA590` / `0xF890`… | C++ string / logger / helper glue (not named without PDB) |

Control shape (static + strings):

```
WinMain:
  if (__argc >= 2 && argv[1] is --health-check*) → probe; return
  init logger / ProductionRuntime
  construct Win32IDE; createWindow; showWindow (→ 0x12FB30)
  optional --open → may SendMessageA(WM_CLOSE)
  log "Entering message loop"
  call 0x12FB80          ; blocks in GetMessageA/DispatchMessageA
  log "Message loop exited with code "
  shutdown; return
```

Literal `.rdata` hits used at pre-pump sites:

| RVA | String |
|-----|--------|
| `0x492918` | `--health-check` |
| `0x492BC8` | `Entering message loop` |
| `0x492BE0` / `0x492C08` | `WinMain` |
| `0x492BE8` | `Message loop exited with code ` |

## 4) Participation classification (fail-closed)

| Class | Status | Evidence |
|-------|--------|----------|
| Window creation / app entry (`WinMain`) | **PROVEN** | Sole CRT caller ABI + strings + call to show helper + create/init callees |
| Message-loop **owner** (calls pump) | **PROVEN** | `call 0x12FB80` @ `0x33F4`; dump RET `+0x33F9` |
| Dialog-dispatch **body** | **NOT** (this func) | Pump body is `0x12FB80`; FUNC_26C0 only invokes it |
| Cancel handling | **NOT_PROVEN** | No Cancel/BM_CLICK/stop-button identity in this function |
| Application WndProc | **NOT_PROVEN** | Do **not** infer WndProc from message-processing chain ownership |
| Other | n/a | Health-check / MessageBox / WM_CLOSE-on-open-fail are peripheral paths |

```
PARTICIPATION=WINDOW_CREATION_PLUS_MESSAGE_LOOP_OWNER
APP_WNDPROC=NOT_PROVEN
```

## 5) Dump stack_parse ↔ comctl32 callback

Authority: `stack_parse_073409.txt`, `stack_parse_070906.txt`.

| Claim | Status |
|-------|--------|
| `+0x33F9` present both dumps @ rsp+0x4E0 | **YES** |
| `+0x12FB9C` present both @ rsp+0x480 (inner to `+0x33F9`) | **YES** |
| Static nest = WinMain → pump → GetMessageA → … → user32/comctl32 | **YES** (call graph) |
| Exception context registers (RCX/RDX/R8/R9/RBP) owned by FUNC_26C0 | **NOT_PROVEN** |
| FUNC_26C0 is the faulting comctl32 user callback | **NOT_PROVEN** (refuted by identity: outer WinMain frame) |

Exception RIP remains `comctl32.dll+0xBD02`. Product frames on the faulting thread are the **pump and its WinMain caller**, i.e. above dispatch — not a named Cancel/ChatWindow callback. 070906-only nearer product RET `+0x1365D4` is still **not** proven WndProc (prior gate).

```
COMCTL32_CALLBACK_LINK=STACK_NESTING_ONLY
```

## 6) Optional source correlation (no rebuild)

Strengthens identity only; does not authorize rebuild:

| Binary fact | Source |
|-------------|--------|
| `__argc`/`__argv` + `--health-check` | `main_win32.cpp` `WinMain` / `RunHealthCheckProbe` |
| Strings `Entering message loop` / `Message loop exited…` / `WinMain` | `main_win32.cpp` LOG_INFO lines |
| Pump API quartet | `Win32IDE::runMessageLoop` in `Win32IDE_lifecycle.cpp` |
| `ShowWindow`+`UpdateWindow` on `m_hwndMain` | `Win32IDE::showWindow` → matches helper `0x12FB30` + `obj+0x568` |

`SOURCE_CORRELATED=YES` for **WinMain / message-loop owner**. Still `APP_WNDPROC=NOT_PROVEN`.

## 7) Classification (fail-closed)

| Claim | Status |
|-------|--------|
| FUNC_26C0 = `WinMain` | **PROVEN** |
| Insn before `+0x33F9` = `call 0x12FB80` | **PROVEN** |
| Shared dump frames explained | **YES** |
| Application-owned WndProc named | **NOT_PROVEN** |
| Cancel-specific defective path | **NOT_PROVEN** |
| PRODUCT_DEFECT (rebuild-authorizing) | **NOT_PROVEN** |

```
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
```

## DISPOSITION

```
DISPOSITION=FUNC_26C0_IDENTIFIED_WINMAIN_NO_PRODUCT_DEFECT
FUNC_26C0_IDENTITY=WinMain
INSN_BEFORE_+0x33F9=call_0x12FB80
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
PROMOTE=0
```

Sealed ChatWindow / Token64 / GhostText remain closed.

## NEXT_ACTION

1. **Preferred:** analyze dispatch-path product callback candidates (e.g. `+0x1365D4` / `0x136510` forwarder, or lifecycle `WindowProc`) **without** treating WinMain as WndProc — still no auto-rebuild.
2. Else same-SHA narrow Cancel matrix (no source change): Cancel no-Clear; WM_SETTEXT-only vs dual SetEdit — crash Y/N.
3. Authorize rebuild only after named defective product callback + deterministic fix spec + `REBUILD_AUTHORIZED=1` receipt.

```
NEXT_GATE=DISPATCH_PATH_WNDPROC_OR_NARROW_CANCEL_MATRIX
```
