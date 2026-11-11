# RESOLVE_CALLBACK_CALL_TARGETS

ASOF_UTC=2026-11-03T13:05:00Z
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

## Controlling return

```
CALL_TARGETS=RESOLVED_STATIC
MESSAGE_PUMP_API=GetMessageA+IsDialogMessageA+TranslateMessage+DispatchMessageA
SHARED_APP_FRAMES=YES (+0x12FB9C, +0x33F9)
FUNC_26C0_IDENTITY=WinMain (see FUNC_26C0_CALLSITE_ANALYSIS.md)
INSN_BEFORE_+0x33F9=call_0x12FB80
WNDPROC_APPLICATION_OWNED=NOT_PROVEN
LIFETIME_HWND=NOT_PROVEN
APPLICATION_CAUSATION=NOT_PROVEN
PRODUCT_DEFECT=NOT_PROVEN
NATIVE_STACK=PARTIAL
SAME_PATH=YES
REBUILD=HELD
PROMOTE=0
NEXT_GATE=DISPATCH_PATH_WNDPROC_OR_NARROW_CANCEL_MATRIX
```

## Method

- CERT EXE only (SHA 3B720981…). No rebuild. No sealed CW/Token64/GhostText reopen.
- Prior offline dumps + `stack_parse_073409.txt` / `stack_parse_070906.txt`.
- Static: llvm-objdump of `.text` ranges + `.pdata` function bounds + USER32 IAT slot index math against `dumpbin /IMPORTS` (`logs\imports_iat_snippet.txt`).
- PDB/MAP: absent beside cert bin / known sibling bins. No debugger install this gate.

## 1) Indirect call targets — loop `FUNC_RVA_0x12FB80` (contains RET `+0x12FB9C`)

`.pdata`: `[0x12FB80 .. 0x12FBDD)` size 93.

USER32 Import Address Table base RVA `0x491AA0` (from dumpbin). Slot → name:

| Loop site | IAT RVA | Index `(iat-0x491AA0)/8` | Import name | Role in loop |
|-----------|---------|--------------------------|-------------|--------------|
| `call [rip]` @ `0x12FB96` (RET lands `0x12FB9C`) | `0x491CB8` | 67 | **GetMessageA** | `GetMessageA(&msg, NULL, 0, 0)` — rcx=&local MSG; rdx/r8/r9 zeroed |
| `call [rip]` @ `0x12FBB1` | `0x491C70` | 58 | **IsDialogMessageA** | `IsDialogMessageA(hwnd, &msg)` — hwnd from `[obj+0x568]` |
| `call [rip]` @ `0x12FBC0` | `0x491CC0` | 68 | **TranslateMessage** | `TranslateMessage(&msg)` |
| `call [rip]` @ `0x12FBCB` | `0x491CC8` | 69 | **DispatchMessageA** | `DispatchMessageA(&msg)` |

Control flow (static):

```
loop:
  eax = GetMessageA(&msg, 0, 0, 0)
  if (eax <= 0) return msg.wParam-ish
  if (!IsDialogMessageA(*(HWND*)(obj+0x568), &msg)) {
    TranslateMessage(&msg)
    DispatchMessageA(&msg)
  }
  goto loop
```

No vtable indirection in this function — all four targets are **import thunks** (IAT). Not a product WndProc body.

## 2) Other product code RVAs (section + pdata)

| RVA | Section | `.pdata` function | Notes |
|-----|---------|-------------------|-------|
| `+0x12FB9C` | `.text` | `0x12FB80..0x12FBDD` | Instruction **after** `GetMessageA` — message-pump frame |
| `+0x33F9` | `.text` | `0x26C0..0x3763` (4259 B) | RET after `call 0x12FB80`; function = **WinMain** (PROVEN — `FUNC_26C0_CALLSITE_ANALYSIS.md`) |
| `+0x1365D4` | `.text` | `0x136580..0x1365D9` | Wrapper RET after `call 0x136510`; multi-arg forwarder (loads stack args beyond 4 regs) — **not proven WndProc** |
| `+0x583420` / `+0x583600` | `.data` | n/a | **NOT_CODE** — stack-scan false positives |
| `+0x492FC8` / `+0x49B2B0` / `+0x49B908` | `.rdata` | n/a | **NOT_CODE** — stack-scan false positives |

Wrapper `0x136580` → direct relative call **`0x136510`** (same module). Target name: **NOT_PROVEN** (no PDB). Signature shape ≠ classic 4-arg WndProc proof.

## 3) Dump connection (both Cancel dumps)

Authority scans: `CANCEL\logs\stack_parse_073409.txt`, `stack_parse_070906.txt`.

| Frame | 073409 (single BM) | 070906 (triple) | Same rsp class |
|-------|--------------------|-----------------|----------------|
| `+0x12FB9C` (after GetMessageA) | YES `[19]` rsp+0x480 | YES `[22]` rsp+0x480 | **YES** |
| `+0x33F9` (`FUNC_RVA_0x26C0`) | YES `[20]` rsp+0x4E0 | YES `[23]` rsp+0x4E0 | **YES** |
| `+0x1365D4` (wrapper) | **NO** | YES `[6]` rsp+0xA0 (nearer fault) | 070906-only |
| `.data`/`.rdata` hits | present | present | ignore (not code) |

Near-fault chain (both): `comctl32+0xBD02` ← comctl32/user32/ntdll … then product message-pump / outer frame. **SAME_PATH=YES** at message-dispatch class.

**Shared application-level frames (both dumps): `+0x12FB9C` and `+0x33F9`.**

## 4) Application-owned window procedure?

```
WNDPROC_APPLICATION_OWNED=NOT_PROVEN
```

Evidence for dispatch path: **YES** — static pump ends in `DispatchMessageA` / `IsDialogMessageA` (can also dispatch dialog msgs).

Evidence that the faulting callback is a **product-registered** WndProc/subclass: **NO**

- 073409: no product `.text` RVA between comctl32/user32 near-RSP chain and `+0x12FB9C`.
- Product frames proven on stack are the **pump** and its **caller** (`FUNC_RVA_0x26C0`), i.e. above dispatch — not a named ChatWindow/Cancel WndProc.
- `+0x1365D4` (070906-only) is a multi-arg forwarder candidate, not statically proven as WndProc.
- HWND at `obj+0x568` used by `IsDialogMessageA` — field offset observed; **ownership/lifetime NOT_PROVEN** (no HWND value, no destroy ordering).

Do **not** claim UAF / reentrancy / invalid-HWND from this gate.

## 5) Classification (fail-closed)

| Claim | Status |
|-------|--------|
| `0x12FB80` call targets named | **PROVEN** (GetMessageA / IsDialogMessageA / TranslateMessage / DispatchMessageA) |
| Shared app frames both dumps | **YES** (`+0x12FB9C`, `+0x33F9`) |
| Message-dispatch path | **IDENTIFIED** |
| Application-owned WndProc named | **NOT_PROVEN** |
| HWND/lifetime defect | **NOT_PROVEN** |
| APPLICATION_CAUSATION | **NOT_PROVEN** |
| PRODUCT_DEFECT (rebuild-authorizing) | **NOT_PROVEN** |

```
PRODUCT_DEFECT=NOT_PROVEN
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
```

## NEXT_ACTION

1. Prefer dispatch-path WndProc / forwarder analysis (`+0x1365D4` / lifecycle WindowProc) — WinMain is loop owner only, **not** WndProc.
2. Else same-SHA narrow Cancel matrix (no source change): Cancel no-Clear; WM_SETTEXT-only vs dual SetEdit — crash Y/N.
3. Authorize rebuild only after named defective product callback + deterministic fix spec + `REBUILD_AUTHORIZED=1` receipt.

Sealed ChatWindow / Token64 / GhostText remain closed.

Superseding detail: `CANCEL\FUNC_26C0_CALLSITE_ANALYSIS.md`
`DISPOSITION=FUNC_26C0_IDENTIFIED_WINMAIN_NO_PRODUCT_DEFECT`
