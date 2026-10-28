# WIN32IDE_STUB_GATE_003_FOLLOWUP_001 — OPEN disposition matrix

```
PROMOTE=0
TIP_CLIMB=HOLD
CERTIFIED=0
PERFECT=0
NO_INVENT_PASS=1
REBUILD_TIP=0
WORKSPACE=G:\~dev\rawrxd
ASOF_UTC=2026-10-28T17:26:10Z
TIP_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
ABSORB_GHOSTTEXT_B421=NOT_AUTHORIZED
PARENT=WIN32IDE_STUB_GATE_003
```

| ID | Surface | Tip 748B? | Disposition | Honest seal |
|----|---------|-----------|-------------|-------------|
| O01 | HandleUpdateSignature / HandlePluginSignature | YES (handlers + update_signature.cpp + plugin_signature.cpp linked; tip strings WinVerifyTrust/Authenticode) | **REAL_WINVERIFYTRUST** (not theater) | Tip Authenticode Status=**NotSigned** → ok path does **not** fire; verify fails closed. Handler command RUNTIME exercise = **NOT_RUN** this seal. ok≠update/plugin product beyond Authenticode of current module. |
| O02 | HandleChatPanel GUI create | YES (chat_panel.cpp + string "Chat panel initialized") | **HWND_CREATE_REAL** | `ChatPanel::create` = CreateWindowExW container/RichEdit/input/send. **≠ tip chat owner certify**. Headless already FEATURE_FICTION fail-close (003). |
| O03 | HandleConsentPrompt GUI MessageBox | YES (string "Consent prompt") | **MESSAGEBOX_RECEIPT_REAL** | MessageBoxA YES/NO is a real UI receipt. **≠ product consent-policy certify**. Headless FEATURE_FICTION fail-close (003). |
| O04 | ConPTY RUNTIME_REACHED on tip 748B | YES symbols (CreatePseudoConsole + GateConPty in tip; BIN_CONPTY=1) | **FAIL_CLOSED / NOT_RUN** | Cite `CONPTY_STREAM_OWNER_RUNTIME_748B_001` SUMMARY: `RUNTIME_REACHED=0` `RUNTIME_PASS=0` `PS_CHILD=0` `CONPTY_WITNESS=0` `PHASE5_RUNTIME=0`. Tip **not** overwritten. `RELINK_CLOSED=1` = symbols already in tip ≠ RUNTIME PASS. HWND product ConPTY still NOT_RUN; candidate wire only in separate freeze. |
| O05 | ApplyLoRA product wire | NO (tip strings ApplyLoRA=0 LoRAKernel=0) | **INVENTORY_ONLY** | ASM tree: `src/lora/ApplyLoRA_*.asm`, `src/fusion/kernels/ApplyLoRA*.asm`. Bridge TU CMake **GATED_OMIT** (CMakeLists 5721–5725). `LoRAKernelBridge::initialize` returns false GateStub. No SOURCE_WIRE / no tip clobber this seal. |

## Tip string witness (ASCII scan tip EXE)

```
WinVerifyTrust=1
Authenticode signature=1
Update signature verification=1
Plugin signature=1
Chat panel initialized=1
Consent prompt=1
CreatePseudoConsole=1
GateConPty=1
ApplyLoRA=0
LoRAKernel=0
GATED_STUB=1
FEATURE_FICTION=1
```

## Explicit non-claims

```
SOURCE_WIRED != RUNTIME_REACHED
NOT_RUN != PASS
PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
HWND_CREATE != CHAT_CERTIFY
MESSAGEBOX != CONSENT_POLICY_CERTIFY
BIN_CONPTY != HWND_CONPTY_E2E
RELINK_CLOSED(symbols) != RUNTIME_PASS
ApplyLoRA ASM on disk != PRODUCT_WIRED
```
