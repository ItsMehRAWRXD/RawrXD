# Shared linkage restored + G54 re-verified (2026-11-21)

## Shared build: RESTORED
Both targets now link from the current tree:
- `RawrXD-CLI-V2.vcxproj -> F:\rawrxd\build\bin-msvc\Release\rawr.exe` (6:41:34 PM)
- `RawrXD-Win32IDE-Native.vcxproj -> F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe` (6:42:06 PM)

The `RawrXD::Deep2::QuantDot::WeightCacheRetention()` unresolved symbol is
resolved (quant_dot_dispatch linked into rawrxd_gpu_compute, `2ab93fa30e`).
No stub was introduced; no Deep2 source was edited by this agent.

## G54 re-verified on the fresh binary
```
SEEDED: window x=123 y=77 width=900 height=640
RESTORED_RECT=(123,77,1023,717)   => (123,77) 900x640
G54_SEED_RESTORE=PASS
```
Combined with the earlier maximized-restore PASS, G54 geometry persistence is
verified (position + size + maximized).

## Ledger
```
SHARED_LINK=PASS
CLI_BUILD=PASS
IDE_BUILD=PASS
G54=PASS (seed restore exact on fresh build)
```