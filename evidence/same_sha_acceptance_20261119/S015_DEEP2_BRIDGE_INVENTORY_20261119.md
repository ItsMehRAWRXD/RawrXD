# S015 native Deep2 bridge inventory

Source inspection identified the production bridge and route:

- `src/win32app/Win32IDE_Deep2Bridge.cpp` owns initialization, model loading,
  streaming generation, cancellation, and the `[BRIDGE_STREAM]` witness.
- `src/win32app/Win32IDE.cpp` selects this bridge for
  `RAWRXD_CHAT_BACKEND=deep2` and calls `GenerateStream`.
- `src/win32app/Win32IDE_AgentCommands.cpp` constructs and initializes the
  bridge, honoring the configured model path.
- `Deep2::Deep2Engine::generateStream` is the native generation entry point.

The bridge enables Vulkan by default unless `RAWRXD_BRIDGE_DISABLE_VULKAN=1`,
but source presence does not prove a GUI request reaches the worker or produces
GPU work. Fresh GUI generation and request-attributed dispatch evidence remain
required.

```ini
S015=SOURCE_INVENTORY_COMPLETE
BRIDGE_SOURCE=PRESENT
DEEP2_GENERATION_ENTRY=PRESENT
GUI_RUNTIME_REACHED=UNVERIFIED
GPU_WITNESS=UNVERIFIED
ACCEPTANCE=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
