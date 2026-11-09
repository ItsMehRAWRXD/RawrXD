# Command reachability

The generic top-level `Commands` catalog was not proven to invoke the runtime entrypoint.

The extension sidebar has a separate control path. `IDC_EXT_INSTALL` (the visible Activate button) calls `activateExtension`; list double-click also calls it. The sidebar’s Enable and Disable controls call `enableExtension` and `disableExtension`, which persist ProductExtensionRuntime state but do not themselves call `SpawnHostUnlocked` in the inspected bodies.

The legacy IDs `11810-11814` are handled through `handleExtensionCommand` and chat quick-action dispatch (`Win32IDE_Commands.cpp:5931-5962`). Those handlers are not the proven runtime spawn route. The correct future physical test action is the Extensions sidebar Activate button or list double-click on a scanned, enabled extension.

Static classification:

- Sidebar Activate/double-click: `REACHABLE_STATIC`, conditional on selected extension and enabled runtime record.
- Sidebar Enable/Disable: `CONDITIONAL`, state mutation only; host launch not established.
- Generic Commands menu: `UNKNOWN` for ExtensionHost; no complete call edge found.
- Local HTTP `/api/extensions`: `REACHABLE_STATIC`, server/client preconditions required.
- `extension.activate` tool: `REACHABLE_STATIC`, server/tool dispatch preconditions required.
