# Command dispatch trace

## Observed

The runtime action was a top-level `Commands` menu interaction. No leaf command ID, WM_COMMAND record, command breadcrumb, stack, or wait-chain record was captured. Therefore the last observed runtime marker is the initial UI/accessibility state, not a dispatch marker.

## Static path

The compiled candidate source provides this expected path:

`Win32IDE::WindowProc` — `src/win32app/Win32IDE_Core.cpp:206-230` — resolves the instance from `GWLP_USERDATA` and receives window messages.

`sehCallOnCommand` — `src/win32app/Win32IDE_Core.cpp:610-622` — emits `WM_COMMAND_ENTER`, synchronously calls `onCommand`, and emits either `WM_COMMAND_EXIT_OK` or `WM_COMMAND_SEH_SWALLOWED`.

`Win32IDE::onCommand` — `src/win32app/Win32IDE_Core.cpp:5250-5268` — emits `onCommand_ENTER`, handles control notifications, and continues command routing.

`Win32IDE::routeCommand` — `src/win32app/Win32IDE_Commands.cpp:415-469` and subsequent range handlers — synchronously selects the command handler by ID range.

The fallback near `src/win32app/Win32IDE_Commands.cpp:11693-11705` calls `routeCommandUnified` when legacy routing does not handle the ID.

Existing diagnostic markers include `WM_COMMAND_ENTER`, `onCommand_ENTER`, `onCommand_BEFORE_routeCommand`, `onCommand_AFTER_routeCommand_OK`, `onCommand_routeCommand_MISS`, `onCommand_BEFORE_unified`, `onCommand_AFTER_unified_OK`, `onCommand_unified_MISS`, and `WM_COMMAND_EXIT_OK` (`Win32IDE_Core.cpp:610-622`, `5250+`, and approximately `5838-5878`). None was captured in the prior runtime evidence.

Conclusion: the source trace is established; the actual runtime dispatch boundary is unobserved.
