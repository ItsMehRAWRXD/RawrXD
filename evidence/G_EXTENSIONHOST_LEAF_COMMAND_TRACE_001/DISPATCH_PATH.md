# Dispatch path

Expected native menu path:

`Win32IDE::WindowProc` → `sehCallOnCommand` → `Win32IDE::onCommand` → `Win32IDE::routeCommand` → `routeCommandUnified` fallback. Source locations: `src/win32app/Win32IDE_Core.cpp:206-230`, `610-622`, `5250+`, and approximately `5838-5878`; `src/win32app/Win32IDE_Commands.cpp:415+` and `11693+`.

Extension-panel IDs are handled by `Win32IDE::handleExtensionCommand` in `src/win32app/Win32IDE_ExtensionsPanel.cpp:371-445` (and a separate candidate TU with the same method name exists in `Win32IDE_HandleExtensionCommand.cpp`). Those handlers operate on the extension list, file dialogs, and local state. They do not, from the inspected bodies, call `ProductExtensionRuntime::HandleRoute` or the host spawn routine.

`ProductExtensionRuntime::HandleRoute` is implemented in `src/win32app/ProductExtensionRuntime_Api.cpp:30-66`. Child creation and the five-second ready wait are in `ProductExtensionRuntime_Host.cpp:60-107`. A route-entry-to-host-launch edge from the Commands menu was not established.
