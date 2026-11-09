# ExtensionHost reachability

`EXTENSIONHOST_REACHED=0` (not observed).

No child process, child PID, `CreateProcessA` event, ready-event signal, IPC request/response, or ExtensionHost executable hash was captured in the prior runtime evidence.

Static source shows the intended runtime route, but it is conditional on an extension command. `Win32IDE_HandleExtensionCommand.cpp:5-113` maps extension IDs such as 11810-11814 and 6052-6057 to extension operations. `ProductExtensionRuntime_Api.cpp:30-67` dispatches HTTP-style runtime paths, while `ProductExtensionRuntime_Host.cpp:60-107` owns child creation and readiness. The recorded top-level `Commands` menu click cannot be mapped to any of those routes without its leaf command ID and runtime breadcrumbs.

Therefore the hang cannot presently be assigned to process creation, handshake, IPC, or shutdown.
