# Thread and wait analysis

The affected UI was `HWND=6687086` in candidate PID 24408. The process was initially responsive and later reported `Responding=False`; the desktop window listing subsequently showed `Not Responding`. The process later exited. No UI thread ID, thread stack, CPU sample, wait chain, exception record, dump, or exit code was captured.

The command path is synchronous by construction: `sehCallOnCommand` calls `onCommand` directly (`src/win32app/Win32IDE_Core.cpp:610-622`), and `onCommand` invokes routing/handlers on the UI call path (`Win32IDE_Core.cpp:5250+`). This permits a deadlock, long synchronous operation, or message-pump starvation, but does not identify which one.

The ExtensionHost launch path is also synchronous after routing: `ProductExtensionRuntime_Host.cpp:60-107` constructs the command line, calls `CreateProcessA`, and waits up to 5000 ms for the ready event. Shutdown waits up to 2000 ms before termination (`ProductExtensionRuntime_Host.cpp:24-36`). No evidence shows that this code was reached during the observed interaction.

Classification: deadlock vs. long operation vs. crash vs. harness timeout is `UNRESOLVED`. The available evidence establishes only UI non-responsiveness followed by process exit.
