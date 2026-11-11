# Shutdown Scope

The repaired harness can request `CloseMainWindow()` only for its own process object, waits up to five seconds, and records forced cleanup if graceful exit does not complete. Because no isolated test process was started, no shutdown result is claimed here.
