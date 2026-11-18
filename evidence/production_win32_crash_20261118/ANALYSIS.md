# Production Win32 crash analysis

```ini
EXECUTABLE_SHA256=5B9C60898E7E23AE7805BF247A840A0258D1DA351777535BF780BAD51C57A8FC
MINIDUMP_SHA256=79139C6DDBEC75066874F7453E4740D75DF7762E4C53B772CD595FAEFAC49357
STACK_LOG_SHA256=B2529A5A45B648DD6D00F86D223ADDF17AC742FFDE401D7BFD581218471E8AE6
LATEST_EXECUTABLE_SHA256=A48B07731E2D4A3B836E002B5EEE287731DD2B64AB5E4455B8E3F57315086E81
```

The captured handler log records an underlying `0xC0000005` read access violation on the GUI thread. The reported `0xC000041D` is the secondary unhandled-callback status. The fault context is now explicit: `RIP=0x7FFEE729BD02`, `access=1` (read), `address=0xD93158E3E0`, and `RCX=0xD93158E3E0`. The stack passes through `DrawStatusTextW`/`CallWindowProcW` while processing the GUI message loop. This identifies corrupted or stale status-bar control state as the immediate fault boundary; it does not yet prove which RawrXD write corrupted that state.

The matching PDB is not present, so the offset cannot be mapped to a C++ source line yet. This is sufficient to reject the earlier assumption that the crash was proven to be model-selection reentrancy, but not sufficient to justify a source fix.

```ini
FIRST_FAULT_CAPTURED=PASS
SOURCE_FUNCTION_SYMBOLIZATION=PARTIAL_SYSTEM_STACK
ROOT_CAUSE=STATUS_BAR_STATE_CORRUPTION_SOURCE_UNKNOWN
PRODUCTION_WIN32_E2E=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
