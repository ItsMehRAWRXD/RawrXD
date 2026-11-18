# Production Win32 crash analysis

```ini
EXECUTABLE_SHA256=5B9C60898E7E23AE7805BF247A840A0258D1DA351777535BF780BAD51C57A8FC
MINIDUMP_SHA256=79139C6DDBEC75066874F7453E4740D75DF7762E4C53B772CD595FAEFAC49357
STACK_LOG_SHA256=B2529A5A45B648DD6D00F86D223ADDF17AC742FFDE401D7BFD581218471E8AE6
```

The captured handler log records an underlying `0xC0000005` access violation on the GUI thread. The reported `0xC000041D` is the secondary unhandled-callback status. The stack reaches the Windows message dispatch path and enters the RawrXD image at image-relative offset `0x16ADD7`, inside a compiler-generated string-buffer capacity operation.

The matching PDB is not present, so the offset cannot be mapped to a C++ source line yet. This is sufficient to reject the earlier assumption that the crash was proven to be model-selection reentrancy, but not sufficient to justify a source fix.

```ini
FIRST_FAULT_CAPTURED=PASS
SOURCE_FUNCTION_SYMBOLIZATION=BLOCKED_NO_MATCHING_PDB
ROOT_CAUSE=NOT_ESTABLISHED
PRODUCTION_WIN32_E2E=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
