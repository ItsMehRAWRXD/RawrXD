# S017 — Native Deep2 bridge harness

Date: 2026-11-19  
Source SHA: `bcc6313836fa1c1828ab5a845967aab076e6603f`

## Finding

`tools/release/bridge_lifecycle_test.cpp` is a real bridge lifecycle test. It
constructs `Deep2Bridge`, calls `Initialize(argv[1])`, performs three
`GenerateStream` requests, waits for completion, and calls `Stop()`. It does
not use HTTP or Ollama.

## Build boundary

The source is not registered as a CMake target. The existing CMake project
registers `Win32IDE_Deep2Bridge.cpp` only as part of the full
`RawrXD-Win32IDE-Native` executable. A standalone harness therefore cannot be
claimed built from the current configuration without adding and resolving its
full Win32 bridge dependency graph.

The native IDE target was attempted during S016 and compiled the modified
bridge/lifecycle translation unit, but linking was blocked by the locked
existing executable:

```text
LNK1104: cannot open file
F:\rawrxd\build\bin\Release\RawrXD-Win32IDE-Native.exe
```

No standalone bridge executable or runtime result is claimed in this sprint.

## Disposition

```ini
BRIDGE_HARNESS_SOURCE=FOUND
HTTP_DEPENDENCY=NONE_IN_SOURCE
CMAKE_TARGET=MISSING
STANDALONE_BUILD=OPEN
RUNTIME=NOT_RUN
NEXT_OWNER=CMake target plus isolated bridge dependency link
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
