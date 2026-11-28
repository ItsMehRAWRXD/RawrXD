# Package 4 (crash diagnostic) — mechanism smoke receipt (2026-11-28)

WORKPACKAGES Package 4 specifies the crash filter (minidump + `IDE_CRASH.log` witness +
`exception_stack.txt`). Verified the crash-capture MECHANISM works on this platform using the
same dbghelp primitives the IDE's `RawrxdCrashFilter` uses.

- Test: `tools/crash_filter_smoke.cpp` (installs `SetUnhandledExceptionFilter` → writes witness
  + `MiniDumpWriteDump`, then null-derefs).
- Build: `cl /std:c++17 /EHsc tools\crash_filter_smoke.cpp /Fe:bin\crash_filter_smoke.exe /link dbghelp.lib` => exit 0.

## Run (clean temp dir)
```
PROC_EXIT = -1073741819 (0xC0000005 ACCESS_VIOLATION — filter handled, no WER dialog)
crash_witness.txt (58 B):  IDE_CRASH code=0xC0000005 addr=00007FF7891311AF tid=5308
crash_smoke.dmp   (49528 B): valid minidump
WITNESS_EXISTS=True  DUMP_EXISTS=True
```

## Conclusion
The crash-capture mechanism (witness line with code/address/tid + minidump) is confirmed
functional on this platform. This is the same primitive set the IDE filter chains to.

## NOT established (need full env)
- The IDE's exact `RawrxdCrashFilter` → `rawrxdUnhandledException` wiring inside the packaged
  IDE (needs the full IDE build).
- Fault-with-no-PDB, EXCEPTION_BREAKPOINT continue-search, stack-overflow WER LocalDumps,
  terminating-path — require the full IDE + hardware.
- `CERTIFIED=0` — mechanism only; not a certification.

## State
IMPLEMENTED=1 BUILT=1 RUNTIME_REACHED=1 FUNCTIONALLY_VERIFIED=1 (witness+dump) COMMITTED=1 PUSHED=0