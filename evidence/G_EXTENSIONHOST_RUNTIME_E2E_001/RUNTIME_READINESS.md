# Runtime readiness

Candidate runtime directory: `G:\~dev\rawrxd-ext-candidate-clean\build_ext_host_clean_001\bin`

- Candidate IDE SHA-256 verified as `3711804F318C8A81E154C7009E5AD77E7ABC8CF2536AC228CFB2510F854CE652`.
- Candidate ExtensionHost SHA-256 verified as `53078674DEF8127A802F34ECE71C94A2FEBE0291AA6250E17B8BD2D41C41D07B`.
- Both executables are present beside one another.
- No `RawrXD-Win32IDE` or `RawrXD-ExtensionHost` process was active before launch.
- Candidate source status contains only the previously authorized candidate changes; the primary tree is not in scope.
- Frozen authority hash remains `748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145`.
- Build-time tool `dumpbin.exe` was unavailable for dependency enumeration; this is recorded as an evidence limitation, not treated as a dependency PASS.

Bounded runtime plan: launch the exact candidate IDE, observe its returned window, allow a bounded initialization interval, inspect for normal runtime or fatal startup state, and clean up only candidate-owned processes. No F: native IDE process was active under the checked executable names.

`READINESS=CONDITIONAL_PASS`; dependency enumeration remains limited by unavailable `dumpbin.exe`.
