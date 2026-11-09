# Diagnostic requirements

Before any further runtime test, capture:

1. Exact top-level and leaf menu text, numeric command ID, menu HWND, and `WM_INITMENU`/`WM_INITMENUPOPUP` timing.
2. Existing breadcrumbs from `WM_COMMAND_ENTER` through handler entry/exit and `WM_COMMAND_EXIT_OK`.
3. For a non-responsive state, UI-thread ID, stack, wait chain, lock owner, process liveness, and bounded hang dump.
4. If extension routing is reached, route path, child `CreateProcessA` attempt, immediate launch error, child PID/hash, ready-event result, and IPC evidence.
5. For shutdown, `WM_CLOSE_ENTER`, each `WM_DESTROY_*`, `WM_NCDESTROY_*`, `onDestroy_*`, exit code, and whether cleanup was graceful or forced.

No production instrumentation is justified solely by this read-only inspection; the candidate already contains relevant command and teardown breadcrumbs.
