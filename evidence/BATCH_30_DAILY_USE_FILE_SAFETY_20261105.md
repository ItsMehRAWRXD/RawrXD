# Batch 30 — Daily-use file safety and scoped acceptance (2026-11-05)

Branch: `fix/deep2-multimodel-safety-20261025`
PROMOTE=0
CERTIFIED=0

## Source changes

- `src/win32app/Win32IDE_FileOps.cpp`: include dirty unregistered active editor as "Untitled (active editor)" in the close confirmation. Commit `4dfe50fe35fe2da0f1b4ad127670a0862fb3d88f`.
- `.github/workflows/agent-registry-portable.yml`: push and pull request path filters now include `src/win32app/Win32IDE.cpp` and `src/win32app/Win32IDE_FileOps.cpp`, so portable tests are triggered by native file-save changes. Commit `e9eb6080a6a8625226d241c9d98d0632ecd5dd12`.

## Local tests ACTUALLY executed

```sh
g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=undefined -fno-omit-frame-pointer /mnt/data/batch28_atomic_save_simulation.cpp -o /mnt/data/batch30_atomic_save_smoke
/mnt/data/batch30_atomic_save_smoke
# exit 0, 15/15 PASS

g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=undefined -fno-omit-frame-pointer /mnt/data/batch27_portable_save_smoke.cpp -o /mnt/data/batch30_portable_save_smoke
/mnt/data/batch30_portable_save_smoke
# exit 0, 15/15 PASS
```

These are two *standalone portable C++ harnesses* with actual temporary-file writes/readbacks, **not** linked production Win32IDE code. Their PASS cannot be promoted to native Save, Save As, GUI, or full IDE certification. Logs are local conversation artifacts at `/mnt/data/batch30_atomic_save_smoke.log` and `/mnt/data/batch30_portable_save_smoke.log`.

## Unverified high-priority production gates

1. MSVC build and launch; 2. New/Edit/Save As/Reopen; 3. Save As cancellation; 4. Save All across tabs; 5. failed Save All blocks close; 6. UTF-8 roundtrip; 7. restart/tab restoration; 8. crash recovery; 9. external file changes; 10. Build/Run/Clean; 11. local model inference; 12. model tool dispatch; 13. production editFiles disk readback; 14. cancel and soak; 15. independent package verification.

The workflow change only schedules portable regression tests. No GitHub Actions success receipt or Windows native binary test is established here.
