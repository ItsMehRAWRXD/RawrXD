# Batch 27 — Daily-use Save/Save As integrity

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Production Win32IDE source changes

- `a36d95e612612e3b84707239c2aee2779b51a3e1`: `Win32IDE::saveFile` now opens using a UTF-8-to-native filesystem path, checks write/flush/close, and fails closed if disk verification cannot reopen the file. Previously a failed flush/close could be misreported as success if an old file happened to hash correctly.
- `fc43c75f7aa6ec4bf1be37379d825092c2785384`: `Win32IDE::saveFileAs` now uses the Unicode common file dialog and explicitly converts the chosen path to UTF-8 instead of losing non-ANSI filename characters through `GetSaveFileNameA`.
- `92c43d8fd0e8e6b2d132eef3eba36e701dcd9d97`: fixed dialog buffer size constant without new include dependencies.

## Executed local smoke

Portable C++ source `tools/test_portable_save_roundtrip.cpp` was compiled and executed in a Linux container:

```
g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=undefined -fno-omit-frame-pointer /mnt/data/batch27_portable_save_smoke.cpp -o /mnt/data/batch27_portable_save_smoke
/mnt/data/batch27_portable_save_smoke
```

Result: `PORTABLE_FILESYSTEM_SMOKE=15/15`, exit 0. Covers new file, overwrite, empty file, multiline, embedded NUL, Unicode filename, missing parent rejection, exact disk readback. This is a standalone portable test of equivalent file I/O primitives, NOT the Win32IDE binary, Windows Unicode Save As dialog, or production `saveFile()`.

- `b59cd28bee36ee92f26fb01bb384133e77dce644`: portable source committed.
- `053056b510686bb3381a8248e355ce8d212fab67`: Linux CI compile/execute step committed; CI execution NOT verified.

## Remaining risk

Production save currently truncates destination before verified write; the new checks detect failure but cannot recover previous bytes after a partial write. Replacing this with a same-directory temporary file + atomic rename (with independent backup/recovery semantics) remains a high-priority daily-use reliability task. Windows path, long-path, ACL, sharing violation and GUI Save As still require native testing.

Production acceptance: NOT_RUN.
