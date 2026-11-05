# Batch 28 — Atomic Save safety

Date: 2026-11-05
PROMOTE=0
CERTIFIED=0

## Production source fix

`src/win32app/Win32IDE.cpp` `Win32IDE::saveFile` previously opened the destination with `std::ios::trunc` before writing. Failure could destroy the prior content even when the function returned false.

Commit `9ca7272a4e2211efbbce4a310315ba9a2c1babb1` stages bytes using `GetTempFileNameW` in the same directory, checks write/flush/close, reads back and compares SHA-256, and only then replaces the destination via `MoveFileExW(MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)`. RAII removes the staging file on failure.

## Executed acceptance scope

`g++ -std=c++20 -Wall -Wextra -Werror -fsanitize=undefined -fno-omit-frame-pointer /mnt/data/batch28_atomic_save_simulation.cpp -o /mnt/data/batch28_atomic_save_simulation && /mnt/data/batch28_atomic_save_simulation`

Result: `COMPILE_EXIT=0`, `RUN_EXIT=0`, `PORTABLE_ATOMIC_SAVE_SIMULATION=15/15`. Includes four injected failures with byte-for-byte original-file preservation, successful replacement, binary roundtrip and missing-directory failure.

**This C++ harness is a portable behavioral simulation using `std::filesystem::rename`; it does not link the Win32IDE implementation and does not execute `MoveFileExW`. Do not call the native Save gate PASS.**

## Native acceptance still required

- Windows/MSVC build and link of the modified source.
- Physical Save and Save As with ASCII, Unicode filenames and content, empty/binary fixtures, overwrite, sharing violations, write failures and destination ACL failures.
- Test preservation of existing destination on staging and replacement failure.
- Long-path (>MAX_PATH) and external-change conflict behavior.
- Multi-tab Save All and close/cancel.
- Session recovery, model inference, production agent edits, cancellation, Deep2 CPU/GPU numerical checks, soak and packaging.

NOTE: `GetTempFileNameW` uses a `MAX_PATH` output buffer here; very long directory paths may fail cleanly and are not certified. Existing destination metadata/ACL preservation must be tested on Windows before daily-use certification.
