# T074 — Chat-session persistence and cold restore

## Candidate authority

```ini
EXECUTABLE=F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe
SIZE=6106624
SHA256=884D8FBC81C9960E2DB8EC9D88F7E7C29CDECA596F5960D9C5D5FEB7296704AE
BUILD_CONFIGURATION=Release/x64
BINARY_BUILT_FROM_WORKTREE_SOURCE=1
PROMOTE=0
CERTIFIED=0
```

The executable was tested without replacement or mutation. The source change under test is the chat-session serialization/restore path in `Win32IDE_FileOps.cpp` and the startup-session handling in `Win32IDE.cpp`.

## Build/regression evidence

The rebuilt candidate linked successfully. The full CTest run completed with:

```ini
TOTAL=28
PASSED=27
SKIPPED=1
FAILED=0
EXIT_CODE=0
```

The skipped test was `deep2_h11_prefill_parity`; no test failed.

## Physical Win32 UI test

The test used the real native executable and the real ChatWindow controls:

1. Launched the candidate from the path above.
2. Created a new native Chat session (`Chat 5`) using the New Chat control.
3. Entered and submitted:
   `SESSION_RESTORE_884D_FINAL_20261104. Reply exactly with this marker and nothing else: SESSION_RESTORE_884D_FINAL_20261104`
4. Observed `Ollama: response received` and the exact marker in the ChatWindow output.
5. Closed the IDE through the native title-bar close control.
6. Relaunched the same executable path as a new process.
7. Observed the restored Chat session tabs (`Chat 1`, `Chat 2`, `Chat 1`, `Chat 4`, `Chat 5`) and the exact marker in the ChatWindow output without resubmitting the prompt.
8. Closed the relaunched process through the native title-bar close control.

The persisted session file after shutdown contained the same marker and five chat-session records:

```ini
SESSION_FILE=C:\Users\Garrett\AppData\Local\RawrXD\ide_session.json
CHAT_SESSIONS=5
CHAT_ACTIVE=4
MARKER_PRESENT=1
RAW_MARKER=1
IDE_PROCESS_AFTER_CLOSE=0
```

## Hash stability

The post-test verification returned the same candidate identity:

```ini
POST_TEST_SIZE=6106624
POST_TEST_SHA256=884D8FBC81C9960E2DB8EC9D88F7E7C29CDECA596F5960D9C5D5FEB7296704AE
HASH_STABLE=1
```

## Disposition

```ini
T074_CHAT_SESSION_RESTORE=PASS_BEHAVIORAL
CHAT_HISTORY_RESTORED=PASS
ACTIVE_SESSION_RESTORED=PASS
DUPLICATE_DEFAULT_SESSION_ON_RESTORE=NOT_OBSERVED
MESSAGE_LEVEL_CALLBACK_TRACE=NOT_SEALED
PROMOTE=0
CERTIFIED=0
```

This receipt proves the user-visible cold restore and same-binary persistence behavior. It does not claim message-level callback tracing or full product certification.
