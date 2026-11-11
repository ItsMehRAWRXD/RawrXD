# VERIFY_RECEIPT PROD_AUDIT_BATCH2_001

ASOF_UTC=2026-11-03T07:00:00Z
TIP_EXE=F:\rawrxd\build_modelroute\bin\Release\RawrXD-Win32IDE-Native.exe
SEAL_AUTHORITY_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
SEAL_AUTHORITY_TOUCHED=0
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
INVENT_PASS=0

## Status

Post-fix tip rebuild did not finish in this session (shell execution backend
unavailable / MSBuild hung after `Win32IDE_Deep2Bridge.cpp`). Batch2 string
probe script prepared at `verify_batch2_tip.ps1` but **NOT_RUN**.

Prior tip image (pre-this-fix rebuild attempt) SHA when last hashed in-session:
`CC6E66C36F6181BC85C7EE9898BA0421A23748B4BF848D84FF4274D7CA6271B9`
(LastWriteTime ~2026-11-03 01:14 local). That hash is **not** claimed as the
post-fix tip SHA.

## Gate table (honest)

| Gate | Feature | SOURCE_WIRED (code audit) | RUNTIME_REACHED | Result |
| ---: | --- | --- | --- | --- |
| 19 | Binary save + BCrypt SHA-256 | 1 (`saveFile` / `sha256Hex`) | NOT_RUN | FAIL_CLOSED |
| 20 | DocumentBuffer persist on tab switch | 1 (`persistActiveDocumentBuffer`) | NOT_RUN | FAIL_CLOSED |
| 22 | ide_session.json save/load | 1 (`saveIdeSession` / `ide_session.json`) | NOT_RUN | FAIL_CLOSED |
| 27 | Tools → Build Project (cmake --build) | 1 (menu + Commands.cpp) | NOT_RUN | FAIL_CLOSED |
| 28 | Tools → Test Project (ctest) | 1 (menu + Commands.cpp) | NOT_RUN | FAIL_CLOSED |

Law: `SOURCE_WIRED != RUNTIME_REACHED` · `NOT_RUN != PASS`.

## Next executable gate

1. Finish tip Release rebuild; record new tip SHA256 (not seal).
2. Run `verify_batch2_tip.ps1` for image probes.
3. Optionally exercise binary save SHA round-trip via product UI/path.
4. Re-run Batch1 `harness_cancel_recovery.ps1`.
