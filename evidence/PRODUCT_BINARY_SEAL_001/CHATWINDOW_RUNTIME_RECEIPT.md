# CHATWINDOW_RUNTIME_RECEIPT

ASOF_UTC=2026-11-02T13:14:32Z
GATE=CHATWINDOW_RUNTIME_NATIVE_CANDIDATE
BUILD_SCOPE=CANDIDATE_ONLY
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
CANDIDATE_EXE=F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe
CANDIDATE_SHA256=CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB
SHA_MATCH_EXPECT=1
HARNESS=harness_chatwindow_native_candidate.ps1
RUNLOG=CHATWINDOW_RUNTIME_RUNLOG.txt
UI_SURFACE=Native_Copilot_embedded (class=RawrXD_IDE_Window; control ids 1202/1203/1204/1210)
UI_SURFACE_NOTE=Qt RawrXDChatWindow / RawrXD_IDE_MainWindow / MainMenuReady ABSENT in Native candidate EXE

## Host prereq (this run)
RAWRXD_WIN32IDE_UI_PROCS=0
OLLAMA_UP=1
FREE_PHYS_MB≈39336
F_FREE_GB≈483
PRIOR_CRASH_DUMP_NOTED=RawrXD-Win32IDE.exe.24408.dmp (2026-11-02 03:22 local; non-candidate)

## Observed
LAUNCH=1 pid=27064
CREATE_SHOW=1 (input/output/send present and visible)
PROMPT_SUBMIT=1 (SetEdit + BM_CLICK Send)
MODEL_ROUTING=COMBO_INDEX_0 → ollama_debug.log model=bigdaddyg-productivity-local:latest
OLLAMA_MODEL_LOAD=PASS (from bin\ollama_debug.log)
MAX_OUTPUT_TOKENS_REQUESTED=512
RESPONSE_OK=0
RESPONSE_CLASS=NOT_OBSERVED (UI output/status growth not observed within 120s; no GENERATED_TOKENS line in ollama_debug before teardown)
CANCEL_OK=0 (Stop control present but disabled at cancel attempt; status blank)
TEARDOWN_HIDE=1
TEARDOWN_PROC=1
CRASH_DURING_RUN=0

## Disposition
DISPOSITION=FAIL_CLOSED_RESPONSE_NOT_OBSERVED
RUNTIME_PASS=0
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
TIP_CLIMB=HOLD
NOT_RUN_NEQ_PASS=1

## Law
Create/show + prompt submit proven. Response delivery and cancel not proven. Do not invent PASS.
Prior stub claiming HOST_INSTABILITY / "not executed" is superseded by this receipt + RUNLOG.
