# GhostText stale-response race receipt

## Scope

This receipt records a physical Win32 IDE run against the unchanged T056-T070
candidate. The test used a real document, the native editor control, a local
Ollama route, and a candidate-only callback delay to force the completion to
arrive after the editor had changed.

## Candidate identity

```ini
BINARY=F:\rawrxd\build_repair_candidate\bin\RawrXD-Win32IDE-Native.exe
SIZE=6066688
SHA256=2DBC0030DAE12AA1E8160DF4B6BA31D0C4F06272479D9B767DF8C798753D5F7A
PID=20392
PROCESS_START=2026-11-04T01:07:09.4257370-05:00
SOURCE_HEAD=4e9447beecaf85963859c487d29e86473560ceca
```

The binary hash was re-read after the run and matched the pre-run candidate
hash. The delayed test process was terminated after evidence capture; the
original candidate process remained separate and unchanged.

## Physical sequence

```ini
DOCUMENT=F:\rawrxd\evidence\T056_T070_BATCH_003\ghosttext_document.cpp
EDITOR=Native Win32 RichEdit ID=1001
ROUTE=Local models / Ollama / bigdaddyg-productivity-local:latest
DELAY_ENV=RAWRXD_GHOSTTEXT_TEST_DELAY_A_MS=20000
REQUEST_TRIGGER=REAL_EDITOR_PREFIX
EDITOR_EDIT_AFTER_TRIGGER=REAL_NATIVE_KEY_INPUT
EDITOR_TAIL_AFTER_EDIT=std::string delayed_stale(const std::string& value) { return z
```

The process log shows the real GhostText route was entered at 01:07:58 and
again at 01:07:59. The editor then received the invalidating native key edit;
the post-deadline accessibility snapshot at 01:08:29 contained the edited
`return z` text and no GhostText overlay. The delayed response therefore did
not modify or render into the editor after invalidation.

## Result

```ini
REAL_DOCUMENT=PASS
REAL_EDITOR_FOCUS=PASS
LOCAL_INFERENCE_ROUTE=PASS
GENERATION_DELAYED=PASS
EDITOR_CHANGED_AFTER_REQUEST=PASS
EDITOR_TEXT_PRESERVED_AFTER_DEADLINE=PASS
LATE_SUGGESTION_OVERLAY=NOT_OBSERVED
STALE_RESPONSE_REJECTION=PASS_BEHAVIORALLY
CALLBACK_LEVEL_RECEIPT=NOT_SEALED
```

`CALLBACK_LEVEL_RECEIPT` remains `NOT_SEALED` because this candidate's current
persistent IDE log records the route and editor notifications but does not
persist the controller's detailed `GHOSTTEXT_RESPONSE_RECEIVED` and
`GHOSTTEXT_RENDER_DECISION` trace lines. No stronger message-level claim is
made here.

## Controls

```ini
SOURCE_MUTATION=0
BINARY_MUTATION=0
REBUILD_DURING_TEST=0
PROMOTE=0
CERTIFIED=0
```
