# RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001

```ini
FINAL_VERDICT=PASS
```

Rule enforced by this document: a field is written from source only if it was read from the
tree, and from runtime only if it was observed on a running binary. Anything unmeasured is
`PENDING`. Source evidence is never allowed to imply runtime correctness, and a clean census
is never allowed to promote a build result.

Target: `rawrxd/src/deep2/Deep2Server_Sovereign.cpp`

---

## 1. SOURCE (measured from the tree)

```ini
FILE=src/deep2/Deep2Server_Sovereign.cpp

HEADER_EXISTS=0
IMPLEMENTATION_HISTORY=NONE
  # `git log --follow` yields 7 revisions; every one is the single line
  # "// STUB: src/deep2/Deep2Server_Sovereign.cpp". There is no lost work to restore.
CALLERS=0
INCLUDES=0
SYMBOL_REFERENCES=0

CMAKELISTS_APPEND_PRESENT=1     # inside list(APPEND WIN32IDE_SOURCES ...)
CMAKELISTS_REMOVE_PRESENT=1     # inside list(REMOVE_ITEM WIN32IDE_SOURCES ...)
NET_BUILD_MEMBERSHIP=0          # appended, then stripped before any target consumed it

SPEC_FOR_SOVEREIGN_SERVER=0
  # no design doc, client, port assignment, or interface contract names one.
  # src/core/sovereign_interface_contract.h is a ring-attention swarm contract
  # (RingStatus / RingMetrics / LayerRequest), not a server.

TOMBSTONE_STATUS=RETIRED
SPECULATIVE_IMPLEMENTATION_CREATED=0
STUB_MARKER_COUNT_IN_FILE=0                  measured
NON_COMMENT_LINES_IN_FILE=0                 measured
CMAKE_BARE_SOURCE_ENTRIES=0                  measured
CMAKE_REFS_ARE_COMMENTS_ONLY=YES             measured

RESTORE_COMMAND=git -C F:/~dev checkout HEAD -- rawrxd/src/deep2/Deep2Server_Sovereign.cpp
SHA256_OF_REPLACED_STUB=91A41EDF8BB3338796B19C3CD11B9120EFDFDB5A425A2C620E0015682ECDC557
```

### 1.1 Why retired rather than implemented

Four findings, each independently ruling out "recover the feature":

1. It never had an implementation, so there is nothing to restore.
2. With no header it could not have declared an API.
3. With zero callers, includes and symbol references it has no consumer.
4. With no spec, port, client or contract there is nothing to implement *against*.

The genuine OpenAI/Ollama-compatible Deep2 server is the `rawr-server` target
(`deep2_openai_server.cpp`, port 11435), which is real and links. Writing a second server
here would have meant inventing an API, a port and a route table in order to then certify it
against a test written in the same sitting. That produces a receipt measuring nothing except
the author's ability to satisfy their own assertions.

---

## 2. BUILD

```ini
CONFIGURE_RESULT=PASS
CONFIGURE_EXIT=0
  # fresh directory F:\~dev\build_tombstone_val, NOT an incremental tree.
  # This configure also exercises the known_empty_sources.txt gate added in
  # commit e7fb2efa0; the gate passes on the current tree.
COMPILE_RESULT=PASS
BUILD_EXIT=0
LINK_RESULT=PASS
OUTCOME_CASE=a            # InferenceWire.cpp compiled clean; rawr-server.exe linked
```

### 2.1 A build blocker found and fixed on the way

Nothing linked for reasons unrelated to this work:

```ini
LNK2019  unresolved external symbol Deep2::Wire::WireRecordDispatch
LNK1120  1 unresolved externals
SERVER_EXE_MISSING=1       # the failed relink DELETED the previously built exe
```

`src/deep2/InferenceWire.cpp` was an untracked TU in no target while `Deep2Engine.cpp` called
into it. Fixed by one line, adding it to the `INFERENCE_ENGINE_SOURCES` list beside its only
caller. Verified the entry survives into the generated build:

```ini
INFERENCEWIRE_IN_BUILD_NINJA=YES   2 occurrences: compile rule + InferenceEngine.lib link line
```

One missing source line had removed every runtime certification as collateral, because a
failed relink destroys the output it was trying to replace.

---

## 3. BUILD-GRAPH EQUIVALENCE

Static reasoning says the tombstone reached no target; this measures the A/B instead.

```ini
BUILD_PRE_EXIT=0
BUILD_POST_EXIT=0

STATE_PRE_verification:
  bare_line_count=2  expected=2  at_lines=7232,7404
  in_append_block=1 (expect 1)   in_remove_item_block=1 (expect 1)
  PRE_STATE_VERIFIED=YES
STATE_REPAIRED_verification:
  bare_line_count=0  expected=0   REPAIRED_STATE_VERIFIED=YES

OBJ_DIFF_PRE_ONLY=0      OBJ_DIFF_POST_ONLY=0
SRC_DIFF_PRE_ONLY=0      SRC_DIFF_POST_ONLY=0
AB_BUILD_PRE_LINK_INPUTS=262 obj / 271 src
AB_BUILD_POST_LINK_INPUTS=262 obj / 271 src
LINK_INPUT_SET_EQUAL=1
A_B_INPUTS_DISTINCT=1
  # the two source states hash differently (4B3ADD60... vs 8BEF158A...), so the
  # comparison is not a state against itself

PUBLIC_API_DIFF=NONE               dumpbin /EXPORTS identical
BINARY_BYTE_IDENTICAL=1
BINARY_SHA_PRE =6F12F3482987A036EC6BD556D33BC15C4E0082583F7FB989685B01C3A73016DC
BINARY_SHA_POST=6F12F3482987A036EC6BD556D33BC15C4E0082583F7FB989685B01C3A73016DC
SIZE_DELTA=0
RELINK_OCCURRED=0
AB_INTERPRETATION=STRONGEST_NO_REBUILD
```

The strongest of the two valid outcomes: restoring the phantom source-list membership caused
no rebuild whatsoever, so the executable is provably unchanged.

Every assertion in the harness now passes on a single run, and each was observed rather than
assumed: `PRE_STATE_VERIFIED=YES`, `POST_STATE_VERIFIED=1`, `BUILD_PRE_EXIT=0`,
`BUILD_POST_EXIT=0`, `A_B_INPUTS_DISTINCT=1`, `SERVER_STILL_ALIVE=NO`,
`STRAY_RAWR_SERVER_COUNT_LEFT_RUNNING=0`.

The pre-state was verified to contain two bare entries **at the correct positions**, not merely
the right count. An earlier revision of this harness matched the wrong one of two identical
anchor lines and inserted a phantom source into an unrelated list at line 5715 while still
producing the expected count. Positional assertion is now part of the gate.

`BINARY_SHA` is deliberately not treated as a stable identity. Across runs the same tree
produced `ffd5de31...`, `2EE75013...`, then `C965FBE3...` because MSVC restamps on every
relink. Equivalence is judged on the link input set; the hashes match here only because no
relink occurred *between* the PRE and POST captures.

---

## 4. RUNTIME

Real server, real 668 MB model, PID-scoped launch with image verification.

```ini
SERVER_EXE_SHA256=FFD5DE31C92740C272A968B01F45394FA28053C6074366E736DA35E76B609FE6
SERVER_PID=12352      SERVER_PORT=21600      SERVER_IMAGE_MATCH=1
SERVER_START_UTC=2026-10-03T01:16:39Z
SERVER_STILL_ALIVE=NO (after targeted kill of that PID only)

HEALTH_HTTP=200  HEALTH_MODEL_LOADED=True  HEALTH_STATUS=ok
MODELS_HTTP=200  MODELS_ID=tinyllama-1.1b-chat-v1.0.Q4_K_M  OWNED_BY=deep2-local
API_TAGS_HTTP=200

CHAT_HTTP=200
CHAT_TEXT=" Yes, the French is a|assistant|system|"
CHAT_USAGE=18/12/30        CHAT_FINISH=stop
CHAT_MATCHES_BASELINE=YES
```

Baseline captured before the edit and reproduced exactly: same generated text, same 18/12/30
token accounting, same `finish_reason`. `build_timestamp` and the OpenAI `created` integer
differ between runs as expected and are explicitly not regressions.

`SERVER_IMAGE_MATCH=1` is required, so the result provably came from the binary this run built
rather than from *a* listening `rawr-server.exe`.

---

## 5. NEGATIVE TESTS

```ini
NEG_MALFORMED_JSON_HTTP=400        broken JSON body
NEG_EMPTY_BODY_HTTP=400            zero-length POST
NEG_UNKNOWN_ROUTE_HTTP=404         /does/not/exist
NEG_DEAD_PORT_HTTP=CONNECTION_ERROR
NEG_DEAD_PORT_PROBE_VALID=1        the probe can distinguish absence
```

Resilience, which is the part a status-code-only check would miss:

```ini
HEALTH_AFTER_NEGATIVES_HTTP=200
HEALTH_AFTER_NEGATIVES_MODEL_LOADED=True
HEALTH_AFTER_NEGATIVES_STATUS=ok
CHAT_AFTER_NEGATIVES_HTTP=200
INFER_AFTER_ABUSE_OK=YES           still produced the exact baseline text
```

A server that rejects malformed input correctly and then quietly stops serving inference has
failed even though every status it returned was legitimate HTTP. It did not.

---

## 6. CENSUS

```ini
WHOLE_TREE_STUB_CENSUS=PENDING
LOAD_BEARING_STUB_RECOUNT=PENDING
```

Held separate on purpose. A clean census is evidence about the population; it neither
strengthens nor weakens the tombstone equivalence result, and it must never be used to
promote one to the other. Recorded separately in
`rawrxd/audit/RAWRXD_PHANTOM_COHORT_TRIAGE_001/RECEIPT.md`, whose own verdict is independent.

---

## 7. VERDICT

```ini
SOURCE_TOMBSTONE_CONFIRMED=PASS
CONFIGURE_BUILD=PASS
BUILD_GRAPH_EQUIVALENCE=PASS
LIVE_SMOKE=PASS
NEGATIVE_RESILIENCE=PASS
WHOLE_TREE_STUB_CENSUS=PENDING   (independent claim; not required for this verdict)

FINAL_VERDICT=PASS
```

`FINAL_VERDICT` may become `PASS` only when `CONFIGURE_BUILD`, `BUILD_GRAPH_EQUIVALENCE`,
`LIVE_SMOKE` and `NEGATIVE_RESILIENCE` have all been measured from execution. All four are,
each from a live run on a real model.

**Scope of this PASS.** It certifies exactly this: retiring the tombstone and removing its
two phantom source-list entries does not change what `rawr-server` is built from, and the
server built from that graph still serves correct inference. It says nothing about any other
stub, and it is not a claim about the wider tree.

---

## 8. Defects this exercise found in its own instruments

Recorded because a receipt that lists only its successes is not a receipt.

```ini
HARNESS_KILLED_SERVER_BY_IMAGE_NAME
  `taskkill /IM rawr-server.exe` and `Get-Process -Name 'rawr-server'` would destroy
  another user's or another lane's instance. Now PID-scoped, with SERVER_IMAGE_MATCH
  asserted before any response is trusted, and strays reported rather than killed.

HARNESS_SILENT_STATE_SWAP_RETURN
  The A/B state restore did `if ($idx -lt 0) { Say 'ERROR'; return }` -- it printed an
  error, restored nothing, and let the run continue into the comparison. It would have
  A/B'd two identical states and reported equivalence. Now every transition asserts itself
  and aborts (exit 4 / exit 5).

HARNESS_DUPLICATE_ANCHOR_EDITED_WRONG_LIST
  A replace-first-match against an anchor occurring at lines 5715 AND 7248 inserted a
  phantom source into an unrelated source list while still yielding the expected count.
  Now anchored on unique markers and asserted POSITIONALLY.

HARNESS_DIAGNOSTIC_OUTPUT_CAPTURED_NOT_DISPLAYED
  `Say` used Write-Output inside a value-returning function, so the pre-state verification
  evidence was swallowed into the return value and never printed -- while the run
  continued and produced a plausible-looking result. Now writes to the information
  stream. This was the most dangerous of the four: the run produced a correct answer that
  could not be distinguished from a vacuous one.

HARNESS_COMPARED_A_STALE_ARTIFACT_AFTER_FAILED_BUILDS
  The worst false green of this exercise, and it was produced while the harness was
  reporting STRONGEST_NO_REBUILD:

    BUILD_PRE_EXIT=-1        FAILED
    BUILD_POST_EXIT=-1       FAILED
    PRE_EXE_SHA256 == POST_EXE_SHA256
    BINARY_BYTE_IDENTICAL=1
    AB_INTERPRETATION=STRONGEST_NO_REBUILD

  ninja LEAVES THE PREVIOUS EXE IN PLACE when a link fails, so both builds yielded a
  readable binary and the hashes matched -- because nothing had been rebuilt. The
  build exit codes were PRINTED but never ASSERTED, so a failed build flowed straight
  into the comparison section and produced a clean, confident, entirely vacuous PASS.

  Root cause of the failures: `LNK1104 cannot open file 'bin\rawr-server.exe'`, because
  a server process leaked and held the exe open. The leak was caused by truncating the
  harness output through `Select-Object -First 60`, which terminated the pipeline
  mid-script so its teardown never ran. An operator action silently disabled the
  harness's own cleanup, and the harness had no defence against the consequence.

  Now: both build exit codes abort the run before any comparison, and the teardown is
  verified (`SERVER_STILL_ALIVE=NO`, `STRAY_RAWR_SERVER_COUNT_LEFT_RUNNING=0`).

BASELINE_CONFIGURE_0_RETRACTED
  An earlier CONFIGURE_EXIT=0 was captured at 19:51, before commit e7fb2efa0 added the
  known_empty_sources.txt gate at 20:25. It says nothing about the current tree and was
  withdrawn rather than carried forward. A green result from a tree state that no longer
  exists is not evidence.
```

---

## 9. Memorable

```ini
A_TOMBSTONE_WITH_NO_HEADER_NO_CALLER_NO_HISTORY_IS_NOT_AN_UNFINISHED_FEATURE
A_PHRASE_SO_NOTHING_CANNOT_BE_SATISFIED_WITHOUT_A_SPEC
SOURCE_EVIDENCE_AND_RUNTIME_EVIDENCE_MAY_NOT_IMPLY_EACH_OTHER
JUDGE_BINARY_EQUIVALENCE_ON_LINK_INPUTS_NOT_ON_PE_TIMESTAMPS
AN_APPEND_THEN_REMOVE_ROUND_TRIP_MAKES_THE_SOURCE_LIST_DESCRIBE_SOMETHING_NEVER_BUILT
A_DIAGNOSTIC_WHOSE_OUTPUT_CANNOT_BE_SEEN_IS_NOT_EVIDENCE
A_HARNESS_THAT_CANNOT_REPORT_ITS_OWN_SETUP_FAILURE_PRODUCES_GREEN_BY_DEFAULT
ASSERT_POSITION_NOT_JUST_COUNT_WHEN_AN_ANCHOR_IS_NOT_UNIQUE
A_FAILED_RELINK_DESTRUCTS_THE_ARTIFACT_IT_WAS_REPLACING
```

Full record: `rawrxd/audit/RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001/`
