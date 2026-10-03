# RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001

**Status: INCOMPLETE — runtime evidence not yet collected. This document is not a PASS.**

The single rule this receipt enforces: a field is written from source only if it was read
from the tree, and from runtime only if it was observed on a running binary. Anything not
measured is `PENDING`. Source evidence is never allowed to imply runtime correctness.

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

CMAKELISTS_APPEND_PRESENT=1     # line ~7115, inside list(APPEND WIN32IDE_SOURCES ...)
CMAKELISTS_REMOVE_PRESENT=1     # line ~7274, inside list(REMOVE_ITEM WIN32IDE_SOURCES ...)
NET_BUILD_MEMBERSHIP=0          # appended, then stripped before any target consumed it

SPEC_FOR_SOVEREIGN_SERVER=0
  # no design doc, client, port assignment, or interface contract names one.
  # src/core/sovereign_interface_contract.h is a ring-attention swarm contract
  # (RingStatus / RingMetrics / LayerRequest), not a server.

TOMBSTONE_STATUS=RETIRED
SPECULATIVE_IMPLEMENTATION_CREATED=0
STUB_MARKER_COUNT_IN_FILE=0     # verified post-edit, see script output
NON_COMMENT_LINES_IN_FILE=0     # verified post-edit, see script output
CMAKE_REFS_ARE_COMMENTS_ONLY=YES

RESTORE_COMMAND=git -C F:/~dev checkout HEAD -- rawrxd/src/deep2/Deep2Server_Sovereign.cpp
SHA256_OF_REPLACED_STUB=91A41EDF8BB3338796B19C3CD11B9120EFDFDB5A425A2C620E0015682ECDC557
```

### 1.1 Why the file was retired instead of implemented

The four findings that force this conclusion are cumulative, and each one independently
rules out "recover the feature":

1. It never had an implementation, so there is nothing to restore.
2. With no header it could not have declared an API.
3. With zero callers, includes and symbol references it has no consumer.
4. With no spec, port, client or contract there is nothing to implement *against*.

The genuine OpenAI/Ollama-compatible Deep2 server is the `rawr-server` target
(`deep2_openai_server.cpp`, port 11435), which is real and links. Writing a second
server here would have meant inventing an API, a port and a route table in order to
then certify it against a test also written in the same sitting. That produces a
receipt measuring nothing except the author's ability to satisfy their own assertions.

---

## 2. BUILD

```ini
CONFIGURE_RESULT=PENDING
COMPILE_RESULT=PENDING
LINK_RESULT=PENDING
```

Harness: `tools/validate_tombstone_001.cmd`, log dir `audit_tombstone_001/`.
Fresh configure is used deliberately — an incremental tree can hide a broken source graph.

---

## 3. BUILD-GRAPH EQUIVALENCE

The decisive test. Static reasoning says the tombstone reached no target; this measures
the A/B instead of arguing it.

Harness: `tools/validate_tombstone_binary_001.ps1`

```ini
BUILD_PRE_EXIT=PENDING
BUILD_POST_EXIT=PENDING

OBJ_DIFF_PRE_ONLY=PENDING
OBJ_DIFF_POST_ONLY=PENDING
SRC_DIFF_PRE_ONLY=PENDING
SRC_DIFF_POST_ONLY=PENDING

PUBLIC_API_DIFF=PENDING          # dumpbin /EXPORTS on both builds
BINARY_BYTE_IDENTICAL=PENDING    # whole-file SHA256, pre vs post
PRE_EXE_SHA256_RAW=PENDING
POST_EXE_SHA256_RAW=PENDING
SIZE_DELTA=PENDING
```

A PASS requires `OBJ_DIFF_* = 0` **and** `SRC_DIFF_* = 0`. Equivalence is judged on the
link input set, not on the raw file hash: MSVC stamps a new PE `TimeDateStamp` and a new
PDB GUID on every relink, so a differing hash alone proves nothing. If ninja does not
relink at all, the binary is byte-identical, which is the strongest available result.

State swapping is literal text surgery on saved copies. The script never runs
`git checkout` on a file that may carry another lane's uncommitted work.

---

## 4. RUNTIME

Baseline captured **before** the edit, same model, same prompt:

```ini
BASELINE_HEALTH_MODEL_LOADED=true
BASELINE_HEALTH_STATUS=ok
BASELINE_CHAT_TEXT=" Yes, the French is a|assistant|system|"
BASELINE_CHAT_USAGE=18/12/30
BASELINE_CHAT_FINISH_REASON=stop
```

Post-edit, real server, real 668 MB model, port 21500/21600:

```ini
HEALTH_ENDPOINT=PENDING
MODELS_ENDPOINT=PENDING
CHAT_COMPLETION=PENDING
API_TAGS=PENDING
```

`build_timestamp` and the OpenAI `created` integer are **expected** to differ between runs
and are explicitly not counted as regressions. The load-bearing assertions are
`model_loaded=true`, HTTP 200, and genuinely generated text.

---

## 5. NEGATIVE TESTS

A validator that only exercises the happy path cannot distinguish a working server from a
server that answers 200 to everything.

```ini
NEGATIVE_TEST_DEAD_PORT=PENDING
NEGATIVE_TEST_BAD_MODEL=PENDING
NEGATIVE_TEST_MALFORMED_JSON=PENDING
NEGATIVE_TEST_EMPTY_BODY=PENDING
NEGATIVE_TEST_UNKNOWN_ROUTE=PENDING
NEGATIVE_TEST_DEAD_PORT=connection failure, NOT HTTP 200
NEGATIVE_TEST_LIVENESS_AFTER_ABUSE=PENDING   # server must still be healthy AND still infer
```

The liveness re-check is the part that matters: a server that returns 500 to malformed
input and then quietly stops serving inference has failed, even though every status code it
returned was a valid HTTP status.

---

## 6. CENSUS

Whole-tree re-measurement, independent of any prior audit document.

```ini
WHOLE_TREE_STUB_RECOUNT=PENDING
LOAD_BEARING_STUB_RECOUNT=PENDING
```

The specific claim under test is the existing audit's assertion that these stubs are all
"link-neutral, zero impact". That assertion is the same class of unverified claim this
file just disproved, and it is being re-derived rather than trusted.

---

## 7. VERDICT

### 7.1 Authority chain

Each link is independent. A PASS in one link never implies a PASS in another. In
particular, a clean whole-tree census (`WHOLE_TREE_STUB_CENSUS=PASS`) is evidence about the
population and is **not** permitted to promote a failed or unmeasured binary A/B — the two
are separate claims about separate things and a clean one must never launder the other.

```ini
SOURCE_TOMBSTONE_CONFIRMED=PASS
CONFIGURE_BUILD=PENDING
BUILD_GRAPH_EQUIVALENCE=PENDING
LIVE_SMOKE=PENDING
NEGATIVE_RESILIENCE=PENDING
WHOLE_TREE_STUB_CENSUS=PENDING

FINAL_VERDICT=PENDING
```

### 7.2 Build-graph equivalence: two valid outcomes, kept distinct

```ini
AB_BUILD_PRE_LINK_INPUTS=PENDING
AB_BUILD_POST_LINK_INPUTS=PENDING
LINK_INPUT_SET_EQUAL=PENDING
RELINK_OCCURRED=PENDING
BINARY_BYTE_IDENTICAL=PENDING
BINARY_SHA_PRE=PENDING
BINARY_SHA_POST=PENDING
PUBLIC_API_DIFF=PENDING
AB_INTERPRETATION=PENDING
```

```text
RELINK_OCCURRED=0  +  BINARY_BYTE_IDENTICAL=1  +  LINK_INPUT_SET_EQUAL=1
    AB_INTERPRETATION=STRONGEST_NO_REBUILD
    The graph mutation triggered no rebuild at all. The executable is provably unchanged.

RELINK_OCCURRED=1  +  LINK_INPUT_SET_EQUAL=1
    AB_INTERPRETATION=VALID_RELINK_INPUTS_UNCHANGED
    A relink occurred for incidental build-system reasons, but the executable's
    semantic link inputs did not change. Also a valid result.

LINK_INPUT_SET_EQUAL=0
    AB_INTERPRETATION=INVALID_INPUTS_CHANGED
    The mutation DID alter what is linked. This is a real regression and must be
    investigated, not explained away by a restamped PE header.
```

### 7.3 Harness containment

A process-name kill is broader than the experiment boundary. Both harnesses now identify
the server by the PID they launched and terminate only that PID, so a `rawr-server.exe`
belonging to another user or lane cannot be destroyed as collateral. Neither harness will
start if its port is already serving, and each reports the pre-existing instances it
deliberately left running.

```ini
SERVER_PID=PENDING
SERVER_PORT=PENDING
SERVER_EXE_SHA256=PENDING
SERVER_EXE_PATH=PENDING
SERVER_IMAGE_MATCH=PENDING
SERVER_START_UTC=PENDING
SERVER_EXIT_CODE=PENDING
STRAY_RAWR_SERVER_COUNT_LEFT_RUNNING=PENDING
```

A PASS requires `SERVER_IMAGE_MATCH=1`, so the smoke result provably came from the exact
binary this run built rather than from *a* listening `rawr-server.exe`.

### 7.4 The verdict itself

```ini
FINAL_VERDICT=PENDING
```

`FINAL_VERDICT` may become `PASS` only when `CONFIGURE_BUILD`, `BUILD_GRAPH_EQUIVALENCE`,
`LIVE_SMOKE` and `NEGATIVE_RESILIENCE` have all been measured from execution. A passing
`SOURCE_TOMBSTONE_CONFIRMED` does not substitute for any of them, and a passing census
does not substitute for all of them.

---

## 8. MEMORABLE

```ini
A_TOMBSTONE_WITH_NO_HEADER_NO_CALLER_NO_HISTORY_IS_NOT_AN_UNFINISHED_FEATURE
A_PHRASE_SO_NOTHING_CANNOT_BE_SATISFIED_WITHOUT_A_SPEC
SOURCE_EVIDENCE_AND_RUNTIME_EVIDENCE_MAY_NOT_IMPLY_EACH_OTHER
JUDGE_BINARY_EQUIVALENCE_ON_LINK_INPUTS_NOT_ON_PE_TIMESTAMPS
AN_APPEND_THEN_REMOVE_ROUND_TRIP_MAKES_THE_SOURCE_LIST_DESCRIBE_SOMETHING_NEVER_BUILT
```

Full record: `rawrxd/audit/RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001/`
