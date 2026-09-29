# DEEP2_UPSTREAM_REPEAT_REQUEST_001 — Receipt (fresh-provenance binary)

Date: 2026-09-28 · Port 11436 · Model qwen2.5-coder-1.5b-base (Deep2, OLLAMA_CALLS=0)

## P0.1 — BINARY_PROVENANCE

```
RUNNING_PID=20116
RUNNING_EXE_PATH=F:\~dev\build_rawr_ninja\bin\rawr-server.exe
RUNNING_EXE_SHA256=F1FC9C51B96F1E7A14A029F993E63F30FB5827074EC22ADA4D37C08411B98BC3
RUNNING_EXE_MTIME=2026-09-28T16:1x (post-rebuild)

SOURCE_GIT_HEAD=01ec95709421c68f2514e048cac1b0a7aedc826c
SOURCE_TREE_DIRTY=579 (working tree has in-flight fixes)
BUILD_TREE=F:\~dev\build_rawr_ninja
CMAKE_HOME_DIRECTORY=F:/~dev/rawrxd
CMAKE_GENERATOR=Ninja
BUILD_CONFIG=Release

RUNNING_EXE_SHA_MATCH=PASS      (running image == on-disk artifact, SHA equal)
RUNNING_EXE_EQUALS_JUST_BUILT_ARTIFACT=PASS
BUILD_STARTED_AFTER_RELEVANT_SOURCE_CHANGE=PASS
  (decisive check: 0 relevant sources newer than exe after rebuild —
   Deep2Engine.cpp 16:15:58 change was caught as STALE against the old exe
   15:58:06; server killed (LNK1104 lock), rebuilt 13/13, restarted)
BINARY_PROVENANCE=PASS
```

Note: stale-binary risk was REAL — the previous running exe predated the
Deep2Engine.cpp/GGUFLoader.cpp edits. Provenance gate caught it; this is why
Q's "triple" check matters beyond mtimes.

## P0.2 — Repeat-request lifecycle (3 sequential requests, same process)

```
MODEL_LOAD=PASS (D2LOAD + MODEL_LOAD=PASS in fresh stderr)
HEALTH=PASS (pre + post, both 200)

REQUEST_1_GENERATED=PASS (200, 8 tokens, echoed prompt text "Say exactly: A_162…")
REQUEST_2_GENERATED=PASS (200, POST 16744.37 ms)
REQUEST_3_GENERATED=PASS (200, POST 15319.62 ms)

SAME_PROCESS=PASS (all served by PID 20116)
SAME_ENGINE_INSTANCE=PASS (engine_ is a member of OpenAIServer::Impl,
  constructed once in OpenAIServer(); no per-request engine make_unique)

REQUEST_2_STATE_RESET=PASS (engine->reset() at request entry clears KV/hidden/SSM/MLA — deep2_openai_server.cpp:504-508)
REQUEST_3_STATE_RESET=PASS (same path)
KV_POSITION_MISMATCH_COUNT=0 (fresh server stderr: 0 mismatch lines across all requests)
PROMPT_DEPENDENT_OUTPUT=PASS (unique timestamp echoes per request — not canned)

POST_REQUEST_HEALTH=PASS (200, 0.06 ms)

VERDICT=PASS
```

## First-divergence checkpoint capture (P0.2 instrument, for future runs)

Checkpoint/state schema per Q's spec is ready to wire into the server's request
path (REQUEST_BEGIN/ENGINE_RESET_ENTER/EXIT/TOKENIZE_DONE/PREFILL/KV_VALIDATE/
DECODE_BEGIN/REQUEST_END) — current evidence level: black-box (HTTP + stderr)
plus source verification of the reset call. The FIRST_DIVERGENCE capture is not
needed while the ladder passes; it becomes the tool the moment any request
regresses to 0 tokens.

## Open follow-ons

- P0.4 (bind authority) remains IN_FLIGHT: verify default bind + add
  `--listen` explicit opt-in + auth-on-non-loopback.
- P0.3 (HTTP status contract) stays BLOCKED on P0.2 finalization — ladder green.
- P1 (Qwen2 Q/K/V bias + numerical parity) stays BLOCKED on P0 lifecycle
  sign-off; tokenizer first-mismatch finding from
  `_qwen2_parity_receipt.md` remains the numerical gate entry.