# REAP16 Coding Milestone — Generated Programs Compile and Pass Tests

Scope: verify that the repaired REAP16 exports are usable as local coding models, not
merely loadable. Audit only; no model weights changed in this step. `PROMOTE=0`.

## Prerequisites already closed

`expert_used_count` was being overwritten with the retained-expert count
(`REAP_EXPERT_USED_COUNT_FIX_001`). After repair, all five affected files carry the
original top-k:

```
qwen35moe.expert_count      = 199   qwen35moe.expert_used_count      = 8
deepseek2.expert_count      = 59    deepseek2.expert_used_count      = 4
nemotron_h_moe.expert_count = 81    nemotron_h_moe.expert_used_count = 6
```

## 64K context variants

Created as separate tags; the originals were not modified.

```
ctx64k-reap16-glm-4_7-flash_latest
ctx64k-reap16-nemotron-3_5_latest

Modelfile:  FROM <model>
            PARAMETER num_ctx 65536
```

Both load and respond:

```
ctx64k-reap16-glm-4_7-flash_latest    OK  resp='OK.'
ctx64k-reap16-nemotron-3_5_latest     OK  resp='OK'
```

A configured 64K window is not proof of reliable 64K inference; no long-context test has
been run. `LONG_CONTEXT_VALIDATION=NOT_TESTED`.

## Coding task

Prompt (identical for both, `temperature=0`, `seed=1234`, `num_ctx=65536`, `num_predict=512`):

> Write a complete C++17 program that reverses a singly linked list.
> Requirements: define struct Node; implement reverseList; include main() with three test
> cases — empty list, one node, and multiple nodes. Output only compilable C++ code.

| Model | Tokens | done_reason | Chars |
|---|---|---|---|
| `reap16-glm-4_7-flash:latest` | 400 | `stop` | 1401 |
| `reap16-nemotron-3_5:latest` | 297 | `stop` | 978 |

Both finished naturally. Neither truncated, so this is a completed submission rather than a
partial one.

## Compilation

MSVC 14.44.35207, `/std:c++17 /EHsc /W3`, no warnings promoted to errors.

```
reap16-glm-4_7-flash_latest.cpp    66 lines   BUILD_EXIT=0
reap16-nemotron-3_5_latest.cpp     42 lines   BUILD_EXIT=0
```

Both generated programs compiled on the first attempt with no source edits.

## Execution

```
=== GLM REAP59 ===
Test 1 (Empty List):
Test 2 (One Node): 5
Test 3 (Multiple Nodes): 3 2 1
EXIT=0

=== NEMOTRON REAP81 ===
Empty list reversed:
One node reversed: 5
Multiple nodes reversed: 3 2 1
EXIT=0
```

All three cases are correct in both programs: an empty list reverses to empty, a single node
is unchanged, and `1 -> 2 -> 3` becomes `3 -> 2 -> 1`.

## What the generated code actually did

Both models independently produced the standard iterative three-pointer reversal
(`prev` / `current` / `next`), which is the correct O(n) algorithm. GLM additionally emitted
`printList` and `deleteList` helpers and used a constructor-initialised node; Nemotron used
aggregate initialisation (`new Node{5, nullptr}`) with no constructor. Both are valid C++17
and both free their allocations on the paths exercised.

## Throughput

| Run | GLM | Nemotron |
|---|---|---|
| First (cold/warm mix) | 32.34 t/s | 24.76 t/s |
| After unload/reload, request 1 | 134.14 t/s | 155.52 t/s |
| After unload/reload, request 2 | 137.33 t/s | 155.22 t/s |

The later figures are with a short prompt and warm caches and are not comparable to the
first row. `load_s` was 27.62 for GLM (cold) and 0.04 for Nemotron (already resident), so the
two first-row wall times are not a like-for-like comparison.

## Stability

Both models survived `ollama stop` followed by repeated generate requests, with no loader
error and no crash. Each returned on-topic code for a second, different prompt
(palindrome check) after the full unload/reload cycle.

## What this establishes

- A repaired REAP16 export can drive a real coding task end to end: prompt, generate,
  extract, compile, run, and pass independently executed tests.
- The reduction is not merely structurally valid; it is functionally sufficient for
  straightforward code generation on these two models.
- 64K context can be configured and the models respond under it.

## What this does NOT establish

- **Broader quality.** Two models on one task family. No benchmark suite, no pass-rate
  comparison against the originals, no coding-reasoning or multi-file tasks.
- **Expert routing parity.** `expert_used_count` is now correct in metadata, and coherent
  output at 25-32 t/s is consistent with proper top-k, but no runtime expert-selection trace
  has been captured.
- **Native Deep2.** `REAP_NATIVE` remains `BLOCKED_ON_BUILD`; none of this used Deep2.
- **Long context.** 64K is configured, not validated.
- **Reproducibility.** The artifacts were repaired in place; the fixed exporter has not been
  re-run to produce a fresh export.

## Disposition

```
REAP16_GLM_LOAD=PASS
REAP16_GLM_GENERATE=PASS
REAP16_GLM_COMPILE=PASS
REAP16_GLM_TESTS=3_OF_3

REAP16_NEMOTRON_LOAD=PASS
REAP16_NEMOTRON_GENERATE=PASS
REAP16_NEMOTRON_COMPILE=PASS
REAP16_NEMOTRON_TESTS=3_OF_3

CONTEXT_64K_CONFIGURED=YES
LONG_CONTEXT_VALIDATION=NOT_TESTED
EXPERT_ROUTING_PARITY=NOT_VERIFIED
REEXPORT_WITH_FIXED_WRITER=NOT_RUN

REAP_NATIVE=BLOCKED_ON_BUILD
REAP_QUALITY=BROAD_BENCHMARK_NOT_RUN

PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```