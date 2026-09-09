# RawrXD Performance Completion Contract

```text
HANDOFF_AUTHORITY=1
GOVERNING=1
DATE=2026-09-08
```

## Objective

Complete the current RawrXD performance program from the existing sealed state using only:

1. **Coverage**
2. **Epoch accounting**
3. **Measured authority**
4. **Fail-closed promotion**

Do not traverse by intuition, adjacent optimization, speculative ownership, random search, or repeated reopening of previously sealed work.

The process ends only when the legal candidate space has been covered, the winning candidate has survived endurance/repeatability, and the resulting product wall has a promotable receipt.

---

# 1. Current Sealed Authority

```text
PERF_PASS_PROFILE=SEALED
PERF_WITNESS_PURITY=SEALED
PERF_ENV_SINGLE_SOURCE=1

HISTORICAL_CHAMPION=QB_KERNEL_CUT_001
HISTORICAL_CHAMPION_TPS=5.904

ROOT_REPEATABLE=0
ROOT_PROMOTABLE=0
PROMOTABLE_BASELINE=NONE

TIP_CLIMB=HOLD
LIVE_TIP_CLIMB=HOLD

NEXT_LIVE_COMPUTE=CHAMPION_REPRODUCTION
FIRST_DELTA=REPRODUCE_CHAMPION_ENV_BYTEWISE
```

Historical `5.904 TPS` is a comparison datum only until reproduced under the authoritative purified runner.

Do not silently convert it into a stable baseline.

---

# 2. Purity Contract

All performance measurements must use the same profile.

```text
CHRONO=LUKEWARM
# hot things stay hot when hot; not-hot ≠ number-sided-only
# lukewarm = scan-time binary fix of TPS-ungenating force arms

FORCED_OFF:
  TOKEN_PACING=OFF
  DEEP2_CERT_STEP_LOG=0
  DEEP2_LOGITS_GPU_SPLIT=0
  QKV_OWNER_RESI_LOG=0
  TOK_RESIDUAL_SPAM=0
  DEEP2_CKV=0
  ENABLE_WARMUP=0
  DEEP2_MARS=0
```

```text
FORCED_ON (product sticky only):
  DEEP2_MLA_Q_DEVICE=1
  DEEP2_WEIGHT_PIN=1
  DEEP2_MLA_FUSED_Q4KT=1
  DEEP2_LOGITS_THREADS=32
  DEEP2_LIVE_POLICY=AUTO
  DEEP2_LIVE_PATH=1
  DEEP2_LIVE_MECH=trampoline
  DEEP2_GEN_ALG=greedy
```

Never force:

```text
DEEP2_MLA_Q_DEVICE=0
DEEP2_LIVE_POLICY=PROMO
DEEP2_GEN_ALG=medusa
DEEP2_LIVE_MECH=trampoline,cyclone,elastic,warmup
```

Any candidate with purity drift is invalid.

```text
FAIL_CLOSED_ON_PURITY_DRIFT=1
```

No performance result obtained outside this profile can promote.

---

# 3. Existing Authorities and Artifacts

Treat these artifacts as authoritative inputs:

```text
evidence/RAWRXD_PERFORMANCE_001/PERF_WITNESS_PURITY.txt
evidence/RAWRXD_PERFORMANCE_001/PERF_PASS_PROFILE_001.txt

evidence/RAWRXD_PERFORMANCE_001/QB_KERNEL_CUT_001/
evidence/RAWRXD_PERFORMANCE_001/QKV_READBACK_CUT_001_ACCEPT.txt

evidence/RAWRXD_PERFORMANCE_001/GATE.txt
evidence/RAWRXD_PERFORMANCE_001/K2_CURRENT_TPS_LINE.txt
evidence/K2_USEFUL_TPS_001/PERF_OWNER.txt

evidence/RAWRXD_PERFORMANCE_001/RAINBOW_TABLE_001/
evidence/RAWRXD_PERFORMANCE_001/TIP_CLIMB_001_HOLD.txt
evidence/RAWRXD_PERFORMANCE_001/CHAMPION_ENV_BYTEWISE_REPRO_001/
evidence/RAWRXD_PERFORMANCE_001/PERF_COMPLETION_CONTRACT.md
evidence/RAWRXD_PERFORMANCE_001/COVERAGE_MATRIX_001/
```

Existing generation/measurement scripts include:

```text
scripts/PerfWitnessPurity.ps1
scripts/Generate-QbKernelCutPassManifest.ps1
scripts/Generate-PerfPassManifests.ps1
scripts/Generate-PastPerfPassManifests.ps1
scripts/Generate-PerfRainbowTable.ps1
scripts/Run-QbKernelCutRepeatability.ps1
scripts/Run-ChampionEnvBytewiseRepro.ps1
scripts/Invoke-PerfTipBot.ps1
scripts/Run-K2PerfCandidate.ps1
```

Do not create duplicate authorities unless an existing file truly cannot represent the required receipt.

---

# 4. Rainbow Search Authority

Current active rainbow neighborhood:

```text
DIMENSION_COUNT=3
FINITE_PASS_SIZE=18
RNG_USED=0
ENUMERATOR=MIXED_RADIX
```

Legal domains:

```text
DEEP2_QB_SX_ROWS  ∈ {32,64,128}
DEEP2_QA_SX_ROWS  ∈ {32,64,128}
DEEP2_QKV_SX_ROWS ∈ {64,128}
```

Therefore:

```text
UNIQUE_CONFIGURATION_COUNT=18
```

The cursor may already show advanced ordinals (e.g. NEXT_ORDINAL=4096/8192).

This does **not** mean that many unique candidates exist.

The mixed-radix enumerator wraps after every 18 legal tuples.

Treat subsequent ordinals as **epochs over the same finite 18-tuple set**.

---

# 5. Coverage Law

Do not optimize by direction.

Do not ask:

```text
what looks faster?
what parameter should increase?
what owner should be attacked next?
what neighboring tuple should be climbed toward?
```

Ask only:

```text
HAS_THIS_LEGAL_CONFIGURATION_BEEN_MEASURED?
HAS_THIS_EPOCH_COMPLETED?
IS_THIS RESULT AUTHORITATIVE?
```

The search progresses by complete finite coverage.

For each legal tuple assign a stable canonical configuration identity derived only from its legal values.

Example:

```text
QB32_QA32_QKV64
QB32_QA32_QKV128
...
QB128_QA128_QKV128
```

Each of the 18 unique tuples must have exactly one first-pass authoritative measurement before any tuple receives a second search measurement.

---

# 6. Epoch Law

Define:

```text
EPOCH_SIZE=18
```

One epoch means every legal unique tuple has been visited once.

Ordinal traversal may wrap infinitely, but live measurements must not.

Maintain separately:

```text
ENUMERATOR_ORDINAL
ENUMERATOR_EPOCH
UNIQUE_CONFIGURATION_ID
CONFIG_MEASUREMENT_COUNT
```

Calculate:

```text
ENUMERATOR_EPOCH = floor(ORDINAL / 18)
EPOCH_SLOT       = ORDINAL mod 18
```

Do not interpret a higher ordinal as new coverage if its configuration identity has already been covered.

---

# 7. Phase A — Reproduce Historical Champion

No rainbow live search begins before this phase closes.

Reconstruct the historical `QB_KERNEL_CUT_001` execution environment bytewise or semantically exact where byte identity is impossible.

Compare:

```text
executable path
executable hash
working directory
argv count
argv ordering
argv bytes
prompt bytes
PROMPT_TOKENS
model path
model identity/hash if available
environment variable names
environment variable values
environment variable absence/presence
forced-off purity profile
device-selection variables
Q-device selection
process priority
CPU affinity
launch mechanism
runner script path/hash
model/runtime toggles
Deep2 toggles
perf instrumentation toggles
GPU/device visibility
other known process-level performance controls
```

Explicitly account for the earlier discrepancy:

```text
Series A:
  Start-Process
  PROMPT_TOKENS=1
  TPS≈5.547–5.632
  NON_AUTHORITATIVE_ARGV

Series B:
  direct argv
  PROMPT_TOKENS=7
  TPS≈2.58–3.85

Series C:
  ollama stopped
  PROMPT_TOKENS=7
  TPS≈3.06–4.27
```

Known observation:

```text
MLA_Q_DEVICE_OPS=3904
```

Q-device remained live on slow runs.

Stopping Ollama did not restore the tip.

Therefore:

```text
OLLAMA_INTERFERENCE=NOT_PROVEN_ROOT_CAUSE
```

Do not spend optimization work here.

This phase is reproduction/accounting only.

---

# 8. Champion Reproduction Exit Conditions

Produce a champion reproduction receipt containing at minimum:

```text
CHAMPION_ENV_MATCH
ARGV_MATCH
PROMPT_MATCH
PROMPT_TOKENS
EXECUTABLE_HASH_MATCH
RUNNER_HASH_MATCH
PURITY_PROFILE_MATCH
PRODUCT_PATH
PARITY
MLA_Q_DEVICE_OPS
DECODE_TPS_REAL
GENERATION_WALL_NS
REPEAT_INDEX
```

The phase may end in one of two ways.

## A. Reproduced

```text
CHAMPION_REPRODUCTION=PASS
```

if the authoritative purified environment reproduces a valid stable wall consistent with the champion.

Then establish that reproduced value as the candidate-search comparison baseline.

## B. Historical-only

```text
CHAMPION_REPRODUCTION=NOT_REPRODUCED
```

if exact/authoritative reconstruction still cannot reproduce 5.904.

In that case:

```text
5.904=HISTORICAL_ONLY
PROMOTABLE_BASELINE=<best repeatable authoritative wall>
```

Do not keep blocking forever on an irreproducible historical point.

Document the discrepancy and move forward using the strongest repeatable authoritative baseline.

---

# 9. Establish the Search Baseline

Before rainbow live coverage starts, write:

```text
SEARCH_BASELINE_ID=
SEARCH_BASELINE_TPS=
SEARCH_BASELINE_REPEATABLE=1
SEARCH_BASELINE_PRODUCT_PATH=1
SEARCH_BASELINE_PARITY=1
SEARCH_BASELINE_PURITY=1
```

This is the only number candidates compare against for promotion during the coverage phase.

Do not change it mid-epoch.

A new baseline may only be installed between completed epochs and only after endurance promotion.

---

# 10. Phase B — Enumerate Exactly 18 Unique Candidates

Build the canonical set of all 18 tuples from the three domains.

Deduplicate by configuration identity, not ordinal.

Produce one coverage manifest containing:

```text
CONFIG_ID
QB_SX_ROWS
QA_SX_ROWS
QKV_SX_ROWS
FIRST_ORDINAL_SEEN
ENUMERATOR_EPOCH
MEASURED
MEASUREMENT_RECEIPT
PARITY
TPS
STATUS
```

Required invariant:

```text
UNIQUE_CONFIG_COUNT=18
DUPLICATE_CONFIG_COUNT_IN_COVERAGE_SET=0
```

Do not live-measure wrapped duplicate ordinals during first coverage.

---

# 11. Phase C — First Measurement Epoch

Measure each of the 18 configurations exactly once using the same purified live 64-token K2 witness.

For every candidate:

```text
SAME_PASS_PROFILE=1
PRODUCT_PATH=1
PARITY=<0|1>
DECODE_TPS_REAL=<measured>
GENERATION_WALL_NS=<measured>
CONFIG_ID=<canonical>
EPOCH=0
MEASUREMENT_INDEX_FOR_CONFIG=1
```

No retries during the first coverage epoch unless the run is invalid for an external/mechanical reason such as:

```text
runner failed before generation
receipt malformed
purity drift
process launch failure
missing model
hardware/runtime initialization failure
```

A valid slow result is still a valid result.

Do not retry because TPS is disappointing.

---

# 12. Candidate Classification

Every measured tuple must become exactly one of:

```text
INVALID
PARITY_FAIL
MEASURED_NON_WINNER
EPOCH_WINNER
```

Rules:

```text
INVALID:
  purity/product/receipt authority invalid

PARITY_FAIL:
  valid measurement but parity failed

MEASURED_NON_WINNER:
  parity passed but TPS below epoch maximum

EPOCH_WINNER:
  parity passed and highest authoritative TPS in epoch
```

Do not promote the epoch winner yet.

---

# 13. Ranking Law

Rank only authoritative parity-passing candidates.

Primary ordering:

```text
1. PARITY=1
2. highest DECODE_TPS_REAL
```

Tie-breaking, only if required:

```text
1. lower GENERATION_WALL_NS
2. lower QKV critical-path time if already measured
3. deterministic CONFIG_ID lexical/order tie-break
```

Do not introduce new metrics solely to break a tie.

Do not use historical reputation, theoretical occupancy, or expected kernel shape.

Measured wall wins.

---

# 14. Phase D — Winner Endurance

After all 18 unique configurations have one authoritative measurement, take only the epoch winner into endurance.

Do not endurance-test all 18.

Run repeated purified witnesses for the winner.

Suggested minimum contract:

```text
ENDURANCE_REPEATS>=5
```

Record:

```text
TPS_MIN
TPS_MAX
TPS_MEAN
TPS_MEDIAN
TPS_STDDEV
WALL_MIN
WALL_MAX
PARITY_ALL
PURITY_ALL
PRODUCT_PATH_ALL
```

Promotion requires all endurance runs to remain authoritative.

---

# 15. Promotion Law

Promote the winner only if:

```text
PURITY_ALL=1
PRODUCT_PATH_ALL=1
PARITY_ALL=1
REPEATABILITY=PASS
WINNER_MEDIAN_TPS > SEARCH_BASELINE_TPS
```

For the currently documented historical comparison contract, if 5.904 remains the accepted comparison champion:

```text
PROMOTE only if TPS > 5.904
```

But do not confuse that historical comparison threshold with a repeatable installed baseline unless champion reproduction has closed accordingly.

---

# 16. Attribution-Only Law

A cut may still be valuable without promotion.

For example:

```text
READBACK_REDUCED=1
TPS<=COMPARISON_CHAMPION
```

Then classify:

```text
RESULT=ATTRIBUTION_ONLY
PROMOTE=0
```

Preserve the evidence.

Do not delete a valid negative result.

Do not reinterpret it as a successful speedup.

---

# 17. QKV Readback Cut Contract

Current owner from the sealed performance line:

```text
CURRENT_OWNER=QKV_READBACK
FIRST_DELTA=QKV_READBACK_CUT
```

Do not begin this optimization until the baseline/reproduction authority allows optimization spend.

Once allowed, promotion requires:

```text
SAME_FORCED_OFF_PROFILE=1
PRODUCT_PATH=1
PARITY=1
QKV_READBACK_REDUCED=1
DECODE_TPS_REAL > COMPARISON_CHAMPION
```

If:

```text
QKV_READBACK_REDUCED=1
DECODE_TPS_REAL <= COMPARISON_CHAMPION
```

then:

```text
QKV_READBACK_CUT=ATTRIBUTION_ONLY
```

---

# 18. No-Reopen Law

Unless new measured evidence invalidates a seal:

```text
NO_REOPEN=QB_KERNEL|KVA|LOGITS
```

Do not revisit:

```text
QB kernel
KVA
LOGITS
```

merely because a later candidate is slow.

Do not use a slow result as permission to re-open previously closed owners.

A reopen requires a new receipt showing that the old ownership conclusion is false under the current authoritative product path.

---

# 19. No Directional Climb

Forbidden behavior:

```text
increase rows because previous increase helped
decrease rows because GPU looks saturated
follow fastest neighbor
gradient-like parameter walking
hill climbing
tip-bot 256 repeated witnesses
random search
RNG sampling
manual cherry-picking
skip configurations predicted to be bad
```

Required behavior:

```text
enumerate
deduplicate
cover
measure
rank
endurance
promote
```

---

# 20. Tip Bot Law

`Invoke-PerfTipBot.ps1` remains disabled as a 256-iteration live hill climb.

```text
TIP_CLIMB=HOLD
```

It may later be reused only if its execution semantics are changed or constrained so that it consumes the finite canonical candidate set without repeats during a coverage epoch.

Allowed behavior:

```text
18 unique candidates
1 measurement each
deterministic order
no RNG
no repeated live search witnesses
```

Not allowed:

```text
256 repeated live witnesses over wrapped ordinals
```

---

# 21. Rainbow Cursor Law

The rainbow cursor may continue advancing for deterministic manifest enumeration.

However:

```text
ORDINAL_ADVANCE != NEW_CONFIGURATION_COVERAGE
```

Current neighborhood has only:

```text
FINITE_PASS_SIZE=18
```

Track both:

```text
RAW_ORDINAL_COVERAGE
UNIQUE_CONFIGURATION_COVERAGE
```

The latter is what determines completion.

---

# 22. Epoch Completion Receipt

At the end of each live measurement epoch emit:

```text
PERF_EPOCH_ID=
EPOCH_NUMBER=
EXPECTED_UNIQUE=18
MEASURED_UNIQUE=18
INVALID_COUNT=
PARITY_FAIL_COUNT=
PARITY_PASS_COUNT=
WINNER_CONFIG_ID=
WINNER_TPS=
SEARCH_BASELINE_TPS=
IMPROVEMENT_TPS=
IMPROVEMENT_RATIO=
EPOCH_COMPLETE=1
```

Do not advance to endurance unless:

```text
MEASURED_UNIQUE=18
```

excluding only explicitly invalid runs that have been rerun to obtain a valid authoritative measurement.

---

# 23. Coverage Matrix

Maintain a single authoritative matrix:

```text
CONFIG_ID
QB_ROWS
QA_ROWS
QKV_ROWS
EPOCH_0_TPS
EPOCH_0_PARITY
EPOCH_0_STATUS
ENDURANCE_TPS_VALUES
FINAL_STATUS
```

Do not scatter candidate truth across unrelated logs without a consolidated index.

Path:

```text
evidence/RAWRXD_PERFORMANCE_001/COVERAGE_MATRIX_001/
```

---

# 24. Evidence Preservation

Every live measurement should have:

```text
PASS_MANIFEST.json
PASS_MANIFEST.txt
stdout/stderr witness
environment/purity receipt
candidate config
wall/TPS receipt
parity result
```

Never overwrite prior valid witnesses.

Use deterministic receipt IDs.

---

# 25. Manifest Truth Law

Do not infer tunable dimensions from incidental manifest fields.

Rejected examples include measurement/noise fields such as:

```text
receipt_id
q_branch_us
qkv_join_us
timestamps
status text
derived counters
```

Legal tunable dimensions come only from explicit rainbow domains/override authority.

The `_` separator rejection fix remains part of the sealed inference law.

---

# 26. Product-Path Requirement

Synthetic, isolated, microbenchmark, or non-product speedups may inform attribution but may not promote the product baseline.

Every promotion candidate must have:

```text
PRODUCT_PATH=1
```

The final performance number must be measured on the real product generation path.

---

# 27. Parity Requirement

Performance without correctness does not count.

Every promoted configuration requires:

```text
PARITY=1
```

Any candidate with higher TPS but failed parity is rejected.

No exceptions.

---

# 28. Stable Wall Requirement

The final result is not the fastest single witness.

The final result is the strongest repeatable purified product wall.

Required final state:

```text
STABLE_PRODUCT_WALL=1
PROMOTABLE_BASELINE=1
```

---

# 29. Final Completion Conditions

The performance program is complete when all are true:

```text
PERF_WITNESS_PURITY=SEALED
CHAMPION_REPRODUCTION=CLOSED
SEARCH_BASELINE_REPEATABLE=1

RAINBOW_UNIQUE_CONFIGS=18
RAINBOW_UNIQUE_COVERED=18
FIRST_MEASUREMENT_EPOCH_COMPLETE=1

EPOCH_WINNER_IDENTIFIED=1
WINNER_ENDURANCE_COMPLETE=1
WINNER_PARITY_ALL=1
WINNER_PURITY_ALL=1
WINNER_PRODUCT_PATH_ALL=1

FINAL_BASELINE_REPEATABLE=1
STABLE_PRODUCT_WALL=1
PROMOTABLE_BASELINE=1
```

If no legal candidate beats the repeatable baseline:

```text
SEARCH_COMPLETE=1
PROMOTION=NONE
BASELINE_RETAINED=1
```

That is a valid completion.

Do not keep searching simply because the target was not reached.

---

# 30. Target TPS

The aspirational target may remain:

```text
TARGET_TPS=8.0
```

But `8.0 TPS` is not permission to run indefinitely.

The finite candidate-space completion contract has higher authority.

If all 18 legal candidates have been measured and the winner has endured but remains below 8 TPS:

```text
CURRENT_SEARCH_SPACE=EXHAUSTED
TARGET_TPS=UNMET
```

Then stop.

Opening another search space requires a separately justified new dimension set based on measured ownership evidence.

---

# 31. New Search-Space Law

Do not silently add dimensions.

A new domain may be introduced only after the current 18-candidate epoch is fully exhausted and the winner has been endurance-tested.

Each new dimension requires:

```text
DIMENSION_NAME
WHY_IT_IS_EXECUTABLE
WHY_IT_IS_PRODUCT_RELEVANT
LEGAL_VALUES
SOURCE_AUTHORITY
EXPECTED_OWNER
NO_CONFLICT_WITH_SEALED_WORK
```

Then create a new explicit rainbow domain revision.

Never mutate the active epoch's domains while measurements are in progress.

---

# 32. Failure Handling

If a candidate crashes:

```text
classify crash
preserve receipt/log
determine whether configuration-invalid or infrastructure-invalid
```

If infrastructure-invalid:

```text
rerun same configuration
```

If configuration-valid but runtime-crashing:

```text
STATUS=INVALID_OR_UNSAFE_CONFIGURATION
```

Do not modify unrelated runtime code merely to rescue one candidate unless the crash reveals a genuine product bug independent of the tuning tuple.

---

# 33. Agent Behavior

The agent must not ask for the next optimization direction after every receipt.

It should autonomously continue through the finite completion contract.

Required loop:

```text
READ_AUTHORITY
VERIFY_PHASE
SELECT_NEXT_UNCOVERED_CONFIGURATION
RUN_AUTHORITATIVE_WITNESS
WRITE_RECEIPT
UPDATE_COVERAGE_MATRIX
CONTINUE_UNTIL_EPOCH_COMPLETE
RANK
ENDURANCE_WINNER
PROMOTE_OR_RETAIN
SEAL_FINAL_STATE
```

Only stop early for:

```text
missing required executable/model
unrecoverable build failure
corrupt authority artifacts
hardware/runtime failure preventing authoritative measurement
contradictory sealed contracts that cannot be resolved from existing evidence
```

Do not stop merely to ask what direction to explore.

There is no directional exploration.

---

# 34. Required Final Output

When complete, emit a concise final authority block:

```text
PERF_PROGRAM_COMPLETE=1

PURITY=SEALED
SEARCH_SPACE_UNIQUE=18
SEARCH_SPACE_COVERED=18
EPOCHS_USED=<n>

ORIGINAL_HISTORICAL_CHAMPION_TPS=5.904
AUTHORITATIVE_START_BASELINE_TPS=<value>

WINNER_CONFIG_ID=<id>
WINNER_QB_ROWS=<value>
WINNER_QA_ROWS=<value>
WINNER_QKV_ROWS=<value>

WINNER_FIRST_PASS_TPS=<value>
WINNER_ENDURANCE_MIN_TPS=<value>
WINNER_ENDURANCE_MEDIAN_TPS=<value>
WINNER_ENDURANCE_MAX_TPS=<value>

PARITY=PASS
PRODUCT_PATH=PASS
PURITY=PASS
REPEATABILITY=PASS

FINAL_PROMOTED_TPS=<value>
STABLE_PRODUCT_WALL=1
PROMOTABLE_BASELINE=1

TARGET_TPS_8=<PASS|UNMET>
SEARCH_SPACE_EXHAUSTED=1
NEXT_ACTION=<NONE|NEW_MEASURED_OWNER_REQUIRED>
```

---

# 35. Governing Principle

```text
NO_DIRECTIONAL_TRAVERSAL
NO_RANDOM_SEARCH
NO_REOPEN_BY_INSTINCT
NO_REPEAT_UNTIL_COVERAGE
NO_PROMOTION_FROM_SINGLE_WITNESS

COVERAGE
→ EPOCH
→ RANK
→ ENDURANCE
→ PROMOTE OR RETAIN
→ SEAL
```

Complete the finite authority tree. Do not wander outside it.

**Terminal condition:** if all 18 configurations are covered and none produces an endurance-qualified improvement, the search is finished rather than expanding indefinitely.
