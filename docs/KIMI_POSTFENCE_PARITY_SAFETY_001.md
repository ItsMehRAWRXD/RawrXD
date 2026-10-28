# Kimi post-fence parity diagnostic safety — isolated incremental patch

**Canonical base:** `fix/deep2-multimodel-safety-20261025` at `499001b2af2c57cf2d0a14f633f97664571e41c9`.

This patch preserves the canonical fused GPU execution, scalar-input capture, aggregate post-fence analysis, and native build targets. It does not copy the divergent older `K2NativeMoEFfn_ExpertGpu.cpp` from draft PR #62 over the canonical file.

## Fail-closed changes

- Every expert must have CPU-accessible gate/up/down input slices for aggregate CPU/GPU diagnostic comparison. A pinned expert with unavailable host slices now causes `status=BLOCKED reason=CPU_EXPERT_INPUT_UNAVAILABLE` instead of silently comparing an incomplete CPU sum.
- Aggregate comparison reports `scope=DIAGNOSTIC_ONLY` and `status=DIAGNOSTIC` (or `NONFINITE`), never `status=OK` as if it were certified numerical parity.
- GPU scratch arena reads remain *after* fused/device completion. Multi-expert scratch attribution is blocked with `MULTI_EXPERT_SCRATCH_IDENTITY_UNPROVEN`. In a single-expert worklist the stage diagnostic remains available but explicitly says `DIAGNOSTIC_UNPROVEN_BUFFER_IDENTITY`, because a fence does not independently prove that EndDevice preserved ArenaDown/ArenaFFNAct values.
- Failed stage downloads now report zero finite elements rather than a misleading complete finite vector.

## Verification contract

Run `python tools/test_k2_postfence_parity_safety.py` or run the existing Windows offline suite in a new private evidence directory. These are source-regression checks, **not** executed GPU numeric parity or buffer-lifetime proof. Native MSVC and Vulkan regression results have not been executed or inspected for this new branch.

### Next required implementation

Implement a dedicated per-expert retained GPU output/activation snapshot with explicit command-buffer ownership and immutable expert/layer/stick metadata; submit and fence that snapshot before D2H; independently audit SHA-256 of the captured vector and inputs; compare complete post-SwiGLU and down-GEMV outputs against the scalar oracle. The current single-expert scratch download remains provisional and cannot certify G05/G06.

```ini
CANONICAL_BASE=499001b2af2c57cf2d0a14f633f97664571e41c9
NEW_BRANCH=cert/kimi-postfence-parity-safety-20261027
SOURCE_FIX=WIRED
OFFLINE_TEST=NOT_VERIFIED_THIS_BRANCH
GPU_EXPERT_BUFFER_IDENTITY=UNPROVEN
CERTIFIED_GATES=0
PROMOTE=0
TIP_CLIMB=HOLD
```

## Increment 2: paired completed aggregate vectors

Added `k2_parity_capture::CaptureAggregateComparison`, used only after
`K2MoEStickEndDevice` returns and the aggregate diagnostic has evaluated
**all** required CPU reference experts. It writes paired complete vectors
into a pre-existing private directory under
`DEEP2_MOE_PARITY_CAPTURE_DIR`:

- `k2_l<L>_s<S>_aggregate_comparison.gpu.txt`
- `k2_l<L>_s<S>_aggregate_comparison.cpu.txt`
- `k2_l<L>_s<S>_aggregate_comparison.manifest.txt`

The manifest records layer, stick, vector size, ordered routed expert IDs
and weights, provenance `POST_END_DEVICE_GPU_PARTIAL_AND_COMPLETE_CPU_REFERENCE`,
`scope=AGGREGATE_ONLY_NOT_PER_EXPERT_PARITY`, and `certified=0`.
Malformed input, nonfinite vectors or routing coefficients, duplicate
expert identities, incorrect dimensions, existing filenames, and missing
directories fail closed. Exclusive-create file writes preserve existing
evidence. On partial failure, only newly written files are cleaned up.

Enable `DEEP2_MOE_GPU_PARITY=1`, raise
`DEEP2_MOE_GPU_PARITY_LIMIT` to cover the entire worklist, and set a
new private capture directory before the native Kimi run. Pair outputs
are diagnostic evidence suitable for a later aggregate full-vector
numerical comparator, **not** a GPU expert activation/down witness.
The GPU scratch buffer identity limitation remains. In particular,
G05 and G06 cannot be promoted from this output.

Added standalone C++ capture smoke cases and a source regression check.
No new MSVC/Vulkan execution evidence has been collected for this PR.

```ini
POST_DEVICE_AGGREGATE_PAIR_CAPTURE=SOURCE_ADDED
REAL_MODEL_AGGREGATE_VECTOR_RECEIPT=NOT_RUN
PER_EXPERT_BUFFER_IDENTITY=UNPROVEN
G05_G06=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## Increment 3: strict offline aggregate vector comparison

Added `tools/k2_aggregate_vector_audit.py` to consume the three
`k2_l<L>_s<S>_aggregate_comparison.*` files emitted by the post-device
capture. It verifies the manifest's schema, exact identity/filename,
layer/stick, vector dimensions, full ordered routing list, unique expert IDs,
finite route coefficients, provenance, scope, and the mandatory
`certified=0` field. It refuses blank/malformed/nonfinite vectors or
mismatched lengths and computes max/mean/RMS absolute error plus the
worst-error index. Explicit numerical thresholds are mandatory.
SHA-256 hashes cover both vectors and the manifest.

Example, using an *actual* emitted manifest and a fresh receipt filename:

```powershell
python tools/test_k2_aggregate_vector_audit.py
python tools/k2_aggregate_vector_audit.py --manifest "F:\rawrxd\evidence\KIMI_AGGREGATE_001\k2_l2_s0_aggregate_comparison.manifest.txt" --max-abs 0.01 --max-rms 0.001 --receipt "F:\rawrxd\evidence\KIMI_AGGREGATE_001\comparison_receipt.json"
```

Thresholds above are illustrative, **not certified tolerances**. Status
`PASS_DIAGNOSTIC` means only that this aggregate pair met the specified
thresholds. Numerical disagreement exits 2; malformed/missing evidence
exits 3. Existing receipts are never overwritten. Every receipt contains
`gpu_expert_witness=ABSENT`, `certified=false`, and `promote=0`.
No model-specific numerical PASS is claimed without executing actual Kimi
captures, inspecting the receipts, and independently reviewing tolerance
provenance. Ten synthetic regression cases were added to the offline suites.

```ini
PAIRED_AGGREGATE_AUDITOR=SOURCE_COMMITTED
SYNTHETIC_REGRESSION=SOURCE_ADDED_NOT_RUN
REAL_KIMI_AGGREGATE_RECEIPT=NOT_RUN
GPU0_PER_EXPERT_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```

## Increment 4: explicit aggregate layer/stick coverage gate

Added `tools/k2_aggregate_batch_audit.py`, a fail-closed audit across a
caller-declared, bounded list of completed aggregate layer/stick pairs.
It consumes each strict paired manifest using
`k2_aggregate_vector_audit.read_capture`, applies the **same explicit**
max-absolute and RMS thresholds to each, records the exact ordered routed
expert IDs/weights and SHA-256 of both vectors and manifest, and refuses
duplicate scopes or any missing/malformed/nonfinite/mismatched capture.

Example (select layers actually executed; these values are illustrative):

```powershell
python tools/test_k2_aggregate_batch_audit.py
python tools/k2_aggregate_batch_audit.py --capture-dir "F:\rawrxd\evidence\KIMI_AGGREGATE_001" --require 2:0 3:1 --max-abs 0.01 --max-rms 0.001 --receipt "F:\rawrxd\evidence\KIMI_AGGREGATE_001\batch_receipt.json"
```

The batch result is `PASS_DIAGNOSTIC` only if all specifically requested
layer/stick pairs pass. Missing or invalid evidence fails with exit 3;
numerical disagreement exits 2. Explicitly missing layers are never
treated as pass. The receipt always states `certified=false`,
`gpu_expert_witness=ABSENT`, and `promote=0`. This does not
establish per-expert GPU ownership, full routed-expert coverage, or
production numerical tolerance authority.

Ten synthetic cases were added and registered in CI and the Windows
offline gate. Their execution on real Kimi hardware is unverified.

```ini
AGGREGATE_LAYER_COVERAGE_AUDITOR=SOURCE_COMMITTED
AGGREGATE_BATCH_REGRESSION=SOURCE_ADDED_NOT_RUN
REAL_GPU0_PARITY=NOT_CERTIFIED
CERTIFIED_GATES=0
PROMOTE=0
TIP_CLIMB=HOLD
```

## Increment 5: single-expert GPU aggregate vs independent scalar expert

Added \`tools/k2_single_expert_aggregate_oracle.py\` to join the completed
GPU aggregate manifest with the CPU packed Q4_K gate/up, Q6_K down,
and normalized-hidden input manifest. It **requires exactly one routed
expert** and validates matching layer, stick, expert ID, hidden dimension,
quant tensor shapes, and input hashes. It independently evaluates
Q4_K gate/up → SwiGLU → Q6_K down, multiplies that scalar expert
vector by the recorded router weight, and compares the result with the
**completed GPU aggregate**, using explicit max-absolute and RMS tolerances.

This is a step closer to an independent numerical witness than the
CPU-kernel aggregate comparison. But it does not prove any individual
GPU activation or unweighted down buffer. A multi-expert aggregate is
always rejected rather than incorrectly attributed to one expert.
Every receipt remains \`certified=false\`, \`promote=0\`, with both
\`gpu_post_swiglu_witness=ABSENT\` and
\`gpu_unweighted_down_witness=ABSENT\`.

Example using real single-expert capture manifests and a fresh receipt:

\`\`\`powershell
python tools/k2_single_expert_aggregate_oracle.py --aggregate-manifest "F:\rawrxd\evidence\RUN\k2_l2_s0_aggregate_comparison.manifest.txt" --scalar-input-manifest "F:\rawrxd\evidence\RUN\k2_l2_e44_s0_scalar_inputs.manifest.txt" --max-abs 0.01 --max-rms 0.001 --receipt "F:\rawrxd\evidence\RUN\independent_aggregate_receipt.json"
\`\`\`

The expert 44 and thresholds above are examples, **not** real evidence or
certified tolerances. Requires actual emitted manifests from the same
execution, not a coincidental matching layer/stick. Recording a common
unique run/submission identifier is a future evidence-contract improvement.
Ten synthetic tests are registered in the local offline and GitHub CI suites.
A native Vulkan GPU run and test execution have not been verified here.

\`\`\`ini
INDEPENDENT_SINGLE_EXPERT_AGGREGATE=SOURCE_COMMITTED
EXACT_SAME_RUN_PROVENANCE=NOT_ESTABLISHED
GPU_EXPERT_STAGE_WITNESS=ABSENT
G05_G06=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
\`\`\`

## Increment 6: explicit same-invocation identity for independent scalar comparison

Previously a scalar-input witness and a completed aggregate witness could
be joined using matching layer, stick, and expert ID even when captured
from different Kimi inference executions. This is insufficient for a
same-execution numerical claim.

Both \`CaptureScalarInputs\` and \`CaptureAggregateComparison\` can now
stamp the same \`run_id\` from \`DEEP2_MOE_PARITY_RUN_ID\` into their manifest.
Set this variable to a freshly generated unique identifier before **one**
bounded Kimi diagnostic execution; it must consist of 16–128 ASCII letters,
digits, hyphens or underscores. The run ID is not independently attested
and must never be reused between inference invocations.

Example (PowerShell, prior to starting the Kimi executable):

\`\`\`powershell
$env:DEEP2_MOE_PARITY_RUN_ID = [guid]::NewGuid().ToString('N')
$env:DEEP2_MOE_GPU_PARITY = '1'
$env:DEEP2_MOE_GPU_PARITY_LIMIT = '64'
$env:DEEP2_MOE_PARITY_CAPTURE_DIR = 'F:\rawrxd\evidence\KIMI_ONE_RUN_001'
\`\`\`

The private evidence directory must already exist. Legacy aggregate
audits still accept previously captured manifests without \`run_id\`,
but \`k2_single_expert_aggregate_oracle.py\` now fails closed without
matching valid run IDs in *both* manifest files. The report includes the
matched run ID. A matching value is necessary but **not sufficient** to
establish buffer ownership or identical source tensor generations.

Added same-run/native manifest smoke and wrong-run/missing-run synthetic
negative tests. Their execution on the user's Windows GPU remains pending.

\`\`\`ini
SAME_RUN_ID_MANIFESTS=SOURCE_WIRED
SINGLE_EXPERT_AUDIT_REQUIRES_MATCH=SOURCE_WIRED
NATIVE_MSVC_SMOKE_THIS_INCREMENT=NOT_VERIFIED
GPU_POST_SWIGLU_BUFFER_OWNERSHIP=NOT_PROVEN
CERTIFIED_GATES=0
PROMOTE=0
TIP_CLIMB=HOLD
\`\`\`

## Increment 7: three-way independent parity decision

The single-expert joined audit now calculates three complete vector checks:
\`gpu_vs_oracle\`, \`cpu_vs_oracle\`, and \`gpu_vs_cpu\`. Every check
must satisfy both explicit absolute and RMS limits before the receipt can
report \`PASS_DIAGNOSTIC\`. This closes a source-level false-positive gap:
a completed GPU aggregate matching the scalar oracle no longer masks a
broken optimized CPU aggregate, and a GPU/CPU match cannot mask both
agreeing on the wrong numerical answer.

The receipt now includes \`checks\` and \`comparisons\` maps with per-pair
worst-index and error metrics, plus the legacy \`metrics\` alias for
\`gpu_vs_oracle\` consumers. Three synthetic disagreement cases were added.

\`\`\`ini
INDEPENDENT_THREE_WAY_PARITY=SOURCE_COMMITTED
SYNTHETIC_REGRESSION_CASES=ADDED_NOT_VERIFIED
REAL_GPU_RUN=NOT_EXECUTED_THIS_INCREMENT
GPU_PER_EXPERT_STAGE_WITNESS=ABSENT
CERTIFIED_GATES=0
PROMOTE=0
TIP_CLIMB=HOLD
\`\`\`
