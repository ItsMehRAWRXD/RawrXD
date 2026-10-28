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

## Increment 8: full provisional GPU-stage vector evidence

Previously \`DEEP2_MOE_GPU_STAGE_PARITY\` printed only summary differences
for the last expert's GPU scratch \`ArenaFFNAct\` and \`ArenaDown\`.
With **exactly one** selected expert, after \`K2MoEStickEndDevice\`,
successful stage downloads, and complete finite checks, the diagnostic
can now persist all four vectors:

- \`k2_l<L>_e<E>_s<S>_provisional_stage.gpu_act.txt\`
- \`k2_l<L>_e<E>_s<S>_provisional_stage.cpu_act.txt\`
- \`k2_l<L>_e<E>_s<S>_provisional_stage.gpu_down.txt\`
- \`k2_l<L>_e<E>_s<S>_provisional_stage.cpu_down.txt\`
- \`k2_l<L>_e<E>_s<S>_provisional_stage.manifest.txt\`

Requires a pre-existing exclusive evidence directory, valid
\`DEEP2_MOE_PARITY_RUN_ID\`, \`DEEP2_MOE_GPU_PARITY=1\`,
and \`DEEP2_MOE_GPU_STAGE_PARITY=1\`. The manifest records the run ID,
layer, stick, expert ID, dimensions,
\`source=POST_END_DEVICE_SCRATCH_DOWNLOAD\`,
\`gpu_buffer_identity=UNPROVEN\`,
\`scope=DIAGNOSTIC_NOT_PER_EXPERT_GPU_PARITY\` and \`certified=0\`.
It refuses nonfinite data and existing outputs and cleans up partial
new writes. The snapshot does not affect production inference output.

**These are GPU scratch downloads, not a retained-buffer authority
proof.** \`K2MoEStickEndDevice\` may overwrite or repurpose scratch;
until the kernel and command submission ownership are independently
verified, values must be treated as \`PROVISIONAL\` and cannot certify
G05/G06. The next step is checking full vectors against the CPU and
independent scalar stage references with a same-run receipt, then
implementing a dedicated retained GPU copy if current scratch lifetime
cannot be established.

Standalone C++ smoke cases now exercise successful four-vector capture,
overwrite refusal and nonfinite GPU activation rejection. Source safety
regression coverage was extended. New MSVC and Vulkan execution receipts
remain required.

\`\`\`ini
PROVISIONAL_STAGE_VECTOR_CAPTURE=SOURCE_WIRED
MSVC_SMOKE_THIS_INCREMENT=NOT_RUN
REAL_KIMI_PROVISIONAL_VECTORS=NOT_CAPTURED
GPU_BUFFER_IDENTITY=UNPROVEN
G05_G06=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
\`\`\`

## Increment 9: full provisional stage-to-independent-oracle comparison

Added \`tools/k2_provisional_stage_oracle_audit.py\`, consuming a
same-run \`k2_l<L>_e<E>_s<S>_provisional_stage.manifest.txt\` and the
matching \`k2_l<L>_e<E>_s<S>_scalar_inputs.manifest.txt\`.

The audit validates exact schema and filename identity, all four complete
finite stage vectors, expert/layer/stick/geometry, valid matching run IDs,
SHA-256 of inputs, and explicit maximum-absolute and RMS tolerances.
It independently reconstructs Q4_K gate/up → SwiGLU → Q6_K down and
checks six pairs: GPU activation vs oracle; CPU activation vs oracle;
GPU activation vs CPU; GPU down vs oracle; CPU down vs oracle; and GPU
down vs CPU. All six must satisfy both thresholds to return
\`PASS_DIAGNOSTIC\`. A mismatch exits 2, missing/bad evidence exits 3.
Existing receipts cannot be overwritten.

With matching real emitted run-specific manifests, use:

\`\`\`powershell
python tools/k2_provisional_stage_oracle_audit.py --stage-manifest "F:\rawrxd\evidence\RUN\k2_l2_e44_s0_provisional_stage.manifest.txt" --scalar-input-manifest "F:\rawrxd\evidence\RUN\k2_l2_e44_s0_scalar_inputs.manifest.txt" --max-abs 0.01 --max-rms 0.001 --receipt "F:\rawrxd\evidence\RUN\provisional_stage_audit.json"
\`\`\`

The layer/expert and thresholds above are illustrations, not approved
settings or actual evidence. The 12 synthetic cases exercise six-way
agreement, independent-oracle disagreement, cross-run identity,
malformed provenance, nonfinite vectors, invalid geometry and
overwrite refusal. CI and local Windows offline runner are registered.

**No result from this audit can certify G05 or G06.** The manifest must
continue to state \`gpu_buffer_identity=UNPROVEN\`; the tool rejects
claims of proven buffer identity. Matching downloaded scratch values
are not a substitute for a retained GPU buffer with verified command
ordering and ownership. The original GPU execution path is untouched.

\`\`\`ini
STAGE_ORACLE_SIX_WAY=SOURCE_COMMITTED
SYNTHETIC_TESTS=12_ADDED_UNEXECUTED
MSVC_VULKAN_RUN_THIS_INCREMENT=NOT_VERIFIED
GPU_BUFFER_IDENTITY=UNPROVEN
G05_G06=NOT_CERTIFIED
CERTIFIED_GATES=0
PROMOTE=0
TIP_CLIMB=HOLD
\`\`\`

## Increment 10: strict complete-vector geometry at the common comparator

The common \`k2_aggregate_vector_audit.compare\` routine also serves the
batch, single-expert, and provisional GPU stage comparisons. Before
this fix, Python \`zip(candidate, reference)\` could silently truncate
an in-memory vector and report an apparently passing comparison using
the declared row count. Valid file parsers normally prevented this,
but the comparator itself was unsafe as a reusable numerical gate.

It now requires an actual positive integer \`rows\` and exact lengths
of **both** vectors before any metrics are calculated. It also refuses
nonfinite elements in either input before subtraction. The test suite
adds explicit truncated candidate, truncated reference, inconsistent
row declaration, zero-length, and nonfinite input cases.

This guards a source-level correctness flaw. New test execution, real
GPU capture, and independent buffer-lifetime authority remain pending.

\`\`\`ini
FULL_VECTOR_LENGTH_GUARD=SOURCE_COMMITTED
NONFINITE_INPUT_GUARD=SOURCE_COMMITTED
SYNTHETIC_TESTS=ADDED_NOT_EXECUTED
G05_G06=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
\`\`\`

## Increment 11: bounded all-routed-expert independent aggregate oracle

The native GPU worklist previously captured scalar inputs from at most
one cold expert per stick, preventing independent verification of a
multi-expert weighted aggregate. With the **new opt-in**
\`DEEP2_MOE_CAPTURE_ALL_EXPERTS=1\` and a valid same-run ID, it now
attempts to capture every routed expert's host-visible Q4_K gate/up,
Q6_K down, and normalized hidden input **before** command recording.
This is bounded to 1–8 routed experts. It logs
\`GPU_SCALAR_ALL_INPUT_CAPTURE\` with \`COMPLETE_DIAGNOSTIC\` only when
all experts were saved, otherwise \`INCOMPLETE\`. Host-inaccessible
resident experts fail the input coverage requirement; this diagnostic
does not alter or disable the normal GPU inference path. Previous
single-expert capture behavior remains the default.

Added \`tools/k2_all_expert_aggregate_oracle.py\` to consume the
post-EndDevice GPU/CPU aggregate witness and every ordered routed
expert's input witness. All manifests must match the same run ID,
layer, stick, and expert identity. Any missing expert, malformed
tensor, nonfinite route, or shape mismatch fails closed. It
independently evaluates each expert via Q4_K gate/up, SwiGLU and Q6_K
down, applies its captured route weight, and sums the expert outputs
before comparing **GPU vs oracle**, **CPU vs oracle**, and **GPU vs CPU**
at explicit max-absolute and RMS tolerances. The receipt includes
per-expert packed-input hashes, aggregate hashes and the weighted
scalar-oracle hash.

Example (with a freshly allocated private evidence directory):

\`\`\`powershell
$env:DEEP2_MOE_PARITY_RUN_ID = [guid]::NewGuid().ToString('N')
$env:DEEP2_MOE_PARITY_CAPTURE_DIR = 'F:\rawrxd\evidence\KIMI_ALL_EXPERTS_001'
$env:DEEP2_MOE_GPU_PARITY = '1'
$env:DEEP2_MOE_GPU_PARITY_LIMIT = '8'
$env:DEEP2_MOE_CAPTURE_ALL_EXPERTS = '1'
# After a real GPU run and review of the COMPLETE_DIAGNOSTIC receipt:
python tools/k2_all_expert_aggregate_oracle.py --aggregate-manifest "F:\rawrxd\evidence\KIMI_ALL_EXPERTS_001\k2_l2_s0_aggregate_comparison.manifest.txt" --scalar-dir "F:\rawrxd\evidence\KIMI_ALL_EXPERTS_001" --max-abs 0.01 --max-rms 0.001 --receipt "F:\rawrxd\evidence\KIMI_ALL_EXPERTS_001\all_expert_oracle_receipt.json"
\`\`\`

Layer 2 and tolerances are examples, **not real receipt values or approved
thresholds**. The directory must already exist. Partial input capture
is never sufficient for this audit. Captures remain CPU input evidence
and completed GPU aggregate evidence only; no per-expert GPU output
buffer identity is demonstrated. G05/G06 remain blocked.
Eight synthetic scenarios are registered in CI and the Windows runner.
No new native MSVC or Vulkan runtime result is claimed.

\`\`\`ini
ALL_EXPERT_INPUT_CAPTURE=SOURCE_COMMITTED_OPT_IN
ALL_EXPERT_INDEPENDENT_ORACLE=SOURCE_COMMITTED
SYNTHETIC_TESTS=ADDED_NOT_EXECUTED
GPU_PER_EXPERT_BUFFER_IDENTITY=UNPROVEN
CERTIFIED_GATES=0
PROMOTE=0
TIP_CLIMB=HOLD
\`\`\`
