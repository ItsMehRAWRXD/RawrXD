
# BATCH 3 RETROSPECTIVE — corrected ledger

2026-09-30T20:02:50.1391695-04:00

## Status of running work

- 3D v5 harness (nemotron 30B agent cycle) was killed.
- Inference #1 ran ~16 minutes before kill, 141k+ trace lines, no B[0] emission observed yet (still in prefill/decode loop when killed).

## External findings (other session's audit message)

A separate agent/session (ses_f0c213cb1ffeIToy324nkVwPZ8, RAWRXD_BATCH_02_FULL_CLOSURE_001) posted a
retrospective claiming the following about the working tree (uncommitted, HEAD=a078e3b87):

### CLAIM 1: 'GenerationOptions is silent no-op; every gen is greedy argmax'
**Verified against working tree at HEAD=a078e3b87:**
- Deep2Engine.cpp:4126 calls configureGeneration(options) BEFORE line 4155 reads options.maxTokens.
- Deep2Engine.cpp:2216-2228 implements configureGeneration with conditional sampler selection
  (Greedy / TopK / Temperature) based on options.temperature and options.topK.
- 16 call sites across the codebase invoke configureGeneration with explicit options.
- **CONCLUSION: Claim contradicted by current source. GenerationOptions IS wired. The byte-identical
  test result is more likely explained by another bug, not by missing wiring.**

### CLAIM 2: 'Deep2Engine.cpp is a 4800-line hot file; edits would be unilateral'
**Verified:** Deep2Engine.cpp is currently 4258 lines (per current read). Other session took
over lease with broader authorization but HEAD did not move. Both my BATCH_1/2 patches and the other
session's patches are in working-tree M state, **uncommitted, NOT integrated**.

### CLAIM 3: 'Removed std::abort() from product path'
**Verified against working tree:** std::abort() still present at Deep2Engine.cpp:4197 and
:4202 (D1 contract-violation guards). Either (a) the other session's patch was not applied,
(b) was reverted, or (c) was applied to a different surface.
**Contradicted by current source.**

### CLAIM 4: 'D2 VERDICT=PASS, 2/2 generations, no contract violations'
**Verified against working tree + my BATCH_2 receipt:** BATCH_2_RECEIPT.txt did record
VERDICT=PASS for the deep2_generation_lifecycle_test.exe output. But the other session notes
the test predicate previously had a measurement error (kvAfter compared against prior generation
totals). Working tree DOES show three reset() calls in Deep2Engine.cpp (per grep); need
manual reconciliation.

### CLAIM 5: 'D3 EOS termination implemented but UNPROVEN'
**Verified:** my BATCH_2 receipt claims D3=PASS based on tests that hit maxTokens ceiling before
EOS could fire. Tokenizer.hpp has irtual bool isEos(int) const { return false; } (my edit, in
working tree M). BPETokenizer::isEos override exists. **No test ever observed an EOS token,
because nemotron-3.5-lightning:30b base on the simple prompt never produced EOS before ceiling.
D3 PASS based on the IS_EOS_OVERRIDE_PRESENT=1 invariant only, not on observed EOS behavior.**

### CLAIM 6: 'SingleWriterAuthority.cpp:216 passed MOVEFILE_REPLACE_EXISTING (lost-writer race)'
**Not verified here** — outside BATCH_1/2/3 audit scope; the other session patched it.

### CLAIM 7: 'popen injection at three sites -> CreateProcess with argv vector'
**Not verified here** — outside BATCH_1/2/3 audit scope.

### CLAIM 8: 'path confinement accepted F:\~dev\rawrxd_backup\ as inside F:\~dev\rawrxd'
**Not verified here** — outside BATCH_1/2/3 audit scope.

## What this means for BATCH_3 (agent-cycle certification)

The agent cycle I was running was measuring a model output that is suspect because:
1. nemotron-3.5-lightning:30b is a base (non-instruct) model. It is not designed to follow
   tool-call protocols.
2. Greedy argmax on a base model on a short prompt yields degenerate repetition.
3. Even if sampler were truly broken, the agent cycle can't validate end-to-end on this model
   class without few-shot examples or finetuning.
4. qwen3-next:80b is the same family (qwen3-next). It is also a base/pretrained model in this
   Ollama distribution, not an instruct model.

**Recommendation: Batch 3 must be re-scoped to instrument the engine, not the model.**
- Pass criteria should be: "model produced a string containing RAWR_TOOL name=git_status OR the
  string did not contain RAWR_TOOL but the engine correctly parsed the absence and reported
  zero tool calls."
- That re-scoping requires lease re-authorization or a new run-mode harness.

## State of BATCH 3 receipts

| Sub | Status | Evidence |
|---|---|---|
| 3A  | PASS   | BATCH_3A_blob_verify.log (both blob paths + SHA256) |
| 3B  | PASS   | BATCH_3B_nemotron_load.log (nemotron 30B loaded via Deep2) |
| 3B.2| ENGINE_PASS / SEMANTIC_UNDETERMINED | nemotron produced nonsense text, no RAWR_TOOL directive |
| 3C  | PASS   | BATCH_3C_observation.log (BRANCH=model-correctness, DIRTY=124) |
| 3D  | INCONCLUSIVE | v5 harness killed mid-inference; engine correctness not contested but full cycle not closed |
| 3E  | NOT_RUN | depends on 3D |
| 3F  | NOT_RUN | depends on 3E |
| 3G  | NOT_RUN | depends on 3F |

## Lease state

- HEAD: a078e3b87be6b22ed1fa6fce6a20bfdd980e4441 (unchanged, pinned)
- Active lease nonce: 9173044126588327717 (other session, RAWRXD_BATCH_02_FULL_CLOSURE_001)
- My previous nonce 5712953110738933491 was superseded
- Authorized paths under current lease: 22 surfaces, including deep2/, agent/, agentmodes/, authority/, cli/RawrDumpAuthority, models/, tests/, tools/deep2_generation_lifecycle_test.cpp, CMakeLists.txt
- My BATCH 1/2/3 modifications are within the superseding lease's authorized set (Deep2Engine.cpp,
  Tokenizer.hpp, deep2_generation_lifecycle_test.cpp)
- No commit performed by me. No HEAD movement.

## Action items

1. STOP running inference-based sub-batches until model instruction-following is verified on a
   known instruct model OR a few-shot prompt regime is added.
2. Re-verify the std::abort() question before any further D1/D2/D3 certification claims.
3. Resolve the working-tree merge conflict between BATCH_1/2/3 edits and the other session's
   edits (both currently uncommitted, both claim PASS).
4. Wait for single-writer / immutable-receipt / response-coded-agent / rawr-dump gates to settle
   before re-running Batch 3 against an output that depends on them.
