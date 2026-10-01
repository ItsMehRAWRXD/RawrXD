
# BATCH 2 — corrected ledger (after user feedback)

2026-09-30T20:17:07.2685090-04:00

## Current state (measured)

`
BATCH_2=OPEN
D1_RESULT_CONTRACT=NEEDS_FINAL_MEASURED_GATE
D2_LIFECYCLE=PROVISIONAL_PASS_NEEDS_FINAL_REBUILD
D3_EOS=IMPLEMENTED_UNPROVEN
SAMPLER_OPTIONS=PARTIALLY_WIRED_UNPROVEN
CP08=NOT_RERUN

BATCH_3=INCOMPLETE
MODEL_SELECTED_TOOL=NOT_CERTIFIED
REAL_TOOL_EXECUTION=PARTIALLY_PROVEN
OBSERVATION_RETURNED_TO_MODEL=NOT_CERTIFIED
GROUNDED_SECOND_INFERENCE=NOT_CERTIFIED
INDEPENDENT_MODEL_COUNT=0
`

## Authority state (Item 1, measured)

- HEAD: a078e3b87be6b22ed1fa6fce6a20bfdd980e4441 (pinned, no movement)
- Branch: model-correctness
- My session PID: 27964
- Lease holder PID: 30252 (process deep2_lease_holder, alive since 2026-09-30T14:44:44-04:00)
- Lease nonce: 9173044126588327717
- Lease acquirer: ses_f0c213cb1ffeIToy324nkVwPZ8 (RAWRXD_BATCH_02_FULL_CLOSURE_001)
- HEAD matches lease expected_head: yes
- **VERDICT: I am NOT the lease holder. The lease holder process is alive.**

Per user's item 1 directive: "Do not mutate from a process/session that is not the actual lease holder."

## Mutation plan status

Items 1, 2, 3 of the 15-item Batch 2 closure sequence are read-only and COMPLETED:
- Item 1 (authority precheck): COMPLETED. PID 30252 alive, mutations blocked.
- Item 2 (git diff baseline): COMPLETED. Baseline saved to
  F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_2_CLOSURE_baseline_deep2_engine_diff.patch
  (13,665 chars, captures my BATCH_1/2 patches and any other session's
  patches in working-tree M state).
- Item 3 (GenerationOptions audit): COMPLETED. Audit saved to
  F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_2_CLOSURE_generation_options_audit.txt.

Items 4-14 require source/test mutation. They are BLOCKED until lease authority is acquired.

Item 15 (final inspection) can be executed at any time; not blocked.

## Item 3 audit results (measured)

GenerationOptions struct (Deep2Engine.h:297-309) has 7 fields. Field-by-field CONSUMED_BY audit:

| Field | Header decl | Deep2Engine.cpp consumer | Verdict |
|---|---|---|---|
| maxTokens | L298 | yes — generateStream L4155, generateText L4097-4113 | CONSUMED |
| temperature | L300 | yes — configureGeneration L2217,2223,2227 | CONSUMED |
| topP | L301 | **none** | NO_CONSUMER |
| topK | L303 | yes — configureGeneration L2217,2220,2223 | CONSUMED |
| repeatPenalty | L305 | **none** | NO_CONSUMER |
| minP | L306 | **none** | NO_CONSUMER |
| seed | L308 | **none** | NO_CONSUMER |

**Conclusion:** SAMPLER_OPTIONS is PARTIALLY_WIRED. temperature + topK reach
configureGeneration (GreedySampler / TopKSampler / TemperatureSampler selection),
but **topP, repeatPenalty, minP, seed** are declared in the struct and never read.
The other agent's "silent no-op" claim is correct for 4 of 7 fields; it is wrong
about maxTokens + temperature + topK which ARE consumed.

## Item 2 baseline (measured)

The current working-tree diff against HEAD=a078e3b87 shows:
- D2 reset() consolidation: moved from three duplicate sites in generateStream()'s
  return paths to ONE site at the top of generate(). Per the diff comments, this
  also fixes the CP08_KV_WRITE inversion where resetting on the way out forced
  kvCacheLength() to 0 right after generation returned.
- D3 EOS speculative-window guard added.
- D1 contract-violation guards present (abort() still in place; the other agent's
  claim of having removed it is contradicted by the working tree).

## Stale claim corrections

- **Batch 1 "0x0D model output"**: retracted. That was the log's CRLF line
  terminator (0x0D 0x0A), not a decoded model token. The model produces coherent
  text: "[1576, 7483, 310, 278, 3303, 3900]" decodes to "The capital of the United States".
  No decode defect.

## What is BLOCKED vs what is NEXT

**BLOCKED for me** (PID 27964, not lease holder):
- Item 4: sampler plumbing for topP/repeatPenalty/minP/seed
- Item 5: deterministic sampler gate
- Item 6: sensitivity gate
- Item 7: repetition-penalty measurement
- Item 8: first-token EOS test
- Item 9: interior EOS test
- Item 10: D2 four-request KV lifecycle
- Item 11: D1 failure-path tests
- Item 12: CP08 gate rerun
- Item 13: rebuild from working tree
- Item 14: write immutable Batch 2 receipt

**NOT BLOCKED** (read-only / audit):
- Item 15: final inspection (state diff, HEAD, lease, concurrent-mutation summary)

## Path forward (3 options for the user)

### Option A: STOP, wait for lease holder (RAWRXD_BATCH_02_FULL_CLOSURE_001)
- Do nothing further.
- When PID 30252 dies, attempt acquire and run items 4-14.
- Risk: lease holder may be doing their own items 4-14; if so my subsequent
  edits must merge with theirs on the same files.

### Option B: Coordinate with lease holder
- The user (or another session) tells the lease holder to release, or asks them
  to do the missing items, or hands off.
- No action from me until coordination completes.

### Option C: Acquire NOW (force-supersede)
- The WriterLeaseAuthority will refuse if PID 30252 is alive (verified: alive).
- I would have to bypass the mechanism by writing the lease file directly.
- That bypasses the single-writer authority contract and would likely register as
  a CONCURRENT-MUTATION event by the lease holder.

**My recommendation: Option A or B. The lease authority is in place to prevent
exactly this kind of conflict. Suppressing it for speed would re-introduce the
single-writer race the other session was working to fix.**

## What I will do now

1. Execute Item 15 (final inspection): read-only summary of current state.
2. Reclassify BATCH_2 and BATCH_3 in the completion checklist.
3. Correct the stale Batch 1 "0x0D" claim in CHECKLIST.
4. Stop and wait for lease/coordination.
