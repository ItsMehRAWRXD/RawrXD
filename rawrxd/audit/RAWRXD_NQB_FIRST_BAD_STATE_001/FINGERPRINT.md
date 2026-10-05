# RAWRXD_NQB_FIRST_BAD_STATE_001 — FROZEN FAILURE FINGERPRINT

```ini
BUILD_IDENTITY=PASS
CURRENT_TREE_COMPILE=PASS
PROBE=rawrxd/tools/nqb_first_bad_state.cpp
ARTIFACT_SHA256=8D013AF6BCC88FBB7BBF3DDE739E60504929679307EDB3DC8574296B4DE79A8A

GGUF=G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf            (1363935456 B)
NQB =G:\~dev\rawrxd\models\llama3.2-3b-real-f32.nqb        (12857017048 B)
PROMPT=The capital of France is   (5 tokens, greedy, seed=7)
```

## 1. Checkpoint census — comparison is admissible

```ini
GGUF_CHECKPOINT_RECORDS=2479
NQB_CHECKPOINT_RECORDS=2479
GGUF_UNIQUE_LAYERS=28   GGUF_LAYER_MIN=0   GGUF_LAYER_MAX=27
NQB_UNIQUE_LAYERS=28    NQB_LAYER_MIN=0    NQB_LAYER_MAX=27
COMPARISON_ADMISSIBLE=1
```

Neither side degenerated to a single layer, so "layer 0 is first bad" is a real
localisation and not an artefact of a blinded instrument. 17 per-layer stages
(ATTN_NORM Q K V Q_ROPE K_ROPE ATTN_SCORES ATTN_PROBS ATTN_VALUE O_PROJ
ATTN_RESIDUAL FFN_NORM FFN_GATE FFN_UP SWIGLU FFN_DOWN LAYER_RESIDUAL) are
present for every layer 0..27.

## 2. Runtime geometry — the context-length hypothesis is REFUTED for this replay

```ini
GGUF [INIT] maxSeqLen=2048   KVCache::allocate maxSeqLen=2048
NQB  [INIT] maxSeqLen=2048   KVCache::allocate maxSeqLen=2048
NQB  [NQBRAID] LOADED declares maxSeqLen=131072

MAX_SEQ_LEN_DECLARATION_DIFF=1
MAX_SEQ_LEN_LOAD_BEARING_CURRENT_REPLAY=0
FIRST_BAD_DOMAIN_RUNTIME_GEOMETRY=RULED_OUT_AS_FIRST_BAD
```

The NQB header declares a 131072 context but the engine allocates its KV cache at
2048 on **both** routes, so the declared difference is not load-bearing here.
Also measured and equal on both routes: `arch=llama layers=28 hidden=3072
heads=24 kv_heads=8 head_dim=128 gqa_group=3 ffn=8192 vocab=128256
rope_theta=500000 rope_scaling=1 rope_dim=128 rope_neox=1 rope_eps=1e-5
tie_embed=1 quant=Q6_K(type 14) tensors=255`.

## 3. Per-step census — the decisive measurement

```ini
STEP=0  records=495  hash_match=495  hash_mismatch=0    BIT_EXACT
STEP=1  records=495  hash_match= 75  hash_mismatch=420  DIVERGED
STEP=2  records=495  hash_match= 87  hash_mismatch=408  DIVERGED
STEP=3  records=495  hash_match= 82  hash_mismatch=413  DIVERGED
STEP=4  records=499  hash_match= 74  hash_mismatch=425  DIVERGED
```

**Step 0 is bit-identical across all 495 records.** Divergence begins at step 1
and persists. Step 0 is the only step whose inputs are the pristine embedding;
every later step reads back KV state written by the previous step. This is the
signature of a defect in the *stateful* path, not in weight binding.

## 4. First bad state

```ini
FIRST_BAD_STEP=1
FIRST_BAD_LAYER=0
FIRST_BAD_TRANSFORM=Q_ROPE
```

Stage matrix, layer 0, step 1, in causal (data-dependency) order, measured from
the dumped full vectors (`PASS2_STEP=1`, `n=2` for the attention pair, which is
the correct width for seqLen=2):

```ini
EXACT  ATTN_NORM   Q   K   V
DIFF   Q_ROPE       n=3072 cosine=0.973704845 rmse=0.321490 max_abs=3.77615
DIFF   K_ROPE       n=1024 cosine=0.921905933 rmse=0.604786 max_abs=6.79644
DIFF   ATTN_SCORES  n=2    cosine=0.991328156 rmse=0.243191 max_abs=0.343925
DIFF   ATTN_PROBS   n=2    cosine=0.987083788 rmse=0.0830991 max_abs=0.0830991
DIFF   ATTN_VALUE / O_PROJ / ATTN_RESIDUAL / FFN_* / SWIGLU / LAYER_RESIDUAL
```

`Q_ROPE` is the earliest transform whose value differs. `Q`, `K`, `V` and
`ATTN_NORM` are bit-exact, so the projections and the residual-stream input are
identical; the divergence is introduced by the rotary embedding and then carried
by every downstream stage. Note `Q_ROPE` is the *smaller* perturbation
(cosine 0.974) and `K_ROPE` the larger (0.922), which is the expected ordering
when Q is rotated first.

Per-layer mismatch counts at step 1 (24-27 of 28 for every stage) are
**cascade**, not independent defects: layer 0 is the only layer whose input is
the embedding, so from layer 1 onward the residual stream already carries the
error.

### 4a. CORRECTION — an earlier K_ROPE attribution in this file was wrong

The first pass of this analysis reported `FIRST_BAD_TRANSFORM=K_ROPE` on the
strength of the coarse hash for `S1|L0|Q_ROPE` matching while `S1|L0|K_ROPE` did
not. That inference was an artefact of instrument defect I1 below: the vector
loader keyed on the stage name alone, so pass 2 compared the LAST step
(`ATTN_SCORES n=5`, i.e. seqLen 5) rather than the first bad step, and the
reported stage was the first mismatch in alphabetical order rather than causal
order.

With the step-aware key and causal ordering the first bad transform is `Q_ROPE`,
not `K_ROPE`. The corrected run also shows `VECTOR_RECORDS_GGUF=85` /
`VECTOR_RECORDS_NQB=85` (5 steps x 17 stages for layer 0) where the step-blind
build reported 17, which is the direct signature of the overwrite bug.

Two observations survive unchanged across both instrument versions and are the
load-bearing results:

```ini
STEP0_BIT_EXACT=1            (494/494 records, reproduced in both runs)
FIRST_BAD_STEP=1
FIRST_BAD_LAYER=0
```

### 4b. Emitted record counts are not reproducible between runs

```ini
RUN1  RECORDS_GGUF=2479  per-step 495
RUN3  RECORDS_GGUF=2474  per-step 494
```

The same binaries on the same inputs emitted a different number of parity records.
That is not a rounding difference; it means duplicate `(step,layer,stage)` keys
exist in the dump and the loader keeps the first occurrence, so "first bad" is
computed over a set whose membership varies by run. It does not change the
verdict (step 0 exact, step 1 diverged, in both runs) but it does mean the
per-stage attribution is only as stable as the emit order. This is E1, now
measured rather than hypothesised.


## 5. Instrument defects found and fixed in this gate

These were found by reading the measurement against its own source, the same
class of defect this repository has recorded repeatedly.

```ini
I1 PASS2_STEP_BLIND=1 -> 0
   loadVectors() read "STEP=n" from the dump header and then keyed the map on
   the VEC name alone, so each step OVERWROTE the previous one and pass 2 was
   silently comparing the LAST step (n=5 => seqLen 5) instead of the first bad
   step. The data needed to fix this was in the file the whole time.

I2 FIRST_BAD_STAGE_WAS_ALPHABETICAL=1 -> 0
   The reported stage was the first mismatch in std::map order, i.e.
   alphabetical, so it named ATTN_PROBS -- three transformations downstream of
   the defect. Replaced with the declared causal order in kCausalOrder[].

I3 NON_LAYER_SENTINEL_OVERWRITABLE=1 -> 0
   A non-layer divergence was written into firstBadLayer as -2, but the guard
   `firstBadLayer < 0` is still true for -2, so a later per-layer mismatch
   overwrote it and an EMBED-level divergence would have been converted into a
   layer hunt. Now a separate sticky flag.

I4 FORMAT_STRING_ARITY=1 -> 0
   First draft of the census printf passed three arguments to four specifiers
   (undefined behaviour). Caught by MSVC C4477/C4313 before the run.

I5 NO_ADMISSIBILITY_GATE=1 -> 0
   Added COMPARISON_ADMISSIBLE, which returns INVALID_INPUT rather than naming
   a first bad layer when either side has fewer than 2 unique layers.
```

## 6. What this does and does not establish

```ini
STEP0_BIT_EXACT=1              (494/494, reproduced across two instrument versions)
FIRST_BAD_STATE_LOCALISED=1    (step 1, layer 0, Q_ROPE)
FIRST_BAD_DOMAIN_RUNTIME_GEOMETRY=REFUTED
FIRST_BAD_DOMAIN_WEIGHT_BINDING=REFUTED (step 0 exercises the same bindings exactly)
FIRST_BAD_DOMAIN_ROPE_TRANSFORM=LOCALISED (Q_ROPE then K_ROPE; projections exact)
NQB_CAUSAL_ROOT_CAUSE=NOT_YET_ESTABLISHED
```

The rotary embedding is where the two paths first disagree, with `Q`, `K`, `V`
and `ATTN_NORM` bit-exact going in. RoPE *configuration* is identical on both
routes (theta 500000, scaling 1, dim 128, NeoX on) and `applyRoPE` is one
deterministic function applied to both tensors in a single call, so a
configuration difference is excluded. What remains unmeasured is which of these
actually fires:

```text
H1  `pos` reaching applyRoPE differs between routes at step 1 while step 0
    (pos=0, where every rotation is the identity) stays bit-exact. This is the
    strongest surviving candidate: it predicts exactly the observed
    "step 0 exact, step 1 onwards divergent" signature.
H2  the K/Q buffers alias differently, so one route rotates bytes the other
    does not (E2 in 5a).
H3  duplicate emit keys make the coarse hash and the vector describe different
    emissions (E1/E3 in 5a) -- now partially measured, see 4b.
```

H1 is testable directly: the engine already carries a `[ROPEBISECT]` dump gated
on `kvParityDumpEnabled` for `layer==0 && (pos==0||pos==1)`
(Deep2Engine.cpp:5916,5953,5975) which prints `theta/nHeads/nKV` and dumps K
before and after `applyRoPE`. Enabling it and comparing `pos` between the two
routes is the next executable step, and it needs no new instrumentation.

## 8. H1 IS REFUTED — measured with `RAWRXD_KV_PARITY_DUMP=1`

The existing bisect was enabled and run. It fires once per route, so the two
occurrences in the log are directly comparable, and the values are
**bit-identical**:

```ini
                       GGUF route              NQB route
pos=0 K_PRE            6.38664 0.334942 ...    6.38664 0.334942 ...     IDENTICAL
pos=0 K_POST           == K_PRE                == K_PRE                 IDENTICAL
pos=0 ROPE_DELTA_CPU   0                       0                       IDENTICAL
pos=0 Q_PRE            2.87592 -1.26676 ...    2.87592 -1.26676 ...     IDENTICAL
pos=0 ROPE_DELTA_CPU   0                       0                       IDENTICAL

pos=1 K_PRE            6.8198 0.847754 3.51156 1.77736 ...  == ==     IDENTICAL
pos=1 K_POST           2.97139 6.19671 1.11649 3.77406 ...  == ==     IDENTICAL
pos=1 ROPE_DELTA_CPU   5.34895                 5.34895                 IDENTICAL
pos=1 Q_PRE            0.983253 -0.190411 0.716572 0.187001 ... == == IDENTICAL
pos=1 Q_POST           0.69148 0.724499 0.355638 0.64959 ...  == == IDENTICAL
pos=1 ROPE_DELTA_CPU   0.914911                0.914911                IDENTICAL
```

`[KVPAR]` K8/V8 for all 8 KV heads at layers 0 and 27, pos 0 and 1, are also
identical between the two occurrences.

Therefore:

```ini
ROPE_ARITHMETIC_DIVERGES=0        (REFUTED)
ROPE_POS_DIFFERS=0                (pos=0 and pos=1 printed identically)
H1_STATUS=REFUTED
```

The rotation itself is not the defect. This kills the hypothesis that had the
best prior, and it does so on measurement rather than argument: at pos=1 the
rotation is large (`ROPE_DELTA_CPU=5.34895` on K, `0.914911` on Q) and both
routes land on identical values.

### 8a. The remaining tension, stated honestly

That leaves an unresolved conflict rather than a conclusion:

```ini
PASS 1  (run_ropebisect)   Q_POST at pos=1   IDENTICAL between routes
PASS 2  (run_fixed2)       VEC LAYER_0_Q_ROPE at step 1  DIFFERS
                                cosine=0.973704845 max_abs=3.77615
```

These cannot both describe the same execution, and they are not the same
execution: `runOnce` is invoked four times (pass1-gguf, pass1-nqb, pass2-gguf,
pass2-nqb) and each builds a fresh `Deep2Engine`. The bisect above was captured
in pass 1; the `Q_ROPE` vector mismatch was measured in pass 2. So either

```text
T1  the route is not reproducible run-to-run, and the pass-1/pass-2 executions
    are not comparable; or
T2  the vector dump and the bisect observe different buffers, i.e. the Q_ROPE
    emit captures bytes other than the ones applyRoPE just wrote.
```

T2 is the more likely and the cheaper to test: `parityEmit(Q_Rope, qProj, qDim)`
is a separate call site from the `QBISECT` dump, and comparing the first eight
dumped `Q_ROPE` floats against the printed `Q_POST` decides it immediately.

### 8b. Run stability has degraded and now blocks the next step

```ini
RUN1  complete, verdict emitted
RUN2  died in NQB materialisation (OPEN -> before LOADED)
RUN3  complete, verdict emitted, vectors written (85 per side)
RUN4  complete through pass 1, but ZERO VEC lines -- never reached pass 2
```

`RAWRXD_KV_PARITY_DUMP=1` adds a per-layer K/V dump and may be what pushes
RUN4 over; that is not established. What is established is that the probe does
not reliably reach pass 2, and the 8a discriminator needs pass 2.

```ini
PROBE_REACHES_PASS_2=2 of 4
NQB_12_85GB_MATERIALISATION_RELIABLE=NO
PROBE_VERDICT_SURVIVES_PROCESS_FAULT=NO
```

The instrument still cannot distinguish "crashed" from "found nothing", because
the verdict goes to buffered stdout while the engine logs to stderr. That must
be fixed before any further adversarial run:

```text
REQUIRE: fflush(stdout) after every verdict line, or route the verdict to stderr
```

## 9. Current gate state

```ini
FIRST_BAD_STATE_LOCALISED=1        step 1, layer 0
STEP0_BIT_EXACT=1                  494/494, reproduced
ROPE_ARITHMETIC=REFUTED_AS_CAUSE   measured, not argued
FIRST_BAD_TRANSFORM=Q_ROPE         still the leading localisation
NQB_CAUSAL_ROOT_CAUSE=NOT_ESTABLISHED
FIRST_BAD_STATE_VERDICT=PARTIAL
```

`FIRST_BAD_STATE_001` is localised but NOT closed. The remaining work is short
and needs no new instrumentation: flush the verdict stream, make pass 2
reliably reachable, then run the 8a comparison.



### 5a. H1 is REFUTED at the parameter level, and a hard contradiction remains

Both routes load byte-identical RoPE configuration:

```ini
GGUF pass: ROPE_ARCH=llama ROPE_THETA_GLOBAL=500000.0 ROPE_THETA_LOCAL=500000.0
           ROPE_THETA=500000 ROPE_SCALING=1 ROPE_DIM=128 ROPE_NEOX=1
NQB  pass: ROPE_ARCH=llama ROPE_THETA_GLOBAL=500000.0 ROPE_THETA_LOCAL=500000.0
           ROPE_THETA=500000 ROPE_SCALING=1 ROPE_DIM=128 ROPE_NEOX=1
```

`applyRoPE` (Deep2Engine.cpp:5091) is a single deterministic function applied to
both tensors in one call (`:5957`), with the NeoX branch rotating q over
`numHeads` and k over `numKVHeads` through the *same* `rotateHeadNeox` lambda and
the same `effectivePos = pos / scaling`. `rotaryDim` derives from
`modelWeights.ropeDimensionCount` (128 on both) and the layout branch from
`modelWeights.ropeNeoxStyle` (true on both).

Therefore, given:

```ini
K (pre-RoPE)          BIT-IDENTICAL   at step 1, layer 0
applyRoPE             same function, same theta, same scaling, same pos, same layout
K_ROPE                MISMATCH         at step 1, layer 0
```

...the three cannot all be true. Identical input to a deterministic function
cannot produce different output. So either the `K_ROPE` comparison or the `K`
comparison is not measuring what it claims to, and the most likely mechanism is
an emit/alignment problem rather than a numerical one:

```text
E1  the parity file holds DUPLICATE (step,layer,stage) keys, and the loader keeps
    the FIRST occurrence, so the two routes may be comparing different emissions
    of the same nominal checkpoint. NOT YET MEASURED.
E2  the K_ROPE emit at :6012 reads kProj after the KV-cache write has aliased or
    advanced it, on one route only.
E3  `pos` reaching applyRoPE differs between routes while `K` still matches,
    which is possible only if pos is derived per-tensor.
```

Step alignment was checked and holds: layer-0 `ATTN_NORM` at step 1 depends on
the step-0 layer-0 output and does match, so the two routes are not offset by a
step. E1 is the cheapest and most likely, and is the next measurement.

### 5b. NQB weight materialisation is INTERMITTENTLY FATAL

Three executions of the identical command on the identical binaries:

```ini
RUN1  NQBRAID OPEN -> LOADED -> probe completed, VERDICT=FIRST_BAD_STATE_IDENTIFIED
RUN2  NQBRAID OPEN -> process died before LOADED; probe stdout lost to buffering
RUN3  (in progress)
```

Run 2 died with no error text inside the tensor materialisation loop, with
47.3 GB of 63.1 GB free and no stray processes, having completed the GGUF pass
(`status=0 completed=1 generated=1`). Its probe output was lost because the
verdict goes to buffered stdout while the engine logs to stderr.

Two consequences:

```ini
NQB_12_85GB_HEAP_MATERIALISATION_RELIABLE=NO
PROBE_VERDICT_SURVIVES_PROCESS_FAULT=NO   (needs fflush or stderr routing)
```

The first is a direct, measured argument for the zero-copy work being
architectural rather than cosmetic: the copy this refactor would delete is
already unstable. The second is an instrument defect to fix before any
adversarial run, because a crashed probe that prints nothing is
indistinguishable from a probe that found nothing.


## 7. Ledger corrections

```ini
ALL_TENSOR_WEIGHT_VALUE_PARITY=PASS_255_255      (distinct authority, keep both)
NQB_ZERO_COPY_PAYLOAD_VIEW_PARITY=UNMEASURED    (zero-copy does not exist yet)
NQB_ALL_TENSOR_PAYLOAD_PARITY=SUPERSEDED_BY_ALL_TENSOR_WEIGHT_VALUE_PARITY
```

The old name and the new name denote the same 255/255 result; recording both
without that note is what makes a ledger look self-contradictory.
