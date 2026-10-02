# CANONICAL_REAL_INFERENCE_CERTIFICATION — DECODE STEP INSTRUMENTATION

    GATE   = CANONICAL_REAL_INFERENCE_CERTIFICATION
    DATE   = 2026-10-01
    MODEL  = tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
    PROMPT = "What is the capital of France? Answer in one word."
    ROUTE  = CPU (vulkan explicitly disabled, to isolate from GPU)
    RESULT = FAILURE REPRODUCED AND CLASSIFIED: CASE B

---

## 1. The failure is reproduced

    ACCENTED_TEXT=SegúnSegúnSegúnSegúnSegúnSegún
    ALL_LOGITS_HASHES_EQUAL=0
    ALL_ARGMAX_IDS_EQUAL=1
    FAILURE_CLASS=FORWARD_LIVE_ARGMAX_CONSTANT_INVESTIGATE_NUMERICS

The reported failure (`frique` repeated 24x) and this one (`Según` repeated)
are the same defect with different surface tokens. The repetition is
deterministic and independent of the specific wrong token.

## 2. Classification: the four cases, decided by measurement

| Case | Prediction | Measured | Verdict |
|---|---|---|---|
| A | identical LOGITS_HASH every step | A83CFC33 → 8EB73547 → 91ED67F0 → B46DD6A6 → 1FD5AD07 → 4762F724, **all different** | **RULED OUT** |
| B | hash changes, argmax constant | hash changes every step; `ARGMAX_TOKEN_ID=24109` every step | **CONFIRMED** |
| C | token ids differ, text identical | token id is *also* identical (24109 every step) | **RULED OUT** — not detokenisation |
| D | `KV_POS_AFTER == KV_POS_BEFORE` | 13→14→15→16→17→18, monotonically advancing | **RULED OUT** |

So the forward pass genuinely re-executes, the cache position genuinely advances,
and the detokeniser is not at fault. The computation is live and still produces
the same answer.

## 3. What the top-5 reveals, and why it matters

    STEP=0 TOP5=24109:5.3701, 17994:5.3228, 8858:4.6200, 23081:4.3454, 22725:4.0649
    STEP=5 TOP5=24109:5.3663, 17994:5.3326, 8858:4.6261, 23081:4.3500, 22725:4.0655

The **same five tokens in the same order** at every step, with values moving only
in the third and fourth decimal. The 32000-entry logit vector is not frozen —
that is why the hash changes — but its *shape* is effectively frozen.

A working autoregressive model fed its own output token must see its logits move
measurably: the new token changes the next-token distribution. Here, feeding
token 24109 back in produces logits that differ from the previous step by ~0.004.

That is the signature of the model not being able to see the token it just
produced.

## 4. A corroborating defect found in the same run: prefill is off by one

    PREFILL_TOKENS_FED=13
    KV_POS_AFTER_PREFILL=12
    KV_POS_EXPECTED_AFTER_PREFILL=13
    PREFILL_CORRECT=0

Thirteen prompt tokens were decoded and the cache position ended at **12**. One
token is unaccounted for, consistently, at the end of a sequence.

This matters because it identifies *which* token is invisible. If
`kvCacheLength()` reports completed positions, then the final token of every
sequence — the most recent one — is written but not counted, and the attention
read is one step behind the write.

That is a far more specific hypothesis than "investigate numerics":

> The KV write for the newest position and the KV read by attention are
> disconnected. The position counter advances, the forward runs, and the model
> reads a cache that does not contain the token it just produced.

## 5. Hypothesis, and what would falsify it

    HYPOTHESIS
        Newest-slot KV visibility defect. The engine advances the position and
        performs the forward, but the slot it just wrote is not included in the
        attention read, so logits depend only on history up to the previous
        token.

    CONSISTENT_WITH
        Case B confirmed; Cases A, C, D ruled out; prefill off by exactly one;
        logits near-frozen while hash changes; repetition is deterministic.

    FALSIFIED_IF
        (a) instrumenting the attention read shows the newest slot IS read and
            the logits still barely move -> then the defect is upstream in the
            feed-forward/residual, not the cache;
        (b) forcing the KV cache to be rebuilt from scratch each step changes
            the output -> confirms the cache;
        (c) a reference CPU implementation on the same GGUF produces a
            decisive, position-dependent distribution -> confirms Deep2's read
            is wrong rather than the model being pathologically flat.

    NEXT_TEST
        At the attention read, record whether the maximum attended index equals
        the maximum written index, and whether attended length == written length
        for the same step. If attended < written, the hypothesis is confirmed and
        the defect is located to a single site.

## 6. Instrumentation defects I introduced and corrected

Recorded because both produced confident nonsense before being caught:

1. **Seeding by assignment.** The first run set `cursor.pendingToken` in a loop,
   which leaves only the last token pending and runs no forward at all
   (`KV_POS_AFTER_SEED=0`). It produced plausible-looking but meaningless output
   (`<unk>Según Bibliographie`) and an "ALL_LOGITS_HASHES_EQUAL=0" verdict from a
   zero-initialised logit buffer. Fixed by decoding each prompt token.
2. **Scoring an unexecuted buffer.** `PrintArgmaxRow` was called before the first
   forward, so STEP=0 reported `ARGMAX_LOGIT=0.000000` with
   `LOGITS_MEAN=0.000000` — a zeroed buffer, not a model output. It is now
   understood as a pre-forward snapshot rather than a reading.

Both are the same failure mode this project has recorded repeatedly: an
instrument that cannot disagree with the thing it measures. Both were caught
only because the instrument printed its own preconditions (`KV_POS_AFTER_SEED`,
`LOGITS_MEAN`) alongside its readings.

## 7. Ledger

    REPRODUCED                            = 1   ( Según x6, deterministic)
    CASE_A_STALE_FORWARD                   = RULED_OUT
    CASE_B_ARGMAX_CONSTANT                 = CONFIRMED
    CASE_C_DETOKENISATION                  = RULED_OUT
    CASE_D_KV_POSITION_STUCK               = RULED_OUT
    LOGITS_CHANGING_EVERY_STEP             = 1
    KV_POSITION_ADVANCING_EVERY_STEP       = 1
    NAN_OR_INF_IN_LOGITS                   = 0
    PREFILL_TOKENS_FED                     = 13
    PREFILL_KV_POSITION                    = 12
    PREFILL_CORRECT                        = 0
    LOGIT_TOP5_SET_STABLE_ACROSS_STEPS     = 1
    LOGIT_DRIFT_OVER_6_STEPS               = ~0.004 on the argmax
    HYPOTHESIS                             = NEWEST_SLOT_KV_NOT_VISIBLE
    HYPOTHESIS_STATUS                      = UNFALSIFIED

    CANONICAL_REAL_INFERENCE_CERTIFICATION = FAIL (directly reproduced)
    RAWR_SERVER_HTTP_PATH                  = NOT_RETESTED_HERE (observed by
                                             another run; this cert tests the
                                             engine directly)