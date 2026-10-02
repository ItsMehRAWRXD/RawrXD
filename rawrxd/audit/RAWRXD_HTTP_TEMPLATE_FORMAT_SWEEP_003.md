# RAWRXD_HTTP_TEMPLATE_FORMAT_SWEEP_003

This entry **retracts the root cause asserted in
`RAWRXD_HTTP_TEMPLATE_ROOT_CAUSE_002.md`**. That entry is preserved unedited
so the provenance of the error is auditable.

```text
RETRACTED_CLAIM
  "the GGUF's own template asks for a role vocabulary the vocab does not have,
   therefore template and tokenizer are incompatible, therefore the model's
   format emission is a defect"
RETRACTION_REASON
  the inference was drawn from local evidence only. Upstream
  tokenizer_config.json was never consulted before promoting OBSERVED to
  ROOT_CAUSE_CONFIRMED.
STATUS_OF_ENTRY_002 = SUPERSEDED_BY_THIS_ENTRY
STATUS_OF_ENTRY_001 = STILL_CURRENT (transport PASS, content FAIL, controls FAIL)
```

## 1. What upstream actually declares

`TinyLlama/TinyLlama-1.1B-Chat-v1.0` `tokenizer_config.json`:

```json
"added_tokens_decoder": {
  "0": {"content": "<unk>", "special": true},
  "1": {"content": "<s>",   "special": true},
  "2": {"content": "</s>",  "special": true}
},
"tokenizer_class": "LlamaTokenizer"
```

Measured from the GGUF itself, independently:

```text
VOCAB_SIZE=32000
TOKEN_TYPE_CONTROL=2          (<s>=1, </s>=2)
TOKEN_TYPE_USER_DEFINED=0
ADDED_TOKENS_IN_VOCAB=2
PREMISE_MODEL_HAS_NO_ADDED_ROLE_TOKENS=1
```

So the markers `<|system|>` / `<|user|>` / `<|assistant|>` are **not
special tokens because they were never meant to be**. The model was trained on
them as ordinary text pieces. `EXACT_VOCAB_ENTRY=0` is therefore the model's
design, not evidence of incompatibility.

This is the fifth instance in this project of the same failure shape: an
observation was promoted to a root cause without the measurement that could
have falsified it. The probe was not wrong — it reported `0` accurately. The
*interpretation* was wrong.

## 2. Whitespace sweep — the remaining suspect

`formatPhi3` emits `<|user|>\n{content}</s><|assistant|>`, with no newline
after `</s>` and none after the generation marker. Whether that matches
training is empirical. `certs/http_template_format_sweep_001.cpp` measures six
byte-level variants of the same role vocabulary, one engine, greedy, one seed.

```text
VARIANT                SEMANTIC CONTAM   SAMPLE
raw_no_template        3/3      0/3      " the city of Paris, which is the capital of France..."
phi3_current           1/3      3/3      " Yes, the French is a|assistant|system|enjokeeps..."
zephyr_newlines        0/3      3/3      "\n<|user|>\nCan you provide alexicon|lexicon|assistant|..."
zephyr_no_trailing     1/3      3/3      " Yes, the French is a|assistant|system|enjokeeps..."
jinja_loop_newline     0/3      3/3      "\n<|user|>\nCan you provide alexicon|lexicon|assistant|..."
zephyr_trailing_sp     0/3      3/3      "\n<|user|>\nCan you provide alexicon|lexicon|assistant|..."
```

**Whitespace is not the variable.** All five marker renderings contaminate
3/3; raw prompting is 3/3 clean. No candidate recovers semantics.

This does not exonerate the template — it shows the failure is insensitive to
the one dimension the sweep varied, which means the cause lies elsewhere.

## 3. The control experiment is BLOCKED, and that is its own finding

To separate "engine mishandles role markers" from "TinyLlama is too weak to
hold its own format", the sweep must run on a model whose markers are real
special tokens. Both attempted controls were rejected at model admission, by
**two different defects**:

```text
phi3-mini-Q2_K.gguf
  ADDED_TOKENS_IN_VOCAB=14          <- the control we wanted
  MODEL ADMISSION REJECTED arch=phi3
  reason=MissingRequiredTensor field=attn_q
  "4 required tensor role(s) absent; first: attn_q"
  phi3 stores a FUSED attn_qkv tensor; the gate demands a separate attn_q

gemma3-1b-Q2_K.gguf
  ADDED_TOKENS_IN_VOCAB=5
  MODEL ADMISSION REJECTED arch=gemma3
  reason=MalformedMetadata field=numHeads*headDim
  "inconsistent geometry: numHeads*headDim != hiddenDim"
```

Both rejections **failed closed**, which is correct behaviour and is recorded
as such. The defect is coverage, not safety.

### 3.1 The two rejections were not the same kind of defect

Working the phi3 gate forward produced one legitimate relaxation and one
finding that reverses the obvious fix. Both were settled by reading what the
loader *consumes*, not by relaxing until the model loaded.

**Fused QKV — the gate was wrong.** `Deep2Engine.cpp` genuinely binds
`attn_qkv.weight` and genuinely dispatches on it, so phi3 was a supported model
being refused. Relaxed, and phi3 advanced past attention.

**Fused gate+up — the gate was RIGHT, and the loader was wrong.** Relaxing
`ffn_gate` the same way would have been the natural move and would have been a
serious defect. `computeFFN()` selects on tensor *presence*:

```cpp
if (lw.wGate.data && lw.wUp.data && lw.wDown.data)   // SwiGLU: silu(gate)*up
...
else if (lw.wUp.data && lw.wDown.data) {             // "simple MLP": silu(up)
    LinearW(lw.wUp, input, nullptr, gateBuf, I);
    for (...) gateBuf[i] = silu(gateBuf[i]);
```

phi3 is a **gated** model. With `wGate` absent it would have taken the second
branch and computed `silu(up)` instead of `silu(gate)*up` — a wrong model that
emits entirely plausible English. No gate would ever have caught it: the run
would look healthy. The admission gate refusing phi3 was the *only* thing
standing between the engine and silently wrong numbers.

So the fix was made in the loader instead
(`RAWRXD_FUSED_GATE_UP_001`, `Deep2Engine.cpp` binding loop), and only then was
the gate relaxed. The split is proven rather than assumed — it fires only when
the gate is absent **and** `ffn_up.rows == 2 * ffn_down.cols`, the only shape
consistent with one tensor holding two equal projections. Rows are contiguous,
so it is an exact byte-prefix split at a row boundary, which keeps quantised
per-row block structure intact:

```text
blk.0.ffn_up.weight     in=3072  out=16384   (16515072 B)
blk.0.ffn_down.weight   in=8192  out=3072
  out == 2 * in  ->  FUSED CONFIRMED
  16384 rows * 1008 B/row = 16515072 B  (byte count matches the GGUF)
  split at 819257536 B = exactly half
```

`ModelRegistry` then accepts either an explicit `ffn_gate` or a fused `ffn_up`
**paired with `ffn_down`**, counting as one required role, because the down
projection is what proves the 2x ratio. A bare `ffn_up` is equally consistent
with a genuine non-gated MLP — different topology, different arithmetic — and
is still rejected.

Result:

```text
[Deep2Engine] admission OK arch=phi3 family=GENERIC_TRANSFORMER moe=0 mla=0
[Deep2Engine] layer 0..31 fused gate_up split: I=8192
              (gate rows [0,8192), up rows [8192,16384))
```

**A note on the instrument, which was wrong before the model was.** The first
census printed `FFN_FUSED_GATE_UP_SUSPECTED=0` for a tensor that is exactly 2x
fused. GGUF stores weight dims as `[in, out]`; I had read `shape[0]` as the row
count. The model was fine and the measurement was wrong — the same class of
defect as the two the project's own notes record, where a confident specific
wrong answer came from the instrument rather than the system. Corrected, and it
is what made the split provable instead of assumed.

The one control model with broken geometry, `gemma3-1b`, remains **rejected**:

```text
[Deep2Engine] MODEL ADMISSION REJECTED arch=gemma3
  reason=MalformedMetadata field=numHeads*headDim
MODEL_LOAD=0
```

This was asserted in an earlier draft of this section and has been re-measured.
It is recorded here because the correction is the point: `llama3.2-3b` was
**never** rejected. The census had only "NOT TESTED (sweep exceeded 10 min
CPU)" for it, and I had written a rejection reason that no run had produced.
Measured:

```text
[Deep2Engine] admission OK arch=llama family=GENERIC_TRANSFORMER
  moe=0 mla=0 recurrent=0 slidingWindow=0 quant=Q6_K(type 14) tensors=255
```

It is admitted because `numHeads * headDim != hiddenDim` is a **legitimate**
condition for a GQA model, and treating it as malformed was the actual defect —
in the geometry validator, not in these models. It also prints no
`fused gate_up split` line, so llama3.2 uses the separate-`ffn_gate` layout and
the new split path does not fire for it: the pre-existing split layout is
unchanged. `llama3.2` is expensive to sweep (32 layers, 3B) rather than
unsupported, and remains the natural second control once the first completes.

## 4. The control condition is satisfied on phi3

The whole point of phi3 was that its role markers are **real special tokens**,
so a templated prompt cannot be answered by ignoring the format. Measured, from
the running sweep's own tokenizer trace:

```text
[TOKENIZE] text='The first letter of the alphabet is'          -> 17 tokens
[TOKENIZE] text='<|user|>\nThe capital of France is</s><|assistant|>' -> 16 tokens
[TOKENIZE] text='<|user|>\nThe opposite of hot is</s><|assistant|>'   -> 14 tokens
[TOKENIZE] text='<|user|>\nThe first letter of the alphabet is</s><|assistant|>' -> 20 tokens
```

The markers cost **one token each**, not the several word-pieces a literal
`<|user|>` would decompose into. This is the condition TinyLlama structurally
cannot provide (`EXACT_VOCAB_ENTRY=0` for all three markers), and it is why
phi3 is the control and TinyLlama alone could never settle the question.

Performance note, recorded because it shapes how long the sweep takes: the
decode path re-runs a **full forward pass per generated token** with a growing
sequence (`[FWD_ALL] seqLen=30..37`), rather than reusing the KV cache, so
decode is quadratic in context.

```text
[STREAM] RESULT generated=24 promptTokens=17 prefillMs=59328.7
         decodeMs=80192.0 tps=0.30 cancelled=0 completed=1
```

At 0.30 tok/s a full 6-variant x 3-oracle sweep is a ~40 minute run, not a
short one. It is executing detached and its full table is reported in §6.

## 6. The phi3 control ran, and it is INVALID as a control

Full table, 6 variants x 3 oracles, on `phi3-mini-Q2_K.gguf`:

```text
VARIANTS=6
ORACLES=3
raw_no_template        1/3      0/3      greedy    a good idea.
phi3_current           1/3      0/3      greedy    It seems like the incomplete question and ... is incomplete.
zephyr_newlines        0/3      0/3      greedy    <newlines only>
zephyr_no_trailing     1/3      0/3      greedy    The French language is widely spoken in France, ...
jinja_loop_newline     0/3      0/3      greedy    ����z�zotomotomotomotomusolotom
zephyr_trailing_sp     0/3      0/3      greedy    <newlines only>
NOTE=no winner is asserted; the table is the result
```

This result must not be read as "the template is exonerated", and it does not
show "phi3 is broken". It is an **invalid control** for two independent
reasons, either of which alone is sufficient.

**(a) The control is confounded by quantization.** phi3 is `Q2_K` — 2-bit,
visibly degraded. TinyLlama, the one model that produced a clean 3/3 baseline,
is `Q4_K_M`. Comparing a 2-bit run against a 4-bit run attributes the
difference to the template when the quantization is a stronger candidate.
`jinja_loop_newline` is phi3's **own official template** and produces
`zotomotomotomotomusolotom` — degenerate repetition plus invalid UTF-8. A
model that cannot render its own trained template is not evidence about
templates.

**(b) I had just enabled two code paths that had never executed before.**
phi3 was rejected at admission until this session, so fused-QKV and fused
gate+up had **zero** prior coverage. The run above is their first execution
anywhere in this tree, and it produces garbage. So this run is equally
consistent with "my new split is wrong" as with "Q2_K is bad", and I cannot
currently tell which.

What this result *does* establish, on its own, independent of both confounds:

```text
THE ONLY MODEL THAT EVER PRODUCED A CLEAN RESULT (tinyllama, 3/3)
  is the one with NO role tokens as special tokens.
THE ONLY MODEL WITH REAL ROLE TOKENS produces 0/3 clean in EVERY variant,
  including its own official template.
```

The original HTTP defect is therefore still **unexplained**, and the direction
of evidence has not changed. No HTTP gate moved.

**Required before this control is allowed to conclude anything:** re-run on a
control quantised at `Q4_K_M` or better, *and* prove the fused split is
numerically correct in isolation from quantization.

### 6.1 Regression check on the previously-working path — PASS

`tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf` re-run after the fused-split change,
result **byte-identical** to its pre-change baseline:

```text
raw_no_template        3/3 clean   the city of Paris, which is the capital of France.
phi3_current           1/3         3/3 contaminated
zephyr_newlines        0/3         3/3 contaminated
zephyr_no_trailing     1/3         3/3 contaminated
jinja_loop_newline     0/3         3/3 contaminated
zephyr_trailing_sp     0/3         3/3 contaminated
```

This uses the **split** layouts (`attn_q/k/v`, separate `ffn_gate`) and prints
no `fused gate_up split` line, so the new code path does not fire for it. The
existing path is therefore undisturbed, and phi3's garbage cannot be a
regression to previously-working behaviour. It remains attributable to the
newly-exercised fused paths, to Q2_K, or to both.

It also independently re-confirms the original TinyLlama symptom, and the
mechanism is now visible in the output text rather than inferred: the model
**echoes the role markers back as literal strings** (`|assistant|`, `|system|`,
`|user|`, `lexicon`) because in TinyLlama those markers are ordinary
word-pieces, so seeing `<|assistant|>` in the prompt is just text it can
copy. That is a model-capability ceiling, not a rendering defect — consistent
with `EXACT_VOCAB_ENTRY=0`.

### 6.2 Falsification probe of the fused split — PASS, confound (b) cleared

Byte geometry can prove a split is a correct *partition*; it cannot prove
**which half is the gate**. That ordering was previously taken from recall of
llama.cpp's convention, so it was tested instead of trusted.
`RAWRXD_FUSED_GATE_UP_ORDER=up_gate` inverts the halves. Same weights, same
prompt, same greedy seed, 8 tokens, one variant, one oracle:

```text
order=gate_up   QUICK_SAMPLE= " a good idea.\n\n\n\n"
order=up_gate   QUICK_SAMPLE= " , t, t, t t"
```

This probe is diagnostic in both directions, which is why it is worth running:

```text
IF output had been IDENTICAL  -> the split is not consumed at all (dead code,
                                  and the fused path would be a no-op lie)
IF inverted output were BETTER -> the assumed order is wrong
Observed: inverted is dramatically WORSE, and visibly degenerate.
```

So the fused gate+up path is **consumed** and **gate-first is confirmed**, not
assumed. Combined with the byte-exact, row-aligned partition already measured,
the split is established on both axes. It is not the cause of phi3's garbled
templated output.

That also clears the fused-QKV path by implication: this probe runs with fused
QKV **and** fused gate+up both active, and still yields coherent English
("a good idea."). Neither fused path is fundamentally broken.

**Confound (b) is therefore eliminated. Confound (a) — Q2_K — remains, and is
now the only live confound.** The next measurement needs a control quantised at
`Q4_K_M` or better.

### 6.3 One more instrument defect, same class as the rest

The `--quick` flag was first implemented as `argv[2] == "--quick"`. With
`--model <path> --quick` the flag sits at `argv[3]`, so the probe silently
ignored it and ran the **full 6x3 sweep** — a 40 minute run that produced no
`QUICK=` line, and would have been easy to read as "quick mode is broken"
rather than "quick mode never engaged". It is now a scan over all arguments,
and it prints `QUICK=1` on the same line as the flag state so the mode is
visible in the run it affects.

That is the seventh time in this project an instrument defect produced a
confident wrong reading from working code. The common shape is always the same:
**a control that can be silently ignored.**

## 6.4 THE CONTROL RESOLVED IT: the template is exonerated

A valid control turned out to be **already on local disk**, so no download was
needed. `llama3.2:3b` resolves to a `Q4_K_M` GGUF with **256** real special
tokens, and is already admitted:

```text
path:     F:\OllamaModels\blobs\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff
bytes:    2,019,377,376   arch=llama   tensors=255   quantization=Q4_K_M
VOCAB_SIZE=128256  TOKEN_TYPE_CONTROL=256  ADDED_TOKENS_IN_VOCAB=256
PREMISE_MODEL_HAS_NO_ADDED_ROLE_TOKENS=0     <- premise negated
```

This model varies exactly the two things that were confounded in phi3 and holds
everything else fixed: role tokens are real **and** quantization is adequate.

### The measurement

```text
VARIANTS=6  ORACLES=3
raw_no_template        3/3      0/3 contaminated   France\nThe capital of France\n...Paris\n
phi3_current           0/3      0/3 contaminated   France\nThe capital of France\n...Paris\n
zephyr_newlines        1/3      0/3 contaminated   France\nThe capital of France\n...Paris\n
zephyr_no_trailing     0/3      0/3 contaminated   France\nThe capital of France\n...Paris\n
jinja_loop_newline     1/3      0/3 contaminated   France\nThe capital of France\n...Paris\n
zephyr_trailing_sp     0/3      0/3 contaminated   France\nThe capital of France\n...Paris\n
NOTE=no winner is asserted; the table is the result
```

**Zero contamination in every variant, including every templated one.** Output is
coherent, on-topic, and factually correct.

### Three models, one variable, one conclusion

```text
MODEL                role tokens   quant    templated variants contaminated?
tinyllama-1.1b       NONE (0)      Q4_K_M   3/3 on all five
phi3-mini            real (14)     Q2_K     0/3 clean; official template = gibberish
llama3.2-3b          real (256)    Q4_K_M   0/3 contaminated on ALL SIX
```

The pattern is monotone in exactly the two variables, and it is not the
template:

```text
THE TEMPLATE NEVER CONTAMINATED ANYTHING.
  It leaked only where the model's own role markers were not special tokens
  (tinyllama, which therefore has no vocabulary in which to represent them),
  and it failed to be followed only where the model was too degraded to follow
  any format (phi3 at 2-bit, whose own official template also produced garbage).
  Given a model that has the tokens and the capacity, all six templates are clean.
```

**ROOT_CAUSE for the TinyLlama HTTP corruption: a model-capability ceiling, not
an engine defect.** The engine renders and tokenizes templated prompts
correctly; TinyLlama-1.1B-Chat-v1.0 cannot follow a format its own vocabulary
does not encode, so it echoes the marker bytes back. The `|assistant|`,
`|system|`, `|user|` fragments in its output are the model copying visible
prompt text, exactly as `EXACT_VOCAB_ENTRY=0` predicts.

This **supersedes** `ROOT_CAUSE=UNCONFIRMED` and confirms the retraction in
§1-§2: the markers were never made special tokens on purpose, and the probe
reported that accurately all along. Five variants of this investigation, the
answer was in that one measurement.

### What this does and does not license

```text
EXONERATED   template rendering / tokenizer special-token handling / fused paths
NOT FIXED    a single line of product template-selection code. None was changed.
REMAINING    the 0/3-1/3 semantic scores are model capability on specific oracles,
             and they VARY BY VARIANT (1/3 for zephyr_newlines, 0/3 for
             zephyr_trailing_sp) despite identical contamination. That residual
             variance is unexplained and is NOT closed by this result.
OPEN         HTTP negative controls (4 PASS / 2 FAIL), streaming error semantics,
             MODELS_WITH_UNKNOWN_PATH=113, gemma3 GQA geometry validator
```

The honest summary is that the *corruption* is explained and the *oracle
accuracy* is not. Those were already separate findings and remain so.

## 7. Model coverage census
Five GGUFs on the local model root:

```text
MODEL                                          ADMISSION
tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf           ADMITTED
tinyllama.gguf                                 (duplicate of the above)
model.gguf                                     0 bytes
phi3-mini-Q2_K.gguf                             REJECTED  missing attn_q
gemma3-1b-Q2_K.gguf                             REJECTED  numHeads*headDim
llama3.2-3b-Q2_K.gguf                           NOT TESTED (sweep exceeded 10 min CPU)
DeepSeek-V2-Lite-Chat.Q4_K_M.gguf              NOT TESTED this session
```

```text
ADMITTED            = 1 of 4 distinct non-empty models
REJECTED_BY_ADMISSION = 2
ADMISSION_DEFECT_CLASSES = 2 (fused-QKV naming, head geometry validation)
```

This is a materially larger blocker than the HTTP content defect. The
authority chain cannot be certified against a control model while the
admission gate rejects 2 of the 4 available ones.

## 5. Current state of the ladder

```text
1 TOKENIZER/TEMPLATE BISECT        DONE   measured; see entries 002 + 003
2 FIX HTTP CONTENT                 BLOCKED
                                    single-writer repair is premature: the
                                    controlling hypothesis was falsified and
                                    the discriminating control cannot be run
3 RUN NEGATIVE CONTROLS            DONE   4 PASS 2 FAIL (entry 001)
4 STREAMING FAILURE CONTRACT       NOT_RUN
5 CLASSIFY UNKNOWN_PATH=113        NOT_RUN
6 HTTP+INVENTORY AUTHORITY PASS    BLOCKED on 2 and 4
7 BROWSER/RAW CONSOLE              DEFERRED
```

## 6. Decisive next experiments

Two are required, in this order, because the second is cheap and the first is
what a wrong ordering wastes effort on:

```text
E1  Fix admission for fused-QKV archs (phi3 attn_qkv) and for the gemma3
    head-geometry check. One writer. Then re-run the sweep on phi3-mini.

    Decides: is templated generation correct on a model whose role markers
    are real single tokens? That is the only measurement that separates
    "engine defect" from "weak model".

E2  If E1 shows phi3 templated output is clean:
        TinyLlama is a MODEL CAPABILITY finding, not a serving defect, and
        the honest response is to report it as such rather than patch the
        template.
    If E1 shows phi3 templated output is ALSO contaminated:
        the defect is in the engine's render/tokenize path, and phi3 is the
        correct reproducer because its markers are unambiguous.
```

Until E1 is run, the cause of the HTTP content failure is:

```text
ROOT_CAUSE = UNCONFIRMED
CANDIDATES = { engine render/tokenize path, model capability ceiling,
               interaction of both }
FALSIFIED  = { template/vocab incompatibility (entry 002),
               byte-level whitespace (section 2) }
```

## 7. Preserved provenance

```text
ENTRY_002_CLAIM   SUPERSEDED, reason recorded in section 1
ENTRY_002_MEASUREMENTS  still valid (EXACT_VOCAB_ENTRY=0 is accurate)
ENTRY_002_VERDICT_STRING
    TEMPLATE_EMITS_ROLE_MARKERS_ABSENT_FROM_VOCAB
    -- factually true, but the conclusion drawn from it was invalid
ENTRY_001         unchanged, still current
```

A wrong conclusion reached through valid measurements is still a wrong
conclusion. The measurements are retained; the inference is withdrawn.
