# RAWRXD_HTTP_TEMPLATE_ROOT_CAUSE_002

Follow-on to `RAWRXD_HTTP_AUTHORITY_CHAIN_001.md`, which closed with
`ROOT_CAUSE=NARROWED_NOT_CONFIRMED` because the discriminating vocabulary
lookup had no working instrument. This entry closes that gap by building the
instrument, running it, and recording what it measured.

```ini
BINARY      = build_dump_census\bin\http_template_marker_probe_001.exe
ORACLE      = build_dump_census\bin\http_oracle_suite_001.exe
MODEL       = G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
ARCH        = llama   VOCAB=32000   tokenizer.ggml.model=llama
TEMPLATE    = GGUF tokenizer.chat_template, 410 bytes -> ChatTemplateType::PHI3
```

## 1. ROOT_CAUSE is now CONFIRMED

The gate asked a binary question: do `<|user|>` / `<|system|>` /
`<|assistant|>` exist as single entries in this model's vocabulary? Measured
against the production `GGUFLoader` and production `BPETokenizer` — the same
loader the server reads — the answer is **no, all three**:

```text
MARKER=<|system|>
  EXACT_VOCAB_ENTRY=0   TOKEN_COUNT=6
  TOKEN_IDS=1,529,29989,5205,29989,29958
  TOKEN_PIECE=<s> | <  _<  |  system  |  |  >
MARKER=<|user|>
  EXACT_VOCAB_ENTRY=0   TOKEN_COUNT=6
MARKER=<|assistant|>
  EXACT_VOCAB_ENTRY=0   TOKEN_COUNT=7
  TOKEN_IDS=1,529,29989,465,22137,29989,29958
  TOKEN_PIECE=<s> | <  _<  |  ass  istant  |  |  >

ROLE_MARKERS_WITH_EXACT_VOCAB_ENTRY=0
BOUNDARY_MARKERS_WITH_EXACT_VOCAB_ENTRY=2     (<s>=1, </s>=2, both CONTROL)
```

Three distinct facts, and the third is what makes it causal:

```text
1  the GGUF's own template asks for a role vocabulary the vocab does not have
2  the encoder therefore fragments each marker into ORDINARY tokens
3  those ordinary fragments DECODE VISIBLY, so they are generatable text
```

```text
FRAGMENT_ID=529   SPECIAL=0  DECODED_VISIBLE=1  PIECE=_
FRAGMENT_ID=29989 SPECIAL=0  DECODED_VISIBLE=1  PIECE=|
FRAGMENT_ID=465   SPECIAL=0  DECODED_VISIBLE=1  PIECE=ass
FRAGMENT_ID=22137 SPECIAL=0  DECODED_VISIBLE=1  PIECE=istant
FRAGMENT_ID=29958 SPECIAL=0  DECODED_VISIBLE=1  PIECE=>
MARKER_FRAGMENTS_VISIBLE_ON_DECODE=6
MARKER_TEXT_IS_GENERATABLE_VISIBLE_TEXT=1
```

This closes the chain end to end. The model was asked to continue after a
boundary made of visible ordinary characters, in a language it was never
trained to speak, and it dutifully emitted those characters into the answer.
`|assistant|` in the response is not a detokenizer bug and not a special
token being rendered. It is the model reproducing visible prompt bytes.

The three-way discrimination the gate asked for:

```text
GGUF template incompatible with its own tokenizer  <-- CONFIRMED, this one
template rendering implementation wrong             <-- NO, render is faithful
tokenizer special-token handling wrong             <-- NO, <s>/</s> suppress correctly
```

## 2. The 2x2 matrix

Five deterministic oracles, greedy (temp 0, topK 1), same engine, same
weights, same seed. Only the prompt differs between columns.

```text
RAW_PASS=3  RAW_FAIL=2  RAW_CONTROL_CONTAMINATED=0
TPL_PASS=1  TPL_FAIL=4  TPL_CONTROL_CONTAMINATED=3
ORACLES_TOTAL=5

capital of France  ->  the city of Paris, which is the capital of France.
2 + 2              ->  10.00.
opposite of hot    ->  cold, cold, and the opposite of cold
first letter       ->  The word "A"
repeat zebra42     ->  0000000000000000

VERDICT=BOTH_FAIL_TEMPLATE_ADDITIONALLY_LEAKS_MARKERS
```

So the matrix is **not** the clean `PASS/FAIL -> SERVING_OR_TEMPLATE_CORRUPTION`
case. Raw prompting is also 2/5 failing, on its own terms:

- `2 + 2 =` -> `10.00` is a genuine model capability failure. TinyLlama
  Q4_K_M is not reliable at arithmetic. This is a real `FAIL` and is NOT
  attributed to the template.
- `repeat zebra42` -> `0000000000` is a genuine instruction-following
  failure on a 1.1B model.

The correct reading is two independent findings, not one:

```text
RAW 3/5   model capability ceiling, NOT a serving defect
TPL 1/5   plus 3/5 contaminated with marker text -- this IS the serving defect
```

Attributing the raw failures to the template would be the convenient error and
would be wrong.

## 3. Negative control on the instrument itself

Four defects were found in these harnesses by cross-checking printed output
against printed inputs. All four produced confident, specific, WRONG results
from working code — the pattern this project has now hit repeatedly.

```text
DEFECT  PROMPT_ENDS_WITH_ASSISTANT_MARKER=0
CAUSE   compared a 12-byte window against a 13-byte literal, "<|assistant|>"
EFFECT  reported "template does not end at marker" for a prompt that visibly
        does. Window length now derived from the literal's own .size().
        MARKER_WINDOW_BYTES=13 is printed so the value is checkable.

DEFECT  VERDICT=MARKERS_PRESENT_BUT_FRAGMENTED_BY_ENCODER
CAUSE   counted <s> and </s> as "markers found". Those are boundary tokens,
        legitimately present. The role markers -- the ones actually absent --
        were diluted into a passing count.
EFFECT  split the census into ROLE_MARKERS and BOUNDARY_MARKERS and scored
        them separately. Verdict became TEMPLATE_EMITS_ROLE_MARKERS_ABSENT_FROM_VOCAB.

DEFECT  RAW_CONTROL_CONTAMINATED=5   (all five rows, including clean ones)
CAUSE   the detector searched the marker VOCABULARY for a "|" delimiter instead
        of searching the OUTPUT for the markers. Any marker-shaped template
        makes it fire on every row.
EFFECT  it reported a constant, not a measurement. Correctly RAW_CONTROL
        CONTAMINATED=0.

DEFECT  TPL_CONTROL_CONTAMINATED=0 on " Yes, the French is a|assistant|system..."
CAUSE   the detector searched for the COMPLETE literal "<|assistant|>". The
        output contains the marker's FRAGMENTS, which is the whole mechanism.
EFFECT  a fragment-level detector was added; that row now scores 1.
        Under-reporting here was the more dangerous direction: it would have
        certified the exact symptom the gate exists to catch.
```

```text
A_DETECTIVE_THAT_MATCHES_THE_VOCABULARY_INSTEAD_OF_THE_OUTPUT_MEASURES_NOTHING
A_VERDICT_OVER_SUBMEASUREMENTS_MUST_BE_CHECKED_AGAINST_THOSE_SUBMEASUREMENTS
```

## 4. Weakness of the oracle itself, stated

Whole-word matching was substituted for substring matching. Substring
matching scored `first_letter` PASS on `"\n<|user|>\nWrite a|assistant| I's"`
because the expected `a` occurs inside ordinary words. `4` likewise matched
nothing while `10.00` would have contained no `4` but a different answer
could. Remaining limitation: whole-word matching still cannot distinguish
"The capital of France is Paris" from "Paris is wrong", and it cannot grade
prose. It catches marker leakage and gross wrongness, which is what it is for.

## 5. Certificate fields now measured, not asserted

```ini
TRANSPORT_OK                  = 1     (unchanged, already passing)
EXECUTION_REAL                = 1     (unchanged, real weights, real forward)

CONTENT_NONEMPTY              = 1
CONTENT_HAS_NO_CONTROL_TOKENS = 0     <- MEASURED, fails
PROMPT_REPLY_SEMANTIC_MATCH   = 1/5 template, 3/5 raw

ROLE_MARKERS_IN_VOCAB         = 0/3
MARKER_FRAGMENTS_VISIBLE      = 6
TEMPLATE_CONTAMINATION_RATE   = 3/5

VERDICT = FAIL_CONTENT_CORRECTNESS
ROOT_CAUSE = CONFIRMED_TEMPLATE_VOCAB_MISMATCH
```

## 6. What this does and does not authorize

```text
DOES establish   the role markers are absent from the vocabulary
DOES establish   the encoder fragments them into visible ordinary tokens
DOES establish   the model reproduces those fragments into its answer
DOES establish   RAW prompting is independently 3/5, so RAW is not a clean control

DOES NOT establish   what the correct template for this model is
DOES NOT establish   that switching templates fixes content -- NOT YET TESTED
DOES NOT establish   anything about the 113 unknown-path catalog entries
DOES NOT promote     the HTTP authority chain
```

The fix is not a code change to the detokenizer. TinyLlama-1.1B-Chat-v1.0 is a
Zephyr-style chat model whose genuine format is `<|system|>`-flavoured plain
text over an ordinary SentencePiece vocab; the template selection is choosing a
role vocabulary the file's own tokenizer cannot represent. That must be
measured against the correct target format before any code changes, exactly as
the earlier probe refused to be.

```text
STATUS = ROOT_CAUSE_CONFIRMED_REPAIR_NOT_STARTED
NEXT   = determine the format TinyLlama was actually trained with, then measure
         RAW / CORRECT-TEMPLATE / CURRENT-TEMPLATE as a three-column comparison
         before touching a single line of product code
```