# RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001

**Status:** PASS (71/71), bound to production, falsification-proven four times,
measured against real model weights
**Date:** 2026-10-02
**Authority:** `include/agentic/ModelToolProtocol.h`, `src/agentic/ModelToolProtocol.cpp`
**Harness:** `tools/model_tool_protocol_cert.cpp` -> `model_tool_protocol_cert`
**Diagnostic:** `tools/mtp_false_positive_probe.cpp` (`--classify <file>`)
**Receipt:** `receipts/RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001/RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001_LAST.ini`

## 1. The gap, measured rather than asserted

RawrXD had exactly one tool protocol. `ToolRegistry::BuildSystemPrompt()` taught
every model the same grammar:

```
<<<TOOL:tool_name|{"param":"value"}>>>
```

`StreamingToolParser` could read back only that grammar. The canonical REPL
(`src/agentic/AgentToolOrchestrator.cpp`) branched on one thing: did the
streaming parser see a tool block. If not, the turn was treated as **the model's
final answer**.

So for any model not trained on that convention:

```text
model has no tool-calling training
  -> emits ordinary text
  -> parser sees no <<<TOOL:
  -> TurnOutcome::Completed
  -> agent silently degrades to a chat completion
```

Nothing reported this. The run said `success=1`, `turns=1`, `tools_executed=0`,
and the transcript looked like a model that chose to answer instead of a model
that *could not* call a tool. A capability gap reported as a model preference —
the same class of defect as the 2026-10-01 marker-leak finding: a limitation the
instrument had no field for.

Census of the existing surface, all real code, none sufficient:

| surface | what it covered | what it could not |
|---|---|---|
| `StreamingToolParser` | 1 dialect (`<<<TOOL:>>>`), streaming, correct | 0 other dialects, 0 inference |
| `ToolRegistry::BuildSystemPrompt` | 1 grammar, taught unconditionally | cannot know if the model learned it |
| `AgentOrchestrator` | execute, replay, resume | 1 parse path, no model identity, no agency |
| `src/sovereign/puppeteer/*` | JIT / self-modification | unrelated: binary patching, not tool intent |
| `*Hotpatch*` across the tree | x86 address patching | no model-keyed adaptation existed |

"Puppeteer" in this tree meant a JIT assembler. There was no layer that
puppeteers a *model*.

## 2. What was added

```text
NATIVE TOOL MODEL
    -> native tool-call parser (5 trained dialects)
    -> tool execution -> observation -> resumed inference

NON-TOOL MODEL
    -> puppeteering layer (constrained, validated intent extraction)
    -> tool execution -> observation -> resumed inference

INCOMPATIBLE / QUIRKY MODEL
    -> model-keyed hotpatch (prompt rewrites + output marker stripping)
    -> puppeteering -> same canonical agent runtime
```

### Tier selection is from evidence, never from a claim

```ini
NATIVE      a live probe observed a trained-protocol marker
PUPPETEER   unmeasured, or a probe ran and the model did not comply
HOTPATCH    PUPPETEER plus a registered model-keyed adaptation
```

`Negotiate(id, Undeclared)` can never return `Tier::Native`. An unmeasured model
is puppeteered, because "we do not know" and "it can" are different facts and only
one of them is cheap to be wrong about.

### The honesty boundary is in the types, not in a comment

```cpp
enum class Agency {
    ModelNative,      // the marker came from the model's own training
    ModelUnmarked,    // a convention RawrXD taught and the model followed
    RuntimeInferred,  // RawrXD inferred the call from ordinary prose
};
```

`ProbeNativeToolCalling` iterates only `IsTrainedProtocolDialect(d) == true`
dialects. `RawrToolBlock` and `LegacyReAct` are excluded because RawrXD teaches
them; `InferredIntent` is excluded because RawrXD produces it. **A taught
dialect cannot report native support, by construction.**

The probe prompt offers an escape:

```
If you have no tool-calling facility, reply with exactly: NO_TOOL_PROTOCOL
```

Without it a base model hallucinates a plausible call to satisfy the
instruction, and the probe certifies a model that cannot call tools.

### Puppeteering is bounded and refuses rather than guesses

Accepted only for a **registered** tool name at a position that reads as a call.
Refusals are returned as data, never swallowed:

```text
not_a_registered_tool                              hallucinated tool
missing_required_parameter:<name>                  incomplete call
more_positional_arguments_than_declared_parameters ambiguity
unterminated_call / unterminated_tool_block        truncated stream
unterminated_quoted_argument                       unparseable argument
no_separator_between_name_and_arguments            malformed marker
tool_block_body_is_not_an_object                   marker without JSON
bare_argument_form_ambiguous_for_this_tool         bare value, multi-param tool
tool_line_without_arguments                        tool name, no value
ambiguous_bare_arguments                           tool name, several values
```

Prose that is merely call-shaped produces nothing at all — measured at
`accepted=0 rejected=0` on a paragraph of ordinary advice, so a refusal is
distinguishable from silence.

### Dielect-aware observation injection

A Hermes-trained model was trained to see `<tool_response>` back. Qwen/GLM expects
`<|observation|>`. Mistral expects `[TOOL_RESULTS]`. A puppeteered model is best
served by plain text. Replaying one fixed format to every model is how a
non-tool model ends up echoing markup into its answer, so
`BuildObservation(..., Dialect)` switches on the dialect the model actually used.

### Hotpatch

Keyed `arch/family` with per-component `*` wildcards, plus a name substring
fallback; more specific key wins. Carries `outputStrips` (special markers removed
from model output), `promptRewrites`, and `notes` injected into the
tier-appropriate prompt. `HOTPATCH_APPLIED` and `HOTPATCH_ID` ride on the
`Negotiation` and are printed in the receipt.

## 3. Production binding (not an unadopted authority)

`src/agentic/AgentToolOrchestrator.cpp`:

- `RunAgenticTask` builds its system prompt from
  `BuildToolInstructions(defs, negotiation, hp)`. A native-tier prompt contains
  **no grammar on purpose** — re-teaching a model its own protocol is how it
  starts emitting the wrong marker.
- `RunTurn` keeps the streaming parser as the fast path for the Rawr dialect (it
  is correct and already there) and then resolves **every other protocol** from
  the finished assistant text. Only the first accepted call runs: an unproven
  model plus an unproven multi-call chain is how a hallucinated tool becomes a
  real one.
- `TurnResult` carries `toolDialect` + `toolAgency`; `AgentRunReport` carries
  `toolCallsNative/Unmarked/Inferred`, `protocolTier`, `nativeSupport`,
  `tierReason`, `observationTruncatedChars`, `contextMessagesDropped`.
- The assistant replay for an inferred call is what the model actually said, not
  a reconstructed marker, because there was no marker to reconstruct.
- `ProbeNativeSupport()` runs the native probe through the bound backend and
  records what the model emitted (section 7).

`src/agentic/AgentToolRegistry.cpp` gained `GetDefs()` so the authority validates
against the **installed** tool set, in the same name order as the prompt.

CMake: `src/agentic/ModelToolProtocol.cpp` added to `INFERENCE_ENGINE_SOURCES`.
It is required by the target, not optional — the loop calls into it.

## 4. Three real defects the new gate found

None was in the new code. Two were in the loop the new gate exercises; the third
was in the measurement itself.

### 4.1 A tool observation could be dropped, and the run still said success

`AgentStateManager::BuildContextWindow` pinned the system message and **the last
message**. After a tool turn the last message is the observation, so the user's
question was no longer pinned and became the first droppable message. With one
large observation the drop loop removed everything, including the observation:

```text
read_file("F:\~dev\AGENTS.md")  ->  ~58 kB observation against a 16 kB budget
  -> drop loop (oldest-first, all unpinned)
  -> the user's question dropped
  -> the model's tool call dropped
  -> the OBSERVATION dropped
  -> next turn: inference resumes having never seen the tool's answer
  -> report: success=1, tools_executed=1
```

Measured after the fix: `truncated_chars=58149 dropped=1` and the observation is
present in the resumed prompt.

Fix: pin the newest User **and** the newest Tool by role rather than position; if
pinned content alone still exceeds the budget, truncate the newest observation
from the end with the character count lost stated, and count the loss in the run
report. A budget that cuts content must make the cut visible; dropping the
observation makes the run wrong and quiet.

### 4.2 The bare-argument form was read as a model error

`FillFromObject` only understood the wrapped form `{"name":..,"arguments":{..}}`.
Rawr's own block, ReAct's `Action Input`, and a puppeteered `name{...}` carry the
arguments as the object itself. Those produced a call with a name and **no
arguments**, which then failed validation as `missing_required_parameter:path` — a
refusal that looks like the model forgot a parameter rather than the parser
missing a rule. The first certification run failed 7 checks for this reason.

Fix: after the wrapped lookup yields nothing, treat the remaining non-meta keys as
the argument set.

This is a **runtime behaviour change inside tool-call markers**, not a parser-only
cleanup, and section 5 measures exactly how far it reaches.

### 4.3 The refusal counter counted 1 while six refusals happened

Third defect, and the first in the *measurement* rather than the measured.
`AUTHORITY_INTENTS_REJECTED` was incremented on the tool-lookup and `Validate`
paths only; the parse-error and empty-name paths pushed into `res.rejected`
without counting. The receipt read `1` on a run in which the harness had just
produced six refusals.

This is the 2026-10-01 pattern exactly: **a census that undercounts is worse than
one that fails loudly**, because it converts a real finding into silence. Fixed by
funnelling every refusal through one `refuse()` path, and pinned by
`counter.rejections_are_all_counted`.

## 5. False-positive battery (`tools/mtp_false_positive_probe.cpp`)

The 46-check suite had a known blind spot: **all six of its negative controls
were written after the author already knew the answer.** They confirm the
behaviour of fix 4.2; they do not test whether that fix changed what can execute.

Fix 4.2 reads like a widening: it applies inside six scanners, and it appears to
turn

```json
{"name": "read_file", "path": "C:\\Windows\\System32\\config\\SAM"}
```

from a refusal into an execution. That is a configuration dump, not a call.

### The hypothesis was wrong

```text
UNEXPECTED_EXECUTIONS=0
HYPOTHESIS_DISPROVED=bare_form_fallback_widens_executable_surface
```

`FillFromObject` is reachable **only** from the marker-delimited scanners. Bare
JSON in prose carries no marker, so no scanner ever reads it:

```text
bare.config_dump_registered_name    want=REFUSED  got=SILENT
bare.name_only_no_args              want=REFUSED  got=SILENT
bare.tool_schema_fragment           want=REFUSED  got=SILENT
```

The paths that do reach the fallback all behave correctly:

```text
match marker.bare_element_in_tool_calls  ACCEPTED  OPENAI_TOOL_CALLS  MODEL_NATIVE
match marker.bare_object_in_rawr_block   ACCEPTED  RAWR_TOOL_BLOCK    MODEL_UNMARKED
match marker.hermes_non_tool_payload     REFUSED   not_a_registered_tool
match marker.hermes_schema_not_call      REFUSED   missing_required_parameter:path
```

Inside a marker the fallback **does** change behaviour — those four cases were
`missing_required_parameter` refusals before the fix and are accepted after it.
That is a real behaviour change, and it is correct: the model wrote an explicit
tool-call marker, so a bare object in that position is a call. The blast radius is
bounded by the markers.

### Two residual signal-quality items, both safe-direction, neither fixed

1. `marker.hermes_schema_not_call` refuses for the wrong reason. The fallback
   turned `properties` into an argument, so the refusal came from argument
   validation rather than from recognising a JSON Schema. It refused; the receipt
   states a misleading reason.
2. `echo.real_system_prompt` manufactures a refusal. The runtime's own prompt
   teaches `tool_name(arg1="value", arg2="value")`; when a model echoes the rules
   block back, the authority records `REFUSED name=tool_name
   reason=not_a_registered_tool`. Nothing executes, but refusals were designed to
   be a trustworthy signal and the runtime is polluting it with its own
   placeholder. Small models echo the system prompt, and this project already has
   a measured marker-leak finding.

Neither is a security defect. Both are unfixed and undecided.

### The instrument failed before the code did

The first run reported `DISAGREEMENTS=11` out of 11, including two cases whose
printed `want` and `got` were visibly identical:

```text
positive.real_inferred_call   want=ACCEPTED got=ACCEPTED     <- reported DISAGREE
positive.native_marker        want=ACCEPTED got=ACCEPTED     <- reported DISAGREE
```

`got == want` compared `const char*` **addresses**, not string contents. The
corrected result is 5 disagreements, and the two properties are now reported
separately so a safe refusal cannot be read as a missed execution:

```text
DISAGREEMENTS=5
UNEXPECTED_EXECUTIONS=0
SIGNAL_DISAGREEMENTS=5
```

The three `bare.*` expectations are recorded as written, not updated to `SILENT`.
The security property under test — a non-call text must never cause an execution —
held in every case. The expectation was about signal quality and was
mis-specified, and mis-specifying an expectation is worth recording rather than
quietly editing.

## 6. Battery folded into the certification

The battery runs inside `model_tool_protocol_cert`. Two axes are kept separate per
case, both printed side by side:

```text
pinned=     what the implementation does today, so a future widening surfaces as
            a failure instead of a surprise
predicted=  what the security analysis said, written BEFORE execution
```

Where they differ, the analysis was wrong and the difference is preserved rather
than edited away.

The security invariant is stated as its own check so editing a pinned value cannot
quietly remove the protection:

```text
PASS battery.no_non_call_text_executes   unexpected_executions=0 cases=19
```

`battery.echo.real_system_prompt` also earns its keep as a tripwire: it feeds the
*real* prompt built by `BuildToolInstructions` back in. A future edit that adds a
worked example using a real tool name would turn the prompt into an execution
path, and that check fails on the day it happens.

### Third falsification probe — revert fix 4.2

```text
FAIL battery.marker.bare_element_in_tool_calls  pinned=ACCEPTED got=REFUSED
FAIL battery.marker.bare_object_in_rawr_block   pinned=ACCEPTED got=REFUSED
FAIL dialect.rawr.tool_block / react.action / puppeteer.braced
FAIL agency.taught_marker_is_not_native
FAIL falsification.puppeteer_off_removes_inferred_calls
FAIL crosscheck.authority_agrees_with_streaming_parser
CHECKS_FAIL=8   VERDICT=FAIL
```

Both battery pins fail, and so do five pre-existing checks written against the
fixed behaviour. `battery.no_non_call_text_executes` still held, correctly:
removing the fallback narrows execution, never widens it.

The probe itself failed once before it worked. `getenv("RAWR_MTP_BARE") != nullptr`
is true when the variable is set to the string `"0"`, so the first attempt
disabled nothing and the suite passed at 62/62 while claiming to be falsified. The
variable had to be *unset*. A falsification probe that silently fails to falsify is
indistinguishable from a passing one.

## 7. Real models, measured (2026-10-02)

`NATIVE_TOOL_CALLING` was `UNDECLARED` for the whole life of this gate, and it
could never have been anything else: `ProbeNativeToolCalling` and
`BuildNativeProbePrompt` existed but **nothing in the tree could call them** with a
real reply. That is the same orphan-authority finding the 2026-10-01 ledger
recorded against `RAWRXD_SINGLE_WRITER_AUTHORITY_001`.

Two gaps were closed: a `--classify <file>` mode that turns a model reply into a
measured value, and `AgentOrchestrator::ProbeNativeSupport()` in production.

### Evidence

Server: `deep2_openai_server.exe` SHA256 `A37484B1…`, dated **2026-09-27** — five
days before the current tree, which has 315 modified files. The measurement is
therefore bound to *that binary's* inference path, not to the current build, and
the receipt prints the binary hash so a PASS cannot later be read as covering a
path it was never run against.

| model | probe | `NATIVE_TOOL_CALLING` | accepted | markers leaked | would execute |
|---|---|---|---|---|---|
| `tinyllama-1.1b-chat-v1.0.Q4_K_M` | native | `UNSUPPORTED` | 0 | 0 | 0 |
| `tinyllama-1.1b-chat-v1.0.Q4_K_M` | puppeteer | `UNSUPPORTED` | 0 | **1** | 0 |
| `llama3.2-3b-Q2_K` | native | `UNSUPPORTED` | **1** | 0 | **1** |

**The capability works on a real model.** llama3.2-3b returned exactly:

```
read_file("AGENTS.md")
```

in no trained dialect. `ProbeNativeToolCalling` correctly refused to call that
native — there is no marker in it — and the puppeteer tier accepted and executed
it as `RUNTIME_INFERRED`. The design rule working on real weights: a model with no
tool-calling training still participates in the loop.

**TinyLlama cannot participate, and the reason is the model.** Given the exact
puppeteer instructions it produced:

```
1. Use only tools listed in AGENTS.md.2<|user|>
Can you provide me with the list of tools that are listed in AGENTS.md?</s>
```

It invented a user turn, asked a question back, and never wrote a call. A 1.1B
chat model does not follow a one-line output convention. No tier reaches it, and
no runtime work changes that.

### Two inversions in the marker classifier, found by inspecting bytes

The first version used one flat list of special tokens and called every occurrence
a leak. Checking the raw bytes of the llama3.2 reply showed that is wrong in
**both** directions:

- `read_file("AGENTS.md")<|eot_id|>` was counted as leaking. `<|eot_id|>` is that
  model's legitimate end-of-turn token and it arrived trailing. The reply was
  clean, the runtime executed it successfully, and the diagnostic printed
  `UNSUPPORTED_AND_LEAKING_MARKERS` — a defect manufactured in the instrument.
- The TinyLlama puppeteer reply contains a genuine mid-text structural leak
  (`<|user|>`, the model inventing a user turn). The flat list did not contain
  that token, so the run counted the trailing `</s>` instead and reported the right
  number for the wrong reason.

Corrected rule: a role/turn marker appearing as **content** is a leak; a
terminator appearing only as the **final** token is correct behaviour. Corrected
numbers are 0 / 1 / 0, and the llama3.2 verdict moved from
`UNSUPPORTED_AND_LEAKING_MARKERS` to `UNSUPPORTED`.

### Probe adoption

```text
PASS probe.no_backend_leaves_support_untouched        support=UNDECLARED
PASS probe.compliant_backend_is_native                support=PASS tier=NATIVE
PASS probe.real_reply_is_unsupported_not_native       support=UNSUPPORTED tier=PUPPETEER
                                                      reply=[read_file("AGENTS.md")]
PASS probe.unsupported_model_still_joins_the_loop     tool=read_file agency=RUNTIME_INFERRED
```

`ProbeNativeSupport()` refuses and leaves `nativeSupport_` untouched when no
backend is bound, a task is running, or the backend throws — an exception is not a
measurement. The last check replays the real llama3.2 reply verbatim.

### The defect the real models exposed inside the capability itself

Measuring a real model found the failure this capability was built to eliminate,
reproduced inside the capability. TinyLlama answered a call request with:

```
read_file AGENTS.md
```

No brackets. One bare value. Classified by the runtime as:

```text
INTENTS_ACCEPTED=0
INTENTS_REJECTED=0          <- total silence
```

Silence is the one outcome the design forbids. A refusal nobody records is
indistinguishable from a model that had no intent, so the loop degrades to a chat
completion and the transcript reads as a model that chose to answer — the exact
failure that motivated the whole tier mechanism, now occurring one layer in.

The accepted shapes were written for a model that follows a one-line output
convention. A 1.1B chat model does not, and the parser had no answer for what it
actually writes.

**Fix: the bare-argument form**, accepted only under three conditions:

- the line **begins** with a registered tool name;
- exactly one value follows it;
- the tool declares **exactly one** parameter, so the runtime never has to invent
  which parameter the value belongs to.

Anything else on such a line is a measured refusal, never silence:

```text
bareargs.real_tinyllama_bare_value       ACCEPTED  bare_argument_form_accepted_by_the_runtime
bareargs.two_param_tool_single_word      REFUSED   bare_argument_form_ambiguous_for_this_tool
bareargs.tool_name_alone_on_line         REFUSED   tool_line_without_arguments
bareargs.prose_sentence_about_a_tool     REFUSED   ambiguous_bare_arguments
```

Re-classifying the same verbatim real reply:

```text
before:  INTENTS_ACCEPTED=0  INTENTS_REJECTED=0   PUPPETEER_WOULD_EXECUTE=0
after:   INTENTS_ACCEPTED=1  ACCEPTED tool=read_file dialect=INFERRED_INTENT
                                       agency=RUNTIME_INFERRED
         PUPPETEER_WOULD_EXECUTE=1
```

### The rule stays bounded, and that is asserted

The never-be-silent rule only pays if it stays bounded. The system prompt
declares every tool on its own `Tool: <name>` line, so a scan not scoped to line
starts would turn one prompt echo into one refusal per tool and make the refusal
stream as noisy as the signal it protects. Asserted, not assumed:

```text
PASS battery.prompt_echo_does_not_flood_the_refusal_stream
     accepted=0 rejected=1  (one per tool would be 2)
```

`battery.prose_sentence_about_a_tool` is the deliberate cost: prose beginning with
a tool name produces a refusal. Some refusals are noise, and noise is preferable to
a dropped intent.

### Fourth falsification probe

Removing the bare-argument form:

```text
FAIL battery.bareargs.real_tinyllama_bare_value       got=SILENT
FAIL battery.bareargs.two_param_tool_single_word      got=SILENT
FAIL battery.bareargs.tool_name_alone_on_line         got=SILENT
FAIL battery.bareargs.prose_sentence_about_a_tool     got=SILENT
CHECKS_FAIL=4   VERDICT=FAIL
```

Every one reverts to the silence the change removed, which is the evidence that
the pins measure this behaviour rather than passing alongside it.

## 8. Certification

```text
CHECKS_TOTAL=71  CHECKS_PASS=71  CHECKS_FAIL=0  CHECKS_NOT_RUN=0  VERDICT=PASS
BATTERY_CASES=19  BATTERY_PREDICTION_MISSES=6  BATTERY_KNOWN_SIGNAL_DEFECTS=2
REAL_MODEL_PROBE_RUN=1
REAL_MODEL_MEASURED=tinyllama-1.1b-chat-v1.0.Q4_K_M=UNSUPPORTED;
                   llama3.2-3b-Q2_K=UNSUPPORTED_PUPPETEER_EXECUTES
REAL_MODEL_BINARY_SHA256=A37484B19F09186DAABDAE091144D4451F1E1FF305ED2B6467C97C23B465A046
```

Composition, 71 checks: 1 tier default, 10 dialect/agency cases, 3 explicit
agency-class checks, 7 probe + tier-discrimination checks, 6 negative controls,
1 counter census, 2 falsification controls, 5 hotpatch checks, 1 cross-check,
9 loop checks, 19 false-positive battery pins, 1 battery security invariant,
1 prompt-echo flood bound, 4 probe-adoption checks, 1 receipt.

### Cross-check against an independent implementation

The authority's `RawrToolBlock` scanner and the pre-existing
`StreamingToolParser` are separate implementations of the same dialect. On the
same input they must agree on name, on arguments, and on the text left visible:

```text
PASS crosscheck.authority_agrees_with_streaming_parser
     authority=read_file streaming=read_file path=a.cpp text=[clean]
```

One of the two is a new file; the other has been in the tree since
`RAWRXD_AGENTIC_STREAMING_TOOL_PARSER_001`. Agreement is evidence neither is alone.

### The loop's negative twin

The same scripted non-tool model, the same tool call, the same registry — with the
puppeteer tier switched off:

```text
PASS loop.negative_twin_executes_nothing   tools=0 turns=1
```

Same model, same text, opposite outcome. The tier is load-bearing.

### Certified source identities

```text
A6CAA955B83B34781AD4C04C4D84275751BB5EC68AC11895F301898A6DA51EDD  include/agentic/ModelToolProtocol.h
01F1FDA5D7D77D043B1B6C1B254B6F25C20F92CC247FCF5403DD5EE98E138D38  src/agentic/ModelToolProtocol.cpp
7EC8A6FD96A86FEDE46E0EB4523CDF221CE60A680A22FCB9FA3E696BA0EC8DCE  include/agentic/AgentOrchestrator.h
5D428A2180F56925724AF34C80F321355E4D682EA464087EF999C0513F717F8F  src/agentic/AgentToolOrchestrator.cpp
3F2C1624FC72B89D7CBDE5E2AAE1C436D11B0DD74F40F534E368EE8C9D9FB355  include/agentic/AgentStateManager.h
A2851B564AEDD57CD12B870CC5B446AC3AB830D48F43181AA836136437971977  src/agentic/AgentStateManager.cpp
A92BC28C1E3E97116CFA321FF643B655FAD789A932BCEBFE06AB53ADF35E5073  include/agentic/AgentToolRegistry.h
17EBF4C02D3909B052EFE81D0DE5F7D79211F3E83D527751321D544CDB2BCE5D  src/agentic/AgentToolRegistry.cpp
```

Certification binary: `model_tool_protocol_cert.exe`
SHA256 `71F9E8180B47514F5C6E5DF78B0B32F8B482F5C65ACE683ED57B2B70CA8C8DC4`

## 9. Honest limits

```text
REAL_MODEL_CERTIFIED=0
```

- `REAL_MODEL_PROBE_RUN=1` and the values in section 7 are measured on real
  weights. `REAL_MODEL_CERTIFIED=0` remains because **`Tier::Native` has never
  been exercised by a real model** — neither model emitted a trained marker, and
  no tool-trained model exists in `G:\~dev\rawrxd\models`. The NATIVE tier is
  implemented and certified against scripted markers only.
- The real-model evidence is bound to server binary `A37484B1…`, dated 2026-09-27
  against a tree with 315 modified files. It measures that inference path, not the
  current build.
- Three replies from two models is a small sample. It establishes that the
  capability works on a compliant model and that a 1.1B chat model cannot follow
  it; it does not characterise the distribution of model behaviour.
- The scripted model in the loop tests is a cooperative puppeteered model. A model
  that writes a call **and then does not stop** is handled by taking the first
  call only; that rule is implemented and not separately certified.
- Hotpatches are registered by the embedder. **No production hotpatch is
  registered**, so the marker-leak fix for real model output is available but not
  switched on.
- The runtime capability registry (`src/runtime/os/generated/`) was deliberately
  **not** used. Its generator emits `// TODO: hand-written ...` phase bodies from
  `capabilities.yaml`, so an entry there would be an orphan authority with
  `CAN_REPORT_PASS=0` — the finding the 2026-10-01 ledger recorded against
  `RAWRXD_STRICT_CERTIFICATION_AUTHORITY_001`. This authority is hand-written,
  bound, and measured instead.

### Record-keeping failure

This document was truncated to 0 bytes during section renumbering. The command
assigned its content from a read that had already thrown, then wrote the empty
result over the file. No git copy, sibling, or backup existed — the file was
untracked. It was reconstructed from the author's own session context, which was
complete because every section was written here.

The written lesson is AGENTS.md §7a.3 applied to a file I authored myself: an
untracked document is exactly as unrecoverable as untracked source, and the
identity of the thing being overwritten matters regardless of who wrote it. The
reconstruction is faithful to the content but this file has no SHA-256 lineage of
its own, unlike the sources it certifies.

## 10. Files

| file | change |
|---|---|
| `include/agentic/ModelToolProtocol.h` | new — authority API, tiers, dialects, agency |
| `src/agentic/ModelToolProtocol.cpp` | new — scanners, negotiation, validation, observation, bare-argument form, receipt |
| `tools/model_tool_protocol_cert.cpp` | new — 71-check certification: negative + falsification controls and the 19-case battery |
| `tools/mtp_false_positive_probe.cpp` | new — false-positive diagnostic and `--classify` for real model replies |
| `include/agentic/AgentOrchestrator.h` | `SetModelProfile`, `Protocol()`, `ProbeNativeSupport()`, `TurnResult.toolDialect/toolAgency`, report agency and truncation fields |
| `src/agentic/AgentToolOrchestrator.cpp` | tier-aware prompt; multi-dialect extraction; dialect-aware observation; agency accounting; native probe adoption |
| `include/agentic/AgentToolRegistry.h` / `.cpp` | `GetDefs()` |
| `include/agentic/AgentStateManager.h` / `.cpp` | role-based pinning; truncate-not-drop for observations; `LastTruncatedCharCount()` |
| `CMakeLists.txt` | `ModelToolProtocol.cpp` into `INFERENCE_ENGINE_SOURCES`; `model_tool_protocol_cert` target |