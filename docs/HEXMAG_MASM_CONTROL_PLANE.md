# HexMag MASM Control Plane (weightless)

Canonical orchestration for RawrXD is **x64 MASM**, not the FastAPI `/ask` wrapper.

```text
HEXMAG_SWARM_CONTROL_PLANE = MASM
HEXMAG_PYTHON_TREE         = REFERENCE/CI

HEXMAG_WEIGHTED_MODEL      = FALSE
HEXMAG_GENERATOR           = TRUE
HEXMAG_CODEGEN_PRIMARY     = FALSE

HEXMAG_WORK_UNIT           = EPHEMERAL_RESPONDER
HEXMAG_TOPOLOGY            = QUESTION_CONDITIONED
HEXMAG_GROWTH              = TRANSIENT
HEXMAG_WEIGHT_GROWTH       = ZERO

HEXMAG_AGENT               = ACT/VERIFY
HEXMAG_RESPONSE_GEN        = ANSWER/REVERSE/VERIFY

HEXMAG_MISSING_INFO        = ASK_USER
HEXMAG_COMPUTATIONAL_FAIL  = GROW
HEXMAG_VERIFIED            = FINALIZE
HEXMAG_AFTER_FINAL         = DEFLATE
```

## Contract vs implementation status

```text
HEXMAG_GENERATE_ON_CONTACT=TRUE
HEXMAG_RECURSIVE_REFINEMENT=COMPLETE      # candidate→reverse→tuner→final→deflate
HEXMAG_FAILURE_DRIVEN_RESPAWN=COMPLETE
HEXMAG_POST_FINAL_DEFLATION=COMPLETE
HEXMAG_POLYMORPHIC_GEN=TRUE               # each spawn = unused agent/model id
HEXMAG_REPEAT_TUNER=TRUE                  # MASM RawrXD_HexMag_RepeatTuner.asm

HEXMAG_EPHEMERAL_RESPONDERS=TRUE
HEXMAG_PERSIST_RESPONDERS=FALSE
HEXMAG_DYNAMIC_INFLATION=TRUE
HEXMAG_POST_REQUEST_DEFLATION=TRUE
HEXMAG_TRANSIENT_STATE_AFTER_FINAL=0
persistent_weight_delta_bytes=0

HEXMAG_FAILURE_DRIVEN_GROWTH=TRUE
HEXMAG_REVERSE_VALIDATION=TRUE
HEXMAG_UNSUPPORTED_CLAIM_EMISSION=FALSE
HEXMAG_MISSING_INFORMATION_ACTION=ASK_USER
```

Smoke certifies Architect → Codegen → Verification **plus** polymorphic unused
agent minting and failure-directed repeat tuning (wrong → mutate genome → new
`generation_id` → new agent → converge). See
`docs/HEXMAG_POLYMORPHIC_REPEAT_TUNER_001.md`.

## Layers

| Layer | Location |
|-------|----------|
| Control plane (canonical) | `src/asm/RawrXD_HexMag_Swarm.asm` |
| C++ mirror | `src/core/hexmag_swarm.hpp` |
| Actions / finalize classes | `src/agentic/HexMagAction.hpp` |
| Runtime mode toggle | `src/agentic/AgentRuntimeController.hpp` |
| Smoke | `tests/hexmag_swarm_smoke.cpp` |
| Architecture V2 | `docs/HEXMAG_ARCH_V2.md` |
| Python reference | `RawrXD-ModelLoader/services/hexmag/` |

```text
HexMag Swarm
= no learned weights / tokenizer / inference math / model dependency
= question-conditioned ephemeral responders
= generate-on-contact (contract); recursive loop INCOMPLETE on MASM
```

## Label split

```text
llm.answer.candidate  ≠  llm.answer.final
```

First-answer-wins is legacy Python `/ask` compatibility only.

## Target event progression

```text
llm.question
    ↓
hexmag.contact → hexmag.plan → hexmag.responder.spawn
    ↓
llm.answer.candidate
    ↓
hexmag.reverse → hexmag.critique
    ↓
  COMPUTATIONAL fail → hexmag.responder.spawn ↺
  INFORMATION deficit → hexmag.need_input → user → resume
    ↓
hexmag.verify → llm.answer.final → hexmag.deflate
```

## Next implementation target (MASM)

**Not** more Python bot specialization.

Implement on the control plane:

```text
candidate → reverse → spawn/refine → final → deflate
```

When that loop is demonstrated in smoke, flip:

```text
HEXMAG_RECURSIVE_REFINEMENT=COMPLETE
HEXMAG_FAILURE_DRIVEN_RESPAWN=COMPLETE
HEXMAG_POST_FINAL_DEFLATION=COMPLETE
```

## Certification (current smoke)

```text
HEXMAG_SWARM_CONTROL_PLANE = CERTIFIED   # fixed handoff chain
HEXMAG_WEIGHTED_MODEL      = FALSE
HEXMAG_GENERATE_ON_CONTACT = TRUE        # contract
HEXMAG_RECURSIVE_*         = INCOMPLETE  # measurable gap
DEEP2_PARITY_AUTHORITY     = UNCHANGED
```

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Smoke-HexMagMasm.ps1
```

## API

- `HexMag_Init` / `HexMag_Shutdown`
- `HexMag_SubmitGoal` / `HexMag_Step` / `HexMag_PollEvent` / `HexMag_RunToSatisfied`
- `HexMag_BotCount` / `HexMag_GetState`

**Deps:** `VirtualAlloc` / `VirtualFree` / `OutputDebugStringA` only.

```text
HexMag = who / which ephemeral responders run next
Deep2  = whether neural execution is correct   (separate track)
```

Do not blame HexMag for Deep2 tokenizer or Q4_K failures.
AGENT-E2E-002b TinyLlama tool-emission FAIL remains valid and separate.
