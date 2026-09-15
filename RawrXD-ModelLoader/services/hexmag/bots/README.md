# HexMag Bot Ecosystem (Python reference)

> **Canonical control plane is MASM:** `src/asm/RawrXD_HexMag_Swarm.asm`  
> Spec: `docs/HEXMAG_MASM_CONTROL_PLANE.md` · Architecture: `docs/HEXMAG_ARCH_V2.md`

```text
Canonical implementation
    src/asm/RawrXD_HexMag_Swarm.asm
    docs/HEXMAG_MASM_CONTROL_PLANE.md

Python tree
    prototype / CI reference
    API compatibility surface
    responder-seed examples
```

## Frozen contract flags

```text
HEXMAG_WEIGHTED_MODEL=FALSE
HEXMAG_CODEGEN_PRIMARY=FALSE
HEXMAG_GENERATE_ON_CONTACT=TRUE

HEXMAG_RECURSIVE_REFINEMENT=INCOMPLETE
HEXMAG_FAILURE_DRIVEN_RESPAWN=INCOMPLETE
HEXMAG_POST_FINAL_DEFLATION=INCOMPLETE

HEXMAG_EPHEMERAL_RESPONDERS=TRUE
HEXMAG_PERSIST_RESPONDERS=FALSE
HEXMAG_DYNAMIC_INFLATION=TRUE
HEXMAG_POST_REQUEST_DEFLATION=TRUE
HEXMAG_TRANSIENT_STATE_AFTER_FINAL=0

HEXMAG_FAILURE_DRIVEN_GROWTH=TRUE
HEXMAG_REVERSE_VALIDATION=TRUE

HEXMAG_UNSUPPORTED_CLAIM_EMISSION=FALSE
HEXMAG_MISSING_INFORMATION_ACTION=ASK_USER

HEXMAG_AGENT_MODE=SUPPORTED
HEXMAG_RESPONSE_GEN_MODE=SUPPORTED
```

Architectural **contract** vs demonstrated **runtime** must not be conflated:
`GENERATE_ON_CONTACT` is contracted; recursive refine / failure respawn / post-final
deflation on the **MASM** path are still `INCOMPLETE`.

## Label split (eliminates first-answer-wins)

```text
llm.answer.candidate  !=  llm.answer.final
```

Only verify/finalize may emit `llm.answer.final`. Legacy `/ask` scanning the first
`llm.answer` is compatibility-only.

## Event progression (target)

```text
llm.question
    ↓
hexmag.contact
    ↓
hexmag.plan
    ↓
hexmag.responder.spawn
    ↓
llm.answer.candidate
    ↓
hexmag.reverse
    ↓
hexmag.critique
    ↓
        ┌──────────────────────┐
        │                      │
 computational failure   information deficit
        │                      │
        ↓                      ↓
 hexmag.responder.spawn   hexmag.need_input
        │                      │
        └──────↺               ↓
                            user input → resume
        │
        ▼
hexmag.verify
        ↓
llm.answer.final
        ↓
hexmag.deflate
```

## CodegenBot = seed, not HexMag

```text
CodegenBot: keyword → predetermined generator   (regression / compatibility)

HexMag:     question → topology → ephemeral responders → candidate
         → reverse/falsify → grow on failure → final → destroy topology
```

`codegen.py` may remain for CI without defining the architecture.

## Creating a seed bot (Python reference only)

Add a `.py` file defining a `core.contracts.Bot` subclass. Prefer emitting
`llm.answer.candidate` (or partials); do not treat first answer as final.

Next **implementation** target: MASM `candidate→reverse→spawn/refine→final→deflate`
loop — not more Python bot specialization.
