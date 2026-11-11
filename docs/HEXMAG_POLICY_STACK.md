# HexMag Policy-Resolution Stack (chain of command)

```text
L0 CORE INVARIANTS  >  L1 CONSTITUTION  >  L2 MISSION  >  L3 ROLE
  >  L4 TOOL CONTRACT  >  L5 CONTEXT  >  L6 STRATEGY  >  L7 ACTION
  >  VERIFICATION  >  REPEAT TUNER  >  ARBITER  >  RECORDER  >  FINAL GATE
```

## Separation (mandatory)

```text
Authority  ≠  Evidence  ≠  Confidence
claim.verified = evidence.exists && evidence.passesRequiredVerifier
agent_confidence must NEVER imply claim_verified
```

## Code map

| Layer | File |
|-------|------|
| L0–L7 types, resolve, FINAL gate | `src/core/hexmag_authority.hpp` |
| Constitution + directive registry | `src/core/hexmag_constitution.hpp` |
| Facade (ask/stream/feedback) | `src/core/hexmag_control_plane.{hpp,cpp}` |
| MASM swarm + unused agents | `src/asm/RawrXD_HexMag_Swarm.asm` |
| MASM repeat tuner | `src/asm/RawrXD_HexMag_RepeatTuner.asm` |
| IDE client | `src/agent/hexmag_client.hpp` |
| Response Gen default binder | `src/agentic/AgentRuntimeController.hpp` |
| E2E smoke | `tests/hexmag_e2e_smoke.cpp` + `scripts/Smoke-HexMagMasm.ps1` |

## Core invariants (immutable)

```text
unsupported_claim_emission = FORBIDDEN
guessing_missing_facts      = FORBIDDEN
confidence_as_evidence      = FORBIDDEN
missing_information         -> ASK_USER
computational_uncertainty   -> GROW_AND_REVERSE
verified_claim              -> ALLOW_FINAL
```

## Tool rank example (CPU parity)

```text
llama_cpu_oracle (rank 100)  >  llama_vulkan (rank 1)   for domain=numerical_parity
```

## Run

```powershell
.\scripts\Smoke-HexMagMasm.ps1
```
