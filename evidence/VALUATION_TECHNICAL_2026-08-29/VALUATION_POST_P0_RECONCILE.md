# RawrXD Technical Valuation — reconciled P0 close + Deep2 forward blocker

**As of:** 2026-08-29  
**Scope:** Engineering/IP asset (not operating-company valuation)

## Range

| Band | Value |
|------|------:|
| Technical valuation | **$125M–$145M** |
| Midpoint | **~$135M** |

Bump vs ~$125M: removal of agent-loop plumbing / execution-safety discounts (P0s closed).  
**Not** awarded: autonomous GGUF-originated agency premium.

## P0 infrastructure — CLOSED

- model path/tag handling
- duplicate tool-call detection
- shell execution policy
- JSON/tool-call parsing
- scripted E2E proof quality (IDE_AGENT_LOOP_001 / AGENT-E2E-002 spine)

## Remaining critical blocker

> Deep2 must reliably produce a numerically valid bounded forward pass before genuine GGUF-originated agency can be certified.

### Dependency chain (AUTHORITY order)

```
model load
→ one-token forward
→ finite activations
→ valid logits
→ correct deterministic PONG
→ multi-token generation
→ tool-call synthesis
→ AGENT-E2E-002b
```

### Headline gate (next)

```
TinyLlama
prompt: PONG
1-token bounded forward
all required activations finite
logits finite
argmax/sample valid
token decode valid
output=PONG (or expected deterministic token sequence)
fresh process, repeatable
```

## Explicit freezes

- AGENT-E2E-002: frozen CANDIDATE_PASS / NOT_CERTIFIED — do not expand deterministic fixtures
- MLA / SSM architecture certs: frozen until basic transformer path numerically stable
- AGENT-E2E-002b: deferred until one-token forward is green
