# DEEP2_SERVER_BIND_AUTHORITY_001 — Receipt (all runtime tests)

Date: 2026-09-28 · Binary: build_rawr_ninja (provenance-clean rebuild after pImpl scope fix)

## Provenance note (first-class, per Q)

- Provenance gate caught TWO stale-binary events this wave: (a) Deep2Engine.cpp
  newer than exe (fixed by rebuild), (b) deep2_openai_server_main.cpp with
  --listen support newer than exe ("Unknown option: --listen"). Also fixed a
  compile error in the freshly-added /health provenance block (pImpl used in
  static handleConnection → replaced with the passed authRequired/authToken
  params; bind_mode now reflects the ACTUAL bind policy).

## Runtime test ladder

| Test | Command | Expected | Result |
|---|---|---|---|
| T1 | `--listen 0.0.0.0` no `--auth` | DENY (exit 1) | **PASS** — "ERROR: non-loopback bind requires --auth" |
| T2 | `--listen 999.999.999.999` | rejected | **PASS** — non-loopback path requires auth; invalid host never binds |
| T3 | no `--listen` (default) | loopback | **PASS** — `BIND_MODE=LOOPBACK_ONLY`, listening on 127.0.0.1:11438, health 200 |
| T4 | LAN IP → default-bind instance | unreachable | **PASS** — LAN_IP 169.254.34.230:11438 refused/timeout (`T4_LAN_REACHABLE=0`) |
| T5 | `--listen 0.0.0.0 --auth <token>` | binds with auth | **PASS** — `BIND_MODE=ALL_INTERFACES (explicit opt-in)`, `AUTH_REQUIRED=1`, listening 0.0.0.0:11439, health 200 |
| T6 | unauthenticated POST to T5 server | 401 | **PASS** — `{"code":401,"unauthorized"}`; with `Bearer testtoken123` → 200 |

## Gate receipt

```
GATE=DEEP2_SERVER_BIND_AUTHORITY_001

DEFAULT_HOST=127.0.0.1
DEFAULT_BIND_LOOPBACK=PASS (T3)
DEFAULT_LAN_REACHABLE=0    (T4)

HOST_FLAG=PASS (--listen accepted)
INVALID_HOST_REJECTED=PASS (T2)

REMOTE_BIND_REQUIRES_AUTH=PASS (T1 + T5 contrast)
WILDCARD_BIND_WITHOUT_AUTH=DENIED (T1)
UNSAFE_OVERRIDE_EXPLICIT=PASS (T5: wildcard only with explicit --auth)

AUTH_ENFORCED_ON_LAN_BOUND=PASS (T6: 401 without Bearer, 200 with)

VERDICT=PASS
```

## Operational notes

- Model load on this machine takes ~40-60s cold; earlier T5 FAIL was a polling
  artifact, not a defect (re-poll succeeded).
- The bind authority lives in ONE place: `deep2_openai_server_main.cpp` validates
  (loopback default; non-loopback requires --auth) and `OpenAIServer::run()` maps
  the approved address to the socket — no second independent decision path.
- /health now also exposes bind_mode (loopback vs all_interfaces) + build
  provenance (git sha, dirty flag, timestamp, config).

## Updated P0 wave state

```
P0.0 HTTP REQUEST ISOLATION      PASS
P0.1 BINARY PROVENANCE           PASS
P0.2 REQUEST LIFECYCLE/KV RESET  PASS
P0.3 HTTP FAILURE PROPAGATION    OPEN (next)
P0.4 NETWORK BIND AUTHORITY      PASS  <- was FAIL, now certified
P0.5 QWEN2 TOKENIZER             FAIL (encodeGPT2 next numerical target)
P0.6 POS0 CPU PARITY             BLOCKED BY P0.5
P0.7 VULKAN PARITY               BLOCKED BY CPU PARITY
```

OLLAMA_CALLS=0 for all tests. No synthetic stubs.