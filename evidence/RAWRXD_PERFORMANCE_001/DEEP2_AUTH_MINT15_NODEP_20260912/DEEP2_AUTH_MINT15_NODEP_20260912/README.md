# Deep2 Authority Mint-15 — dependency-free source

This drop reverses the previous side-drop law from:

    "cannot mint product authority; cannot set PROMOTE"

to an explicit authorization-capable state machine:

    evidence -> validation -> seal -> mint TPS authority
             -> separate promotion authorization -> PROMOTE

It is still impossible for a self-test result to become live product authority by accident.
The product must supply a one-shot `AuthorityGrant` with the relevant scope bits.

## Top 15 authorization-granted operations

1. `grant_authority` — bind a one-shot authority capability.
2. `bind_gate` — bind the exact gate ID and target token count.
3. `bind_cert_sha256` — bind the measured certification binary hash.
4. `begin_observation` — freeze QPC frequency and required predicates.
5. `observe_token` — ingest each measured QPC begin/end pair.
6. `close_observation` — freeze the timing stream.
7. `validate_cardinality` — require observed == target and non-zero.
8. `validate_integrity` — require gate/cert/grant identity.
9. `validate_qpc` — require monotonic, positive QPC intervals.
10. `calculate_metrics` — derive wall, min/max/mean/P50/P95 and sustained TPS.
11. `validate_predicates` — require full-forward, real AR decode, warmup excluded,
    sealed reuse zero, synthetic logits zero, device-lost zero, cert unchanged.
12. `seal_receipt` — SHA-256 the receipt plus authority nonce.
13. `mint_tps_authority` — set `FULL_MODEL_TPS_AUTHORITY=1`.
14. `authorize_promote` — separately authorize promotion only after TPS authority exists.
15. `commit_promote` — set `PROMOTE=1`.

## Important trust boundary

This module is an in-process policy/authority state machine, not a cryptographic privilege
boundary against arbitrary code already executing in the same process. The receipt is
SHA-256 sealed and bound to the supplied grant nonce and cert hash, but a hostile caller
with arbitrary memory/code execution can always bypass in-process policy.

For Deep2 this is intended to prevent accidental/mocked authority creation and enforce
the correct product sequencing.

## No dependencies

- C++17 only
- no Vulkan headers
- no CUDA/ROCm
- no llama.cpp/Ollama
- no external crypto library
- includes a compact SHA-256 implementation

## Build

MSVC x64:
    build_msvc.bat

Portable:
    g++ -std=c++17 -O2 -Iinclude src/d2_authority_mint15.cpp src/selftest.cpp -o selftest

## Live integration law

Do not feed synthetic/self-test timings into the live authority path.

The live product integration should supply:
- exact current gate ID
- full 64-character measured cert SHA-256
- actual QPC frequency
- one timing pair per generated token
- observed predicate values from the measured run
- an explicit product authority grant

Only then may operation 13 mint live `FULL_MODEL_TPS_AUTHORITY=1`.
Operations 14-15 are intentionally separate so TPS authority does not automatically
imply deployment/promotion authority.
