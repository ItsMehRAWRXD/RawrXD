# Batch 11 — Tagged tool-call framing hardening

Date: 2026-11-05
Branch: `fix/deep2-multimodel-safety-20261025`
CERTIFIED=0
PROMOTE=0

## Source-level finding

The production `parseReply` accepted a valid `<tool>...</tool><args>...</args>` pair even if unrelated prose or role-control tokens appeared before, between or after the pair. Such output could be dispatched as a tool call despite violating the single-call-only contract.

## Commits

- `3594c74a7251727d94e51d82f70a602713cd65a8`: reject non-whitespace prefix, interstitial, and suffix text around a tagged tool call in production.
- `5acdb54f655a5527ae0e7b22d0992699bdbb735f`: apply identical validation to the portable parser.
- `c1a7b51b661df385f735045a8795be6dfc463bdc`: add 15 adversarial framing cases to `rawr_agent_protocol_selftest.cpp`.

## Fifteen regression cases added

1. Prefix prose before tool tag — reject.
2. Suffix prose after args — reject.
3. Interstitial prose — reject.
4. Whitespace prefix plus suffix prose — reject.
5. Chat role-control suffix — reject.
6. Dangling second opening tool tag — reject.
7. DONE suffix — reject.
8. Interstitial extra text — reject.
9. Assistant preamble — reject.
10. Newline final-answer suffix — reject.
11. Multiline interstitial prose — reject.
12. Second dangling args tag — reject.
13. Extra closing tool tag — reject.
14. Dangling subsequent tool call — reject.
15. Whitespace-only surrounding content — accept.

## Verification status

All changes committed; no successful C++ test run or CI job receipt observed in this batch. Tests are pending execution, not marked PASS. The parity script from Batch 10 should detect divergence between the two parser copies. This does not yet prove model-to-tool-to-disk integration.

## Remaining end-to-end work

- Execute CI parser and registry tests with linked commit SHA.
- Replace duplicated parser with a shared implementation.
- Verify model-originated tool invocation and authorized `editFiles` disk persistence.
- Prove tool-result consumption, numerical correctness, GPU inference, native Win32 GUI gates, soak/stress, packaging, and T25 independent certification.
