# Deep2 SNAP native C++20 source drop

This is a **tested host-side component**, not a claim of full Deep2 integration.
No third-party runtime dependencies. Build with MSVC C++20 or GCC/Clang C++20.

## Wire protocol

`TOOL <verb> <byte-count>\n<payload of exactly byte-count bytes>\nEND_TOOL\n`

Allowed verbs: read, write, build, test, finish. The parser accepts byte fragments and emits a stop signal at the final terminator byte, with no sleeps. Token fragments must be complete UTF-8 byte sequences or raw bytes from the detokenizer; payload length is **bytes**, not Unicode codepoints.

## Integration

1. Create `deep2::snap::Controller` per assistant turn, not per process.
2. Check `before_decode()` before each token decode.
3. Feed decoded token bytes to `on_token()`. Feed EOS via `on_token({}, true)`.
4. On `tool_ready`, leave decoding, validate command authorization and path containment in the host, execute the tool and append its result to the conversation.
5. On `finish`, run host-owned verification; do not trust the model's assertion.
6. On `invalid`, return a structured parser error as tool feedback and retry with a bounded turn budget.
7. On cancellation, propagate stop to GPU dispatch boundaries and cancel child processes using native Windows process handles/job objects.
8. Cache reuse must compare actual serialized prompt tokens; never reuse stale generated KV state.

## Security boundaries

The parser only validates syntax. It does **not** authorize filesystem paths, shell commands, or patch contents. Implement canonical workspace containment, no symlink/reparse escapes, explicit tool allowlists, subprocess timeouts, and rollback in the host. The `build` and `test` verbs must map to preapproved commands; do not interpret arbitrary model-provided shell. Parser length limits and output limits bound memory growth.

## Known integration gaps

No connection to `RuntimeGraph::Executor`, token stream, KV cache, Windows child-process management, or existing agent tool dispatcher is included because exact current interfaces are not supplied. Host-side stop latency is event-driven, but GPU kernels cannot be preempted except at supported safe boundaries. No 1ms latency guarantee.

## Test

`cmake -S . -B build && cmake --build build --config Release && ctest --test-dir build -C Release --output-on-failure`
