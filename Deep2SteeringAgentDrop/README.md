# RawrXD Deep2 native steering / tool bridge (C++17)

## Files
- `Deep2Steering.hpp`: session-scoped logit steering (previous source drop)
- `Deep2AgentTools.hpp`: JSON parser, typed argument schema, tool registry, tool call parsing, observation feedback, bounded agent loop
- `Deep2Interventions.hpp`: additive layer interventions with certification bypass; finite-string constrained token masking
- `test_steering.cpp`, `test_agent_tools.cpp`: standalone acceptance tests

## Build
`cl /nologo /std:c++17 /EHsc /W4 /I. test_agent_tools.cpp /Fe:test_agent_tools.exe`
`cl /nologo /std:c++17 /EHsc /W4 /I. test_steering.cpp /Fe:test_steering.exe`

## Wire into RawrXD
1. Implement `GenerateStep` by calling the **real** Deep2 decode loop, preserving its tool-call text; `RunAgent` does not implement model inference.
2. Register actual existing filesystem / process handlers via `ToolRegistry::Register`; callbacks are intentionally NOT wired to any host process or filesystem by this source drop. Enforce workspace root, path canonicalization, executable allowlist, user permissions, process timeouts, and sandbox policy **inside** handlers.
3. Feed `tool_observation_untrusted` to model context as a **tool result**, not as system/developer instructions. Tool output is untrusted.
4. Use `ConstrainedGenerator::Mask` only with exact, context-independent token byte strings. SentencePiece whitespace/byte-fallback or context-sensitive detokenization requires a tokenizer-specific prefix implementation. This is a finite candidate set, **not** arbitrary JSON-schema grammar decoding.
5. Invoke `InterventionController::Apply` at real residual / attention-score / attention-weight hook points on **working tensors**. Caller owns validation of tensor dimensions, softmax renormalization if intervening after softmax, and tensor lifetime. This code does not patch the 300-op executor.
6. Preserve untouched logits and tensor captures for reference parity. Set certification mode on both steering and interventions during certification.

## Schema limits
Argument schemas validate required fields, exact JSON primitive kinds, and reject extra keys by default. They do **not** implement full JSON Schema (`oneOf`, ranges, nested property definitions, regex, formats). JSON parser supports ordinary Unicode BMP escapes but rejects surrogate escape pairs; use direct UTF-8 strings instead. `ParseToolCall` supports one tool call per generation step. No automatic tool execution based on natural-language intent.

## Test scope
Local GCC C++17 tests exercise parsing, schema validation, dispatch, observation/resume, tool budget, intervention bypass and finite candidate masking. They do not certify MSVC builds, live Deep2 generation, or actual filesystem/process tool authority.
