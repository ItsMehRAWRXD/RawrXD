# MODEL_SELECTED_AGENT attempts (SHA 9797521C)

`FORCE_TOOL=ABSENT` · `PROMOTE=0` · `CROSS_SHA_CREDIT=0` · `INVENT_PASS=0`

| ID | Method | Model | Result | MODEL_SELECTED_TOOL |
|----|--------|-------|--------|---------------------|
| baseline runs/ | prior | tinyllama.gguf | PARSE_FAIL / KILLED | 0 |
| a_tiny_json_prompt | A (-p JSON-only) | tinyllama.gguf | Python `{"tool": tool, "path": path}` → tool=path | 0 |
| a_tiny_host_decode | A + HOST_DECODE=1 | tinyllama.gguf | Python prose; no quoted tool | 0 |
| json_emit_probe | control `rawr run` | tinyllama.gguf | markdown JSON with `"tool":"read"` | n/a (not agent) |
| b_phi3_probe | B | phi3-mini-Q2_K.gguf | garbage tokens | 0 |
| b_llama32_probe | B | llama3.2-3b-Q2_K.gguf | non-JSON | 0 |
| C | parser allowlist | — | NOT_APPLIED (would break EXE SHA pin) | — |

**Verdict:** `DISPOSITION=FAIL` on pin. Next close needs EXE Method A/C tip beyond 9797521C, or a GGUF that emits quoted tool JSON under the frozen agent decide prompt.
