# MODEL_SELECTED_AGENT attempts

`FORCE_TOOL=ABSENT` · `PROMOTE=0` · `CROSS_SHA_CREDIT=0` · `INVENT_PASS=0`

| ID | Method | Model | Result | MODEL_SELECTED_TOOL |
|----|--------|-------|--------|---------------------|
| baseline runs/ | prior | tinyllama.gguf | PARSE_FAIL / KILLED on 9797521C | 0 |
| a_tiny_json_prompt | A (-p JSON-only) | tinyllama.gguf | Python `{"tool": tool, "path": path}` → tool=path | 0 |
| a_tiny_host_decode | A + HOST_DECODE=1 | tinyllama.gguf | Python prose; no quoted tool | 0 |
| json_emit_probe | control `rawr run` | tinyllama.gguf | markdown JSON with `"tool":"read"` | n/a (not agent) |
| b_phi3_probe | B | phi3-mini-Q2_K.gguf | garbage tokens | 0 |
| b_llama32_probe | B | llama3.2-3b-Q2_K.gguf | non-JSON | 0 |
| c_method_runtime_template | C prompt+parser+path | tinyllama.gguf | PASS EXIT=0 read→report | **1** |

**Method C tip SHA:** `7C9680CBF025FCD78AD48DFE40D26EB45ADB78FB3F9B41321346990C77E42027`  
**9797521C numerical seals:** KEPT via `rawr_FIX_Q6K_HOST_9797521C.exe`

**Verdict:** `DISPOSITION=PASS` via Method C (runtime chat template + allowlisted `"tool":"<name>"` + workspace path resolve). `PROMOTE=0` · `GATE_STOP=1`.
