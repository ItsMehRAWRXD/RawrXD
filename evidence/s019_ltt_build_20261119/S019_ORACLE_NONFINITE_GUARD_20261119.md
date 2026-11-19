# S019 oracle nonfinite guard

- Source revision before commit: `8a2c86c1e8d2852bf0c070971b3494b4a23cbde8`
- Model: `models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- Tokens: `1,2,3`
- Build target: `deep2_parity_oracle`
- Build: PASS
- Executable SHA-256: `2041CD67F9728142D054C37BD9D858CF667E621795CCCD68DB1A2F82BE062C5E`
- Runtime exit: `9`
- Observed: `FAIL: nonfinite hidden state at step 0`

The oracle now fails closed when the current CPU/reference path produces a non-finite
hidden state or logits. This prevents an all-zero top-1 result from being treated as
a numerical comparison. The same-token Vulkan LTT run remains a separate GPU result;
strict parity is unresolved.

```ini
ORACLE_BUILD=PASS
ORACLE_RUNTIME=FAIL_CLOSED_NONFINITE
VULKAN_RUNTIME=PASS_REPORTED
STRICT_PARITY=OPEN
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
