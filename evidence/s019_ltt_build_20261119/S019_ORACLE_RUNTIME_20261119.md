# S019 oracle runtime receipt

- Source HEAD before this receipt: `86b40315408ffd136f88f85cda74736d50205dd7`
- Oracle executable: `build_s019_ltt_20261119/bin-msvc/Release/deep2_parity_oracle.exe`
- Oracle SHA-256: `D6FF1F0498EF1D758A411BD616B558D186B47D40DB33B8F4E4050EF13A008C18`
- Model: `models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf`
- Input tokens: `1,2,3,4,5`
- Exit: `0`

The rebuilt oracle accepted the explicit token sequence and executed five teacher-forced steps through the current public engine API. It reported top-1 `0` at every step. The LTT Vulkan run for the same token sequence reported top-1 `2760,29871,29966,3,3`.

This is a reproducible CPU/reference-versus-Vulkan mismatch, not a parity pass. The oracle now runs, but its result indicates either a CPU execution/configuration mismatch or a GPU numerical/graph mismatch requiring the next differential trace.

```ini
ORACLE_BUILD=PASS
ORACLE_RUNTIME=PASS
EXPLICIT_TOKEN_CONTRACT=PASS
REFERENCE_TOP1=0,0,0,0,0
VULKAN_TOP1=2760,29871,29966,3,3
STRICT_PARITY=FAIL
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
```
