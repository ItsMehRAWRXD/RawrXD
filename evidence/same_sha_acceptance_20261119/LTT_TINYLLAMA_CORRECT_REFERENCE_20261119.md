# Correct TinyLlama reference comparison

```ini
SOURCE_SHA=9e4370162d4608580035f24be3b1ffcd03d938ec
LTT_EXECUTABLE_SHA256=8CF1C86F86B33E3E6B74CC644B499D1CAC5B9ADC4AF592E107B8620D8E514A84
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
REFERENCE_EXECUTABLE=F:\\rawrxd\\evidence\\DEEP2_QWEN36_NATIVE_LOGIT_ORACLE_001\\bin\\llama_dump_logits_teacher_forced.exe
TOKENS=1,185,42
REFERENCE_EXIT=0
COMPARE_EXIT=0
POSITIONS=3
VOCAB=32000
ALL_FINITE=1
ARGMAX_EXACT=2/3
MIN_COSINE=0.9964957435475023
MAX_ABS_WORST=1.4383420944213867
```

The earlier failed comparison used a Qwen reference artifact with the wrong model identity. A new llama.cpp teacher-forced reference was generated from the exact TinyLlama GGUF and token IDs. The corrected comparison is structurally valid but does not meet strict parity: position 2 has an argmax mismatch and the minimum cosine is `0.9964957435`.
