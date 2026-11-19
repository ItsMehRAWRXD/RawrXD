# Three-token LTT versus retained reference

```ini
SOURCE_SHA=2b25007421d7b77cdb2f91724f37005a033480ff
LTT_EXECUTABLE_SHA256=8CF1C86F86B33E3E6B74CC644B499D1CAC5B9ADC4AF592E107B8620D8E514A84
MODEL=F:\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf
TOKENS=1,185,42
LTT_EXIT=0
COMPARE_EXIT=0
POSITIONS=3
VOCAB=32000
ALL_FINITE=1
ARGMAX_EXACT=0/3
MIN_COSINE=0.058690330059348074
MAX_ABS_WORST=17.32428503036499
```

The LTT execution itself passed with `465` GPU calls and `0` CPU calls. The retained reference comparison completed structurally but failed numerically: no position matched argmax and cosine ranged from `0.05869` to `0.61760`. This is recorded as a parity failure; no kernel change is justified until the reference model identity and tokenizer/configuration are verified.
