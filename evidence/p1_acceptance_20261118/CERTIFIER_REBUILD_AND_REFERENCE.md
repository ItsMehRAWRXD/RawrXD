# Rebuilt certifier and independent reference run

```ini
SOURCE_SHA_BEFORE_EVIDENCE=2963591a14
CERTIFIER_EXECUTABLE_SHA256=B639206365FCF54185B4106EC0F6DB4E37B4A8FB351ED293D084F1D8C3999951
REFERENCE_POS0_SHA256=909F2BCBDE0DEFE9DC358B3521376B9E54FB9BBADC130B10200228457FF5EC5D
REFERENCE_POS1_SHA256=39CE23CEDC16E6A74EE816CC8DA0A63AA281BB51478CD4D9D1F88FCB0FE6E96E
BUILD=PASS
EVIDENCE_COMPLETE=1
GPU_CALLS=546
CPU_FALLBACK_CALLS=0
```

Independent reference results for the real Qwen3.5 fixture:

```ini
POSITION0_COSINE=0.7537246
POSITION0_MAX_ABS=11.11
POSITION1_COSINE=0.6702792
POSITION1_MAX_ABS=12.75
CERT_STATUS=FAIL_REFERENCE_PARITY
```

The certifier's prior MSVC failure was caused by a duplicate `<cstdarg>` include inside the anonymous namespace. Removing that include restored the target build without changing the dirty instrumentation logic.

The full-model numerical defect remains open. The first internal divergences are position 0 block 11 attention output and position 1 block 3 FFN output; fused latent-KV MLA and GPU MoE parity remain untested.
