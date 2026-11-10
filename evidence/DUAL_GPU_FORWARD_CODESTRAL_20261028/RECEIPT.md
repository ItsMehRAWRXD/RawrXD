# Deep2 larger-model dual-GPU forward receipt

This is a bounded development witness for real dual-device execution. It is
not frozen-product certification and does not authorize REAP rewriting.

```ini
RECEIPT_ID=DEEP2_DUAL_GPU_FORWARD_CODESTRAL_20261028
SOURCE_ROOT=F:\rawrxd
SOURCE_COMMIT=b196b56de01dc9e8f0bdd30bb5cf6f2d36a2053f
TARGET=deep2_dualgpu_forward
TARGET_EXE=F:\rawrxd\build_ide\bin\deep2_dualgpu_forward.exe
TARGET_SHA256=554172BFCB2EA67BF5673BD9040A5224181ED6C45AAC33F0817496C6B996854B
MODEL=F:\OllamaModels\_r1_iso\07_codestral\Codestral-22B-v0.1-Q4_K_M.gguf
MODEL_BYTES=12660383840
MODEL_SHA256=0CD893BC242B76EF6BC886C07C8FB318A5493DCE4587E235707905A82E85A841
TOKENS=1,185
DECODE=1
SPLIT_BLOCK=16
PRIMARY=AMD Radeon AI PRO R9700
SECONDARY_DEVICE_INDEX=2
SECONDARY=AMD Radeon RX 7800 XT
EXIT_CODE=0
GPU_CALLS=786
CPU_CALLS=0
FALLBACK=none
NONFINITE_LOGITS=0
PRIMARY_SUBMITS=291
PRIMARY_WEIGHT_MISSES=113
PRIMARY_UPLOAD_MIB=3599.5
PRIMARY_LIVE_MIB=3592.6
SECONDARY_SUBMITS=841
SECONDARY_WEIGHT_MISSES=280
SECONDARY_UPLOAD_MIB=8387.4
SECONDARY_LIVE_MIB=8370.2
VERDICT=PASS_DEVELOPMENT_WITNESS
```

The run initialized Vulkan separately on the R9700 and RX 7800 XT, completed
the split forward, emitted a finite greedy token stream, and cleaned up both
Vulkan contexts. This proves real larger-model dual-device dispatch; it does
not replace Kimi/DeepSeek architecture-specific parity or frozen-product
certification.

```ini
PRODUCT_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
PRODUCT_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
PROMOTE=0
PRODUCT_CERTIFIED=0
```
