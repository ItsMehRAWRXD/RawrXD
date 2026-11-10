# Explicit secondary-device policy receipt

This receipt covers the follow-up witness after the split-forward tool was
hardened against implicit Vulkan index selection. It is development evidence,
not frozen-product certification.

```ini
RECEIPT_ID=DUAL_GPU_FORWARD_EXPLICIT_DEVICE_POLICY_20261028
SOURCE_ROOT=F:\rawrxd
SOURCE_COMMIT=b196b56de01dc9e8f0bdd30bb5cf6f2d36a2053f
TARGET=deep2_dualgpu_forward
TARGET_EXE=F:\rawrxd\build_ide\bin\deep2_dualgpu_forward.exe
TARGET_SHA256=554172BFCB2EA67BF5673BD9040A5224181ED6C45AAC33F0817496C6B996854B
MODEL=F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf
MODEL_SHA256=633FC5BE925F9A484B61D6F9B9A78021EEB462100BD557309F01BA84CAC26ADF
TOKENS=1,185
DECODE=1
SPLIT_BLOCK=2
PRIMARY=AMD Radeon AI PRO R9700
SECONDARY_DEVICE_INDEX=2
SECONDARY=AMD Radeon RX 7800 XT
EXIT_CODE=0
GPU_CALLS=130
CPU_CALLS=0
FALLBACK=none
NONFINITE_LOGITS=0
PRIMARY_SUBMITS=15
SECONDARY_SUBMITS=180
SECONDARY_WEIGHT_MISSES=60
SECONDARY_UPLOAD_MIB=609.0
SECONDARY_LIVE_MIB=607.5
VERDICT=PASS_DEVELOPMENT_WITNESS
```

The negative control was also executed against the same rebuilt binary:

```ini
NEGATIVE_CASE=split_without_ctx_dev
NEGATIVE_EXIT_CODE=1
NEGATIVE_RESULT=SPLIT_FAIL_EXPLICIT_DEVICE_REQUIRED
```

The explicit device requirement prevents D3D12 translation entries or an
integrated adapter from being mistaken for the requested physical secondary
GPU. The frozen product authority remains unchanged:

```ini
PRODUCT_EXE=G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe
PRODUCT_SHA256=748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145
PROMOTE=0
PRODUCT_CERTIFIED=0
```
