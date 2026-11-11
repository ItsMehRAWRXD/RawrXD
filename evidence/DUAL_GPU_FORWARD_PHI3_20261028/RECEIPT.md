# Deep2 dual-device forward witness

This is a development-target hardware witness. It is not a frozen-product
certification receipt and does not enable promotion or REAP rewriting.

```ini
RECEIPT_ID=DEEP2_DUAL_GPU_FORWARD_PHI3_20261028
SOURCE_ROOT=F:\rawrxd
SOURCE_COMMIT=05931405732d3a787a7bd371f263bd5673d6590a
TARGET=deep2_dualgpu_forward
TARGET_EXE=F:\rawrxd\build_ide\bin\deep2_dualgpu_forward.exe
TARGET_SHA256=F894F30455BFCFE21D09849B6DEB7442621A503EEE8C06DCBDFE6DB0BDC856D
MODEL=F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf
MODEL_SHA256=633FC5BE925F9A484B61D6F9B9A78021EEB462100BD557309F01BA84CAC26ADF
TOKENS=1,185
DECODE=1
SPLIT_BLOCK=2
PRIMARY_DEVICE=AMD Radeon AI PRO R9700
SECONDARY_DEVICE_INDEX=2
SECONDARY_DEVICE=AMD Radeon RX 7800 XT
EXIT_CODE=0
GPU_CALLS=130
CPU_CALLS=0
NONFINITE_LOGITS=0
PRIMARY_SUBMITS=15
SECONDARY_SUBMITS=180
SECONDARY_WEIGHT_MISSES=60
SECONDARY_UPLOAD_MIB=609.0
SECONDARY_LIVE_MIB=607.5
VERDICT=PASS_FOR_DEVELOPMENT_WITNESS
PRODUCT_PROMOTION=0
PRODUCT_CERTIFIED=0
```

Observed output included `Vulkan initialized successfully` for both the R9700
and the RX 7800 XT, `fallback=<none>`, and a finite generated stream. The
explicit `--ctx-dev 2` is required because this host's Vulkan enumeration
includes D3D12 translation entries; implicit device selection is now rejected
for split runs.
