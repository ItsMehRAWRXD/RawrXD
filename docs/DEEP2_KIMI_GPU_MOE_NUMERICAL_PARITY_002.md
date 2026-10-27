# DEEP2_KIMI_GPU_MOE_NUMERICAL_PARITY_002 — harness introduction

Base: `ef97b24938f81692cd5aaf305284ebd3150a6822` (`fix/deep2-multimodel-safety-20261025`). This work deliberately does not touch `K2NativeMoEFfn_Place.cpp`, `K2WeightResolve.cpp`, runtime dispatch, model weights, or release controls.

## Scope

`tools/k2_gpu_moe_vector_parity.py` compares complete **CPU, GPU0, and independently generated oracle** vectors. Inputs are text files containing one finite floating-point element per line, with optional blank lines and `#` comments. Every input is hashed in the resulting JSON receipt. Mismatched lengths, missing files, malformed values, and nonfinite values fail closed. The tool reports max/mean absolute difference, RMS, normalized RMS, max relative difference, cosine similarity, and worst-element index and values, for each of CPU/oracle, GPU/oracle, and GPU/CPU.

It **does not implement an independent GGUF dequantization/GEMV oracle** or capture the live tensor buffers. Those are follow-up source integration tasks and must not be counted as passed. The oracle file must be independently generated and its implementation/provenance reviewed. An identical final token is not parity proof.

## Run

```powershell
python tools/test_k2_gpu_moe_vector_parity.py
python tools/k2_gpu_moe_vector_parity.py --cpu cpu_vector.txt --gpu gpu_vector.txt --oracle scalar_oracle_vector.txt --oracle-provenance "independent scalar dequant/GEMV implementation + version" --max-abs 0.01 --max-rms 0.003 --min-cosine 0.999 --output parity_receipt.json
```

Thresholds in the example are **illustrative, not approved certification tolerances**. Choose and freeze tolerances using the independent reference and representative model inputs before issuing a production certificate.

Exit codes: 0 = threshold checks pass **diagnostically**; 2 = numerical threshold failure; 3 = invalid input or evaluation error. All JSON receipts set `certified=false` because vector capture, oracle independence, tensor identity, and quantization tolerances require separate audits.

## Next work

1. Add bounded opt-in CPU/GPU capture at the same layer/expert, before weighted accumulation, with dimensions and tensor hashes.
2. Implement independent scalar GGUF Q4_K/Q6_K dequant and GEMV reference (without using optimized CPU or GPU GEMV dispatch).
3. Validate exact quant block geometry, strides, endianness, weights, input identity, and H2D/D2H byte counts.
4. Run hardware receipts, freeze tolerances, and certify gates 02–10 only after evidence.

```ini
GPU0_DISPATCH=DEMONSTRATED_PREVIOUS_RECEIPT
VECTOR_COMPARISON_HARNESS=SOURCE_ADDED
LIVE_VECTOR_CAPTURE=NOT_IMPLEMENTED
INDEPENDENT_ORACLE=NOT_IMPLEMENTED
NUMERICAL_PARITY=NOT_CERTIFIED
PROMOTE=0
TIP_CLIMB=HOLD
```
