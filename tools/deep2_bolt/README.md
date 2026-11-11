# Deep2 Bolt integration contract

Header-only C++20, no new dependencies. This is an **integration foundation**, not a complete Nemotron-H forward implementation. It intentionally rejects missing operator adapters rather than fabricating logits.

## Integrate
1. Parse real GGUF metadata into `ModelDesc`, including per-layer SSM/attention/MoE plan and exact tensor extents. `file_bytes` and offsets must use the same coordinate system.
2. Bind `Operators` callbacks to existing Deep2 implementations of Mamba-2 selective scan, causal attention, LatentMoE, final norm and output projection. Callback implementations must preserve residuals, norms, scaling and tensor ordering specified by the model.
3. Bind the existing tokenizer and embedding lookup; pass the actual token embedding to `Pipeline::forward`.
4. Invoke `reset()` per independent request, preserve `DecodeState` across generated tokens, and sample the returned logits.
5. Compare against an independent reference for logits, layer outputs and multiple-token generation before declaring success.

## Build smoke test
`cl /std:c++20 /EHsc /W4 /c deep2_bolt_smoke.cpp`

## Caveats
- NVFP4 type 40 mapping and auxiliary scales must be independently confirmed against the producing GGUF implementation.
- GGUF tensors can have padding/alignment. `TensorDesc::bytes` must be the actual tensor payload, not the gap to the next tensor.
- The 88/843 counts are specific to the supplied model, not generic Nemotron-H constants.
- The interface does not implement the missing SSM, attention, or MoE math. A claim of complete production inference would require those implementations and verified parity receipts.
