# VAL-051.7 — Gate 12: Layer Integration

## Document Identity
- **Gate:** 12
- **Version:** 1.0
- **Date:** 2026-08-22

---

## Layer Lifecycle

```cpp
void Deep2Engine::forwardLayer(size_t layer, const float* input, float* output, size_t seqLen) {
    ResidencyCounters::BeginLayer();
    ResidencyCounters::OnLayerTransition();
    
    // Acquire attention weights
    void* wqData = nullptr; size_t wqBytes = 0; uint64_t wqGen = 0;
    void* wkData = nullptr; size_t wkBytes = 0; uint64_t wkGen = 0;
    void* wvData = nullptr; size_t wvBytes = 0; uint64_t wvGen = 0;
    void* woData = nullptr; size_t woBytes = 0; uint64_t woGen = 0;
    void* attnNormData = nullptr; size_t attnNormBytes = 0; uint64_t attnNormGen = 0;
    
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".wq", wqData, wqBytes, wqGen);
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".wk", wkData, wkBytes, wkGen);
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".wv", wvData, wvBytes, wvGen);
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".wo", woData, woBytes, woGen);
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".attn_norm", attnNormData, attnNormBytes, attnNormGen);
    
    // Attention compute
    computeAttention(layer, input, output, seqLen,
                     wqData, wkData, wvData, woData, attnNormData);
    
    // Release attention weights
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".wq");
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".wk");
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".wv");
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".wo");
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".attn_norm");
    
    // Acquire FFN weights
    void* wGateData = nullptr; size_t wGateBytes = 0; uint64_t wGateGen = 0;
    void* wUpData = nullptr; size_t wUpBytes = 0; uint64_t wUpGen = 0;
    void* wDownData = nullptr; size_t wDownBytes = 0; uint64_t wDownGen = 0;
    void* ffnNormData = nullptr; size_t ffnNormBytes = 0; uint64_t ffnNormGen = 0;
    
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".ffn_gate", wGateData, wGateBytes, wGateGen);
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".ffn_up", wUpData, wUpBytes, wUpGen);
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".ffn_down", wDownData, wDownBytes, wDownGen);
    residencyManager.AcquireTensor("blk." + std::to_string(layer) + ".ffn_norm", ffnNormData, ffnNormBytes, ffnNormGen);
    
    // FFN compute
    computeFFN(layer, output, ffnOutput,
               wGateData, wUpData, wDownData, ffnNormData);
    
    // Release FFN weights
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".ffn_gate");
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".ffn_up");
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".ffn_down");
    residencyManager.ReleaseTensor("blk." + std::to_string(layer) + ".ffn_norm");
    
    ResidencyCounters::EndLayer();
}
```

---

## Weight Inventory Per Layer

| Weight | Tensor Name | Role |
|--------|-------------|------|
| WQ | `blk.N.attn_q` | Q projection |
| WK | `blk.N.attn_k` | K projection |
| WV | `blk.N.attn_v` | V projection |
| WO | `blk.N.attn_output` | Output projection |
| AttnNorm | `blk.N.attn_norm` | Attention RMSNorm |
| WGate | `blk.N.ffn_gate` | FFN gate |
| WUp | `blk.N.ffn_up` | FFN up |
| WDown | `blk.N.ffn_down` | FFN down |
| FFNNorm | `blk.N.ffn_norm` | FFN RMSNorm |

---

## Acceptance Criteria

1. Every acquisition has matching release.
2. No active leases at `EndLayer()`.
3. Layer index is monotonic.
4. Layer count matches expected architecture (56 for Codestral-22B).
5. `layerCount == forwardCount * numLayers`.
