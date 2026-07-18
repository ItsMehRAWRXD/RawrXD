# RawrXD Model Compatibility Matrix

**Version:** v1.1.0  
**Last Updated:** 2026-07-13

---

## Supported Architectures

| Architecture | Status | Notes |
|--------------|--------|-------|
| **LLaMA 3/3.1** | ✅ Fully Supported | Primary test platform |
| **LLaMA 2** | ✅ Fully Supported | Backward compatible |
| **Mistral 7B** | ✅ Fully Supported | Sliding window attention |
| **Mixtral 8x7B** | ✅ Fully Supported | MoE routing |
| **Mixtral 8x22B** | ✅ Fully Supported | Extended context |
| **Phi-3/3.5** | ✅ Fully Supported | Long context (128K) |
| **Phi-2** | ✅ Fully Supported | Legacy support |
| **Qwen2/2.5** | ✅ Fully Supported | YaRN scaling |
| **DeepSeek** | ✅ Fully Supported | ALiBi attention |
| **Codestral** | ✅ Fully Supported | Code-optimized |
| **CodeLlama** | ✅ Fully Supported | Code variants |
| **Gemma 2** | ✅ Fully Supported | Google models |
| **Gemma** | ✅ Fully Supported | Legacy support |
| **StarCoder 2** | ⚠️ Beta | Testing in progress |
| **Command-R** | ⚠️ Beta | Cohere models |

---

## Feature Compatibility

### Attention Mechanisms

| Architecture | Standard | Flash Attention | Sliding Window | GQA | ALiBi |
|--------------|----------|---------------|----------------|-----|-------|
| LLaMA 3 | ✅ | ✅ | ❌ | ✅ | ❌ |
| Mistral | ✅ | ✅ | ✅ | ✅ | ❌ |
| Mixtral | ✅ | ✅ | ✅ | ✅ | ❌ |
| Phi-3 | ✅ | ✅ | ✅ | ❌ | ❌ |
| Qwen2 | ✅ | ✅ | ❌ | ✅ | ❌ |
| DeepSeek | ✅ | ⚠️ | ❌ | ❌ | ✅ |
| Codestral | ✅ | ✅ | ✅ | ✅ | ❌ |
| Gemma 2 | ✅ | ✅ | ✅ | ❌ | ❌ |

### Quantization Support

| Format | LLaMA | Mistral | Phi-3 | Qwen2 | DeepSeek |
|--------|-------|---------|-------|-------|----------|
| Q4_0 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Q4_K_M | ✅ | ✅ | ✅ | ✅ | ✅ |
| Q5_K_M | ✅ | ✅ | ✅ | ✅ | ✅ |
| Q6_K | ✅ | ✅ | ✅ | ✅ | ✅ |
| Q8_0 | ✅ | ✅ | ✅ | ✅ | ✅ |
| FP16 | ✅ | ✅ | ✅ | ✅ | ✅ |
| INT8 | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ⚠️ |

---

## Tested Models

### Production Tested

| Model | Size | Quantization | Hardware | TPS |
|-------|------|--------------|----------|-----|
| Llama-3.1-8B-Instruct | 8B | Q4_K_M | RX 7800 XT | 45.2 |
| Llama-3.1-70B-Instruct | 70B | Q4_K_M | RX 7900 XTX | 12.8 |
| Mistral-7B-Instruct-v0.3 | 7B | Q4_K_M | RX 7800 XT | 48.5 |
| Mixtral-8x7B-Instruct-v0.1 | 47B | Q4_K_M | RX 7900 XTX | 18.3 |
| Phi-3-mini-4k-instruct | 3.8B | Q4_K_M | RX 7800 XT | 78.3 |
| Phi-3-medium-128k-instruct | 14B | Q4_K_M | RX 7900 XTX | 28.4 |
| Qwen2.5-32B-Instruct | 32B | Q4_K_M | RX 7900 XTX | 15.2 |
| Codestral-22B-v0.1 | 22B | Q4_K_M | RX 7800 XT | 20.1 |
| Gemma-2-9B-it | 9B | Q4_K_M | RX 7800 XT | 38.7 |
| Gemma-2-27B-it | 27B | Q4_K_M | RX 7900 XTX | 14.5 |

### Community Tested

| Model | Reporter | Status |
|-------|----------|--------|
| DeepSeek-Coder-V2 | @community | ✅ Working |
| StarCoder2-15B | @community | ⚠️ Issues |
| Command-R-Plus | @community | ✅ Working |

---

## Known Limitations

### Current Limitations

1. **Vision Models**
   - CLIP/LLaVA not yet supported
   - Planned for v1.1.0 V.3

2. **Distributed Inference**
   - Multi-node not yet supported
   - Planned for v1.2.0

3. **Speculative Decoding**
   - Draft model support pending
   - Target v1.1.0

4. **INT8 Quantization**
   - Calibration tools in development
   - Target v1.1.0 V.4

### Architecture-Specific

| Architecture | Limitation | Workaround |
|--------------|------------|------------|
| DeepSeek | ALiBi not optimized | Use standard attention |
| Mixtral | MoE routing overhead | Use fewer active experts |
| Phi-3 | Long context memory | Reduce batch size |
| Gemma 2 | QK norm overhead | Disable for speed |

---

## Adding New Models

To add support for a new model:

1. **Detect Architecture**
   ```cpp
   ArchitectureDetector detector;
   auto arch = detector.DetectFromGGUF("model.gguf");
   ```

2. **Create Adapter**
   ```cpp
   auto adapter = ModelAdapterFactory::Create(arch);
   ```

3. **Test Compatibility**
   ```bash
   rawrxd test --model model.gguf --compatibility
   ```

4. **Submit Report**
   - Open issue with compatibility report
   - Include benchmark results
   - Tag with `compatibility`

---

## Reporting Issues

If a model doesn't work:

1. Check this matrix for known limitations
2. Try different quantization format
3. Test with `--compatibility-check` flag
4. Open issue with:
   - Model name and size
   - GGUF source
   - Error messages
   - Hardware specs

---

## Future Support

### Planned (v1.1.0)

- StarCoder 2 full support
- Command-R optimization
- INT8 quantization
- Vision encoder (CLIP)

### Planned (v1.2.0)

- Mamba architecture
- RWKV support
- Distributed inference
- Larger context windows

### Under Evaluation

- Falcon 2
- DBRX
- XVERSE
- Orion

---

**Compatibility Matrix Version:** 1.0.0  
**Last Updated:** 2026-07-13
