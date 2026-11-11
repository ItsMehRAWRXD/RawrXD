static std::vector<float> ExecuteMLADecompressForward(const TensorView& input,
                                                        const TensorView& kvANorm,
                                                        const TensorView& kvAMqa,
                                                        const TensorView& kvB,
                                                        const std::unordered_map<std::string, ModelGenie::GGMLType>& liveTypeMap)
{
    // Dequantize weights
    std::vector<float> kvANormW, kvAMqaW, kvBW;
    DequantizeTensor(kvANorm, kvANormW, liveTypeMap);
    DequantizeTensor(kvAMqa, kvAMqaW, liveTypeMap);
    DequantizeTensor(kvB, kvBW, liveTypeMap);

    // Input dimensions
    const uint32_t inputDim = static_cast<uint32_t>(input.bytes / sizeof(float));
    
    // Constants from generated model config
    const uint32_t kvRank   = Generated::ModelConfig::kKvLoraRank;         // 512
    const uint32_t ropeDim  = Generated::ModelConfig::kRopeDimensionCount; // 64
    const uint32_t heads    = Generated::ModelConfig::kHeadCount;          // 16
    const uint32_t keyDim   = Generated::ModelConfig::kKeyLength;          // 192
    const uint32_t valueDim = Generated::ModelConfig::kValueLength;        // 128
    const uint32_t keyNopeDim = keyDim - ropeDim;                          // 128
    
    // Verify shapes
    if (inputDim != Generated::ModelConfig::kEmbeddingLength) {
        std::fprintf(stderr, "[IR][MLA] inputDim=%u mismatch\n", inputDim);
        fflush(stderr);
        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
    }
    
    // kv_a_mqa output dimension = 512 + 64 = 576
    if (kvAMqaW.size() % inputDim != 0) {
        std::fprintf(stderr, "[IR][MLA] kv_a_mqa weight shape incompatible\n");
        fflush(stderr);
        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
    }
    
    const uint32_t aOutputDim = static_cast<uint32_t>(kvAMqaW.size() / inputDim);
    if (aOutputDim != Generated::ModelConfig::kKvLoraRank + Generated::ModelConfig::kRopeDimensionCount) {
        std::fprintf(stderr, "[IR][MLA] kv_a_mqa output dim=%u mismatch expected=%u\n", 
                     aOutputDim, kvRank + ropeDim);
        fflush(stderr);
        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
    }
    
    // kv_a_norm must be size 512 (kvRank)
    if (kvANormW.size() != kvRank) {
        std::fprintf(stderr, "[IR][MLA] kv_a_norm size=%zu mismatch kvRank=%u\n", 
                     kvANormW.size(), kvRank);
        fflush(stderr);
        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
    }
    
    // kv_b: [4096, 512] -> outputDim=4096, inputDim=512
    if (kvB.rank != 2 || kvB.dims[0] != kvRank) {
        std::fprintf(stderr, "[IR][MLA] kv_b input shape mismatch: rank=%u dim0=%u expected=%u\n",
                     kvB.rank, kvB.dims[0], kvRank);
        fflush(stderr);
        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
    }
    
    const uint32_t expandedDim = kvB.dims[1];  // 4096
    if (expandedDim != heads * (keyDim - ropeDim + valueDim)) {
        std::fprintf(stderr, "[IR][MLA] kv_b output dim=%u mismatch\n", expandedDim);
        fflush(stderr);
        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
    }
    
    // Step 1: Project input to latent space via kv_a_mqa (576 = 512 + 64)
    // kvAMqaW is [576, 2048] or [2048, 576] - layout: [aOutputDim, inputDim]
    std::vector<float> aOut(aOutputDim, 0.0f);
    
    if (kvAMqaW.size() == inputDim * aOutputDim) {
        // Layout: [inputDim][aOutputDim] -> row = o * inputDim
        for (uint32_t o = 0; o < aOutputDim; ++o) {
            float sum = 0.0f;
            const float* row = kvAMqaW.data() + size_t(o) * inputDim;
            for (uint32_t i = 0; i < inputDim; ++i) {
                sum += row[i] * reinterpret_cast<const float*>(input.data)[i];
            }
            aOut[o] = sum;
        }
    }
    else if (kvAMqaW.size() == aOutputDim * inputDim) {
        // Layout: [aOutputDim][inputDim] -> row = o * inputDim
        for (uint32_t o = 0; o < aOutputDim; ++o) {
            float sum = 0.0f;
            const float* row = kvAMqaW.data() + size_t(o) * inputDim;
            for (uint32_t i = 0; i < inputDim; ++i) {
                sum += row[i] * reinterpret_cast<const float*>(input.data)[i];
            }
            aOut[o] = sum;
        }
    } else {
        std::fprintf(stderr, "[IR][MLA] kv_a_mqa weight size mismatch\n");
        fflush(stderr);
        return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
    }
    
    // Split aOut into compressed KV (512) and key rope (64)
    const uint32_t kvRank = Generated::ModelConfig::kKvLoraRank;
    const uint32_t ropeDim = Generated::ModelConfig::kRopeDimensionCount;
    
    std::vector<float> compressedKV(aOut.begin(), aOut.begin() + kvRank);
    std::vector<float> keyRope(aOut.begin() + kvRank, aOut.end());
    
    // Step 2: Normalize ONLY the compressed KV (512) via kv_a_norm
    float ss = 0.0f;
    for (uint32_t i = 0; i < kvRank; ++i) {
        ss += compressedKV[i] * compressedKV[i];
    }
    const float invRms = 1.0f / sqrtf(
        ss / float(kvRank) + Generated::ModelConfig::kRmsEps);
    
    for (uint32_t i = 0; i < kvRank; ++i) {
        compressedKV[i] = compressedKV[i] * kvANormW[i] * invRms;
    }
    
    // Step 3: Project compressed KV (512) -> expanded KV (4096) via kv_b
    // kv_b is [4096, 512] -> outputDim=expandedDim=4096, inputDim=512
    const uint32_t expandedDim = kvB.dims[1];  // 4096
    std::vector<float> expanded(expandedDim, 0.0f);
    
    if (!kvBW.empty()) {
        // kvBW layout: [expandedDim][kvRank] = [4096][512]
        if (kvBW.size() == expandedDim * kvRank) {
            for (uint32_t o = 0; o < expandedDim; ++o) {
                float sum = 0.0f;
                const float* row = kvBW.data() + size_t(o) * kvRank;
                for (uint32_t i = 0; i < kvRank; ++i) {
                    sum += row[i] * compressedKV[i];
                }
                expanded[o] = sum;
            }
        } 
        else if (kvBW.size() == kvRank * expandedDim) {
            for (uint32_t o = 0; o < expandedDim; ++o) {
                float sum = 0.0f;
                for (uint32_t i = 0; i < kvRank; ++i) {
                    sum += kvBW[i * expandedDim + o] * compressedKV[i];
                }
                expanded[o] = sum;
            }
        } else {
            std::fprintf(stderr, "[IR][MLA] kv_b weight size mismatch\n");
            fflush(stderr);
            return std::vector<float>(heads * (keyDim + valueDim), 0.0f);
        }
    }
    
    // Step 4: Pack expanded (4096) into MLA heads (16 x 320 = 5120)
    // Per head: 128 K-nope + 64 K-rope + 128 V = 320
    const uint32_t keyNopeDim = keyDim - ropeDim; // 128
    const uint32_t perHead = keyDim + valueDim;   // 320
    
    std::vector<float> mla(size_t(heads) * perHead, 0.0f);
    
    for (uint32_t h = 0; h < heads; ++h) {
        const float* src = expanded.data() + size_t(h) * (keyNopeDim + valueDim);
        float* dst = mla.data() + size_t(h) * perHead;
        
        // K-nope: first 128
        std::copy_n(src, keyNopeDim, dst);
        
        // K-rope: shared 64 (broadcast from keyRope)
        std::copy_n(keyRope.data(), ropeDim, dst + keyNopeDim);
        
        // V: last 128
        std::copy_n(src + keyNopeDim, valueDim, dst + keyDim);
    }
    
    return mla;
}