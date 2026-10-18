#include "GGUFLoader.hpp"
#include <iostream>
#include <cstring>
#include <cmath>
#include <algorithm>

static const std::vector<std::string> ARCH_PREFIXES = {
    "llama", "qwen2", "gemma2", "phi3", "nemotron", "granite", "starcoder2", "glm"
};

void SkipArray(std::ifstream& f);

std::string ReadGGUFStr(std::ifstream& f) {
    uint64_t len = 0;
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!f || len > 2048) return "";
    std::vector<char> buf(len);
    f.read(buf.data(), len);
    return std::string(buf.data(), len);
}

void SkipGGUFValue(uint32_t type, std::ifstream& f) {
    if (type <= 7) { // Primitive types: 0=U8, 1=I8, 2=U16, 3=I16, 4=U32, 5=I32, 6=F32, 7=BOOL
        // GGUF spec: BOOL (type 7) is 1 byte (uint8), not 8 bytes
        uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
        f.seekg(sz[type & 7], std::ios::cur);
    } else if (type == 8) { // STRING (type 8 in GGUF spec)
        ReadGGUFStr(f);
    } else if (type == 9) { // ARRAY (type 9 in GGUF spec)
        SkipArray(f);
    } else { // Unknown type (10=U64, 11=I64, 12=F64)
        uint32_t sub = 0;
        uint64_t len = 0;
        f.read(reinterpret_cast<char*>(&sub), sizeof(sub));
        f.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (sub == 9) {
            for (uint64_t i = 0; i < len; ++i) ReadGGUFStr(f);
        } else if (sub == 8) {
            for (uint64_t i = 0; i < len; ++i) SkipArray(f);
        } else {
            uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
            f.seekg(len * sz[sub & 7], std::ios::cur);
        }
    }
}

void SkipArray(std::ifstream& f) {
    // GGUF array format: [array_type: uint32] [array_len: uint64] [elements...]
    // array_type is the type of elements (not the array type itself)
    uint32_t arrayType = 0;
    uint64_t arrayLen = 0;
    f.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
    f.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
    if (arrayLen > 1000000) {
        fprintf(stderr, "[WARN] Array length absurdly large (%zu)\n", arrayLen);
        return;
    }
    if (arrayType == 8) {  // String elements
        for (uint64_t i = 0; i < arrayLen; ++i) ReadGGUFStr(f);
    } else if (arrayType == 9) {  // Nested array elements
        for (uint64_t i = 0; i < arrayLen; ++i) SkipArray(f);
    } else {  // Primitive elements
        uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
        f.seekg(arrayLen * sz[arrayType & 7], std::ios::cur);
    }
}

float SafeFp16ToFloat32(uint16_t fp16) {
    uint32_t sign = (fp16 & 0x8000) << 16;
    uint32_t exp  = (fp16 & 0x7C00) >> 10;
    uint32_t frac = (fp16 & 0x03FF);
    uint32_t f32  = 0;
    
    if (exp == 31) {
        f32 = sign | 0x7F800000 | (frac << 13);
    } else if (exp == 0) {
        if (frac != 0) {
            while ((frac & 0x0400) == 0) {
                frac <<= 1;
                exp--;
            }
            exp++;
            frac &= ~0x0400;
            f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
        } else {
            f32 = sign;
        }
    } else {
        f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
    }
    
    float res;
    std::memcpy(&res, &f32, sizeof(float));
    return std::isnan(res) || std::isinf(res) ? 0.0f : res;
}

float ConvertFp16ToFloat32(uint16_t fp16) {
    return SafeFp16ToFloat32(fp16);
}

std::string ExtractJSONField(const std::string& json, const std::string& key) {
    size_t keyPos = json.find("\"" + key + "\"");
    if (keyPos == std::string::npos) return "";
    
    size_t colonPos = json.find(":", keyPos);
    if (colonPos == std::string::npos) return "";
    
    size_t startPos = json.find_first_not_of(" \t\r\n\"", colonPos + 1);
    if (startPos == std::string::npos) return "";
    
    size_t endPos;
    if (json[startPos - 1] == '"') {
        endPos = json.find("\"", startPos);
    } else {
        endPos = json.find_first_of(",}\r\n \t", startPos);
    }
    
    if (endPos == std::string::npos) return "";
    return json.substr(startPos, endPos - startPos);
}

bool ParseOllamaManifest(const std::string& manifestPath, EngineContext* ctx) {
    std::ifstream f(manifestPath);
    if (!f.is_open()) return false;
    
    std::string jsonStr((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::string mediaType = ExtractJSONField(jsonStr, "mediaType");
    std::string digest = ExtractJSONField(jsonStr, "digest");
    
    std::cout << "[MANIFEST_AUDIT] Parsing Ollama Manifest Metadata:"
              << "\n  -> Model MediaType : " << (mediaType.empty() ? "Legacy/Unknown" : mediaType)
              << "\n  -> Layer Hash Sum  : " << (digest.empty() ? "None/Direct" : digest) << "\n";
    return true;
}

void ParseUniversalGGUFMetadata(const std::string& keyStr, uint32_t kvType, std::ifstream& file, EngineContext* ctx) {
    // Handle specific known-problematic keys FIRST, before generic type dispatch
    if (keyStr == "general.tags" || keyStr == "general.languages") {
        // These are arrays of strings, sometimes written as type 9 (string) instead of type 8 (array)
        std::streampos pos = file.tellg();
        uint64_t len = 0;
        file.read(reinterpret_cast<char*>(&len), sizeof(len));
        if (len > 0 && len < 10000) {
            file.seekg(len, std::ios::cur);
        } else {
            file.seekg(pos);
            SkipArray(file);
        }
        return;
    }
    
    bool keyHandled = false;

    // 1. Scan for Dynamic Architecture Geometry Overrides
    for (const auto& prefix : ARCH_PREFIXES) {
        if (keyStr == prefix + ".embedding_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.hiddenDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.hiddenDim = v; }
            else { file.seekg(8, std::ios::cur); }
            keyHandled = true;
        } else if (keyStr == prefix + ".block_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numLayers = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.numLayers = v; }
            else { file.seekg(8, std::ios::cur); }
            keyHandled = true;
        } else if (keyStr == prefix + ".feed_forward_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.intermediateDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.intermediateDim = v; }
            else { file.seekg(8, std::ios::cur); }
            keyHandled = true;
        } else if (keyStr == prefix + ".attention.head_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numHeads = v; }
            else { file.seekg(4, std::ios::cur); }
            keyHandled = true;
        }
    }

    // 2. Global Standalone Metadata Keys Fallback (e.g., general.* namespaces)
    if (!keyHandled) {
        if (keyStr == "general.embedding_length" || keyStr == "general.architecture.embedding_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.hiddenDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.hiddenDim = v; }
            else { file.seekg(8, std::ios::cur); }
        } else if (keyStr == "general.block_count" || keyStr == "general.architecture.block_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numLayers = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.numLayers = v; }
            else { file.seekg(8, std::ios::cur); }
        } else if (keyStr == "general.feed_forward_length" || keyStr == "general.architecture.feed_forward_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.intermediateDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.intermediateDim = v; }
            else { file.seekg(8, std::ios::cur); }
        } else if (keyStr == "general.attention.head_count" || keyStr == "general.architecture.attention.head_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numHeads = v; }
            else { file.seekg(4, std::ios::cur); }
        } else if (keyStr == "general.attention.layer_norm_rms_epsilon") {
            // Read and discard (float32)
            file.seekg(4, std::ios::cur);
        } else if (keyStr == "general.rope.freq_base" || keyStr == "general.architecture.rope.freq_base") {
            double val = 0; file.read(reinterpret_cast<char*>(&val), sizeof(val)); ctx->cfg.ropeThetaGlobal = val;
        } else if (keyStr == "general.rope.dimension_count" || keyStr == "general.architecture.rope.dimension_count") {
            uint32_t val = 0; file.read(reinterpret_cast<char*>(&val), sizeof(val));
        } else if (keyStr == "tokenizer.ggml.tokens") {
            // tokenizer.ggml.tokens is an array of strings
            // kvType should be 9 (ARRAY). Format: [array_type: uint32] [array_len: uint64] [elements...]
            if (kvType == 9) {
                uint32_t arrayType = 0;
                uint64_t arrayLen = 0;
                file.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
                file.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
                if (arrayLen > 1000000) {
                    // Not a valid array, treat as single string (fallback)
                    // Seek back to re-read as string
                    file.seekg(-12, std::ios::cur);
                    ReadGGUFStr(file);
} else {
                    ctx->cfg.vocabSize = arrayLen;
                    if (arrayType == 8) {  // String elements
                        for (uint64_t i = 0; i < arrayLen; ++i) ReadGGUFStr(file);
                    } else if (arrayType == 9) {  // Nested arrays
                        for (uint64_t i = 0; i < arrayLen; ++i) SkipArray(file);
                    } else {  // Primitive elements
                        uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
                        file.seekg(arrayLen * sz[arrayType & 7], std::ios::cur);
                    }
                }
            } else if (kvType == 8) {
                // Sometimes incorrectly written as string (type 8) - try to parse as array
                std::streampos pos = file.tellg();
                uint32_t arrayType = 0;
                uint64_t arrayLen = 0;
                file.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
                file.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
                if (arrayLen > 1000000) {
                    file.seekg(pos);
                    ReadGGUFStr(file);
                } else {
                    ctx->cfg.vocabSize = arrayLen;
                    if (arrayType == 8) {
                        for (uint64_t i = 0; i < arrayLen; ++i) ReadGGUFStr(file);
                    } else if (arrayType == 9) {
                        for (uint64_t i = 0; i < arrayLen; ++i) SkipArray(file);
                    } else {
                        uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
                        file.seekg(arrayLen * sz[arrayType & 7], std::ios::cur);
                    }
                }
            } else {
                // Other types - skip
                SkipGGUFValue(kvType, file);
            }
        } else if (keyStr == "tokenizer.ggml.token_type") {
            // Array of int32
            SkipGGUFValue(kvType, file);
        } else if (keyStr == "tokenizer.ggml.merges") {
            // Array of strings
            SkipGGUFValue(kvType, file);
        } else if (keyStr == "tokenizer.ggml.bos_token_id" || keyStr == "tokenizer.ggml.eos_token_id" ||
                   keyStr == "tokenizer.ggml.unknown_token_id" || keyStr == "tokenizer.ggml.padding_token_id") {
            // uint32 values
            file.seekg(4, std::ios::cur);
        } else if (keyStr == "phi3.context_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.maxSeqLen = v; }
            else { file.seekg(4, std::ios::cur); }
        } else if (keyStr == "phi3.rope.scaling.original_context_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); }
            else { file.seekg(4, std::ios::cur); }
        } else {
            // Secure skip sequence for unknown/unhandled keys
            SkipGGUFValue(kvType, file);
        }
    }
}

bool LoadUniversalBlob(const std::string& path, EngineContext* ctx) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        fprintf(stderr, "[ERROR] Could not open model file: %s\n", path.c_str());
        return false;
    }

    f.read(reinterpret_cast<char*>(&ctx->cfg.magic), 4);
    f.read(reinterpret_cast<char*>(&ctx->cfg.version), 4);
    if (ctx->cfg.magic != 0x46554747) {  // "GGUF"
        fprintf(stderr, "[ERROR] Invalid GGUF magic: 0x%08X\n", ctx->cfg.magic);
        return false;
    }

    f.read(reinterpret_cast<char*>(&ctx->cfg.tensorCount), 8);
    f.read(reinterpret_cast<char*>(&ctx->cfg.kvCount), 8);

    // Parse Dynamic Prefix Metadata arrays
    for (size_t i = 0; i < ctx->cfg.kvCount; ++i) {
        std::string key = ReadGGUFStr(f);
        uint32_t type = 0;
        f.read(reinterpret_cast<char*>(&type), sizeof(type));
        ParseUniversalGGUFMetadata(key, type, f, ctx);
    }

    // Read Layer Allocation Layout indices
    for (size_t i = 0; i < ctx->cfg.tensorCount; ++i) {
        GGUFTensorMeta meta;
        meta.name = ReadGGUFStr(f);
        uint32_t nDims = 0;
        f.read(reinterpret_cast<char*>(&nDims), 4);
        meta.dims.resize(nDims);
        if (nDims > 0) f.read(reinterpret_cast<char*>(meta.dims.data()), nDims * 8);
        f.read(reinterpret_cast<char*>(&meta.type), 4);
        f.read(reinterpret_cast<char*>(&meta.offset), 8);
        ctx->tensors[meta.name] = meta;
    }

    // Align memory segment lines to 64-byte boundaries
    uint64_t currentPos = f.tellg();
    uint64_t pad = (currentPos + 63) & ~63;
    f.seekg(pad, std::ios::beg);
    uint64_t alignedDataStart = f.tellg();

    // Read physical weight arrays straight into aligned heap storage
    f.seekg(0, std::ios::end);
    uint64_t totalBytes = static_cast<uint64_t>(f.tellg()) - alignedDataStart;
    f.seekg(alignedDataStart, std::ios::beg);

    ctx->tensorWeightsPool.resize(totalBytes);
    f.read(reinterpret_cast<char*>(ctx->tensorWeightsPool.data()), totalBytes);

    // Bind raw internal device mapping coordinates
    for (auto& pair : ctx->tensors) {
        pair.second.dataData = ctx->tensorWeightsPool.data() + pair.second.offset;
    }

    // Dynamic Geometry Adaption Guard - ONLY if metadata not parsed from GGUF keys
    // (i.e., values still zero). Don't override correctly parsed phi3.* metadata.
    if (ctx->cfg.hiddenDim == 0 || ctx->cfg.intermediateDim == 0) {
        auto sample_wUp = ctx->tensors.find("blk.0.ffn_up.weight");
        if (sample_wUp != ctx->tensors.end() && sample_wUp->second.dims.size() >= 2) {
            // dims[0] = output_dim (intermediate), dims[1] = input_dim (hidden)
            if (ctx->cfg.intermediateDim == 0) ctx->cfg.intermediateDim = sample_wUp->second.dims[0];
            if (ctx->cfg.hiddenDim == 0) ctx->cfg.hiddenDim = sample_wUp->second.dims[1];
        }
    }

    return true;
}