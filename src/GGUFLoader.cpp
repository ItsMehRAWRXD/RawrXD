#include "GGUFLoader.hpp"
#include <iostream>
#include <cstring>
#include <cmath>
#include <algorithm>

void SkipArray(std::ifstream& f);

static const std::vector<std::string> ARCH_PREFIXES = {
    "llama", "qwen2", "gemma2", "phi3", "nemotron", "granite", "starcoder2", "glm"
};

uint64_t AlignUp(uint64_t offset, uint64_t alignment) {
    if (alignment == 0) return offset;
    return (offset + alignment - 1) & ~(alignment - 1);
}

std::string ReadGGUFStr(std::ifstream& f) {
    uint64_t len = 0;
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!f || len > 2048) return "";
    std::vector<char> buf(len);
    f.read(buf.data(), len);
    return std::string(buf.data(), len);
}

void SkipGGUFValue(uint32_t type, std::ifstream& f) {
    if (type <= 7) {
        uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
        f.seekg(sz[type & 7], std::ios::cur);
    } else if (type == 8) { // STRING
        ReadGGUFStr(f);
    } else if (type == 9) { // ARRAY
        SkipArray(f);
    } else {
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
    uint32_t arrayType = 0;
    uint64_t arrayLen = 0;
    f.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
    f.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
    if (arrayLen > 1000000) {
        fprintf(stderr, "[WARN] Array length absurdly large (%zu)\n", arrayLen);
        return;
    }
    if (arrayType == 8) {
        for (uint64_t i = 0; i < arrayLen; ++i) ReadGGUFStr(f);
    } else if (arrayType == 9) {
        for (uint64_t i = 0; i < arrayLen; ++i) SkipArray(f);
    } else {
        uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 8};
        f.seekg(arrayLen * sz[arrayType & 7], std::ios::cur);
    }
}

float SafeFp16ToFloat32(uint16_t fp16) {
    uint32_t sign = (fp16 & 0x8000) << 16;
    uint32_t exp  = (fp16 & 0x7C00) >> 10;
    uint32_t frac = (fp16 & 0x03FF);
    uint32_t f32  = 0;
    if (exp == 31) f32 = sign | 0x7F800000 | (frac << 13);
    else if (exp == 0) {
        if (frac != 0) {
            while ((frac & 0x0400) == 0) { frac <<= 1; exp--; }
            exp++; frac &= ~0x0400; f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
        } else f32 = sign;
    } else f32 = sign | ((exp + (127 - 15)) << 23) | (frac << 13);
    float res; std::memcpy(&res, &f32, sizeof(float));
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
    size_t endPos = json[startPos - 1] == '"' ? json.find("\"", startPos) : json.find_first_of(",}\r\n \t", startPos);
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
    // Handle known-problematic keys FIRST, before generic type dispatch
    if (keyStr == "general.tags" || keyStr == "general.languages") {
        // These are arrays of strings, sometimes written as type 9 (array) or type 8 (string)
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
    for (const auto& p : ARCH_PREFIXES) {
        if (keyStr == p + ".embedding_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.hiddenDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.hiddenDim = v; }
            else file.seekg(8, std::ios::cur);
            keyHandled = true;
        } else if (keyStr == p + ".block_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numLayers = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.numLayers = v; }
            else file.seekg(8, std::ios::cur);
            keyHandled = true;
        } else if (keyStr == p + ".feed_forward_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.intermediateDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.intermediateDim = v; }
            else file.seekg(8, std::ios::cur);
            keyHandled = true;
        } else if (keyStr == p + ".attention.head_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numHeads = v; }
            else file.seekg(4, std::ios::cur);
            keyHandled = true;
        }
    }

    // 2. Global Standalone Metadata Keys Fallback
    if (!keyHandled) {
        if (keyStr == "general.embedding_length" || keyStr == "general.architecture.embedding_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.hiddenDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.hiddenDim = v; }
            else file.seekg(8, std::ios::cur);
        } else if (keyStr == "general.block_count" || keyStr == "general.architecture.block_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numLayers = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.numLayers = v; }
            else file.seekg(8, std::ios::cur);
        } else if (keyStr == "general.feed_forward_length" || keyStr == "general.architecture.feed_forward_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.intermediateDim = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.intermediateDim = v; }
            else file.seekg(8, std::ios::cur);
        } else if (keyStr == "general.attention.head_count" || keyStr == "general.architecture.attention.head_count") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numHeads = v; }
            else file.seekg(4, std::ios::cur);
        } else if (keyStr == "general.attention.layer_norm_rms_epsilon") {
            file.seekg(4, std::ios::cur);
        } else if (keyStr == "general.rope.freq_base" || keyStr == "general.architecture.rope.freq_base") {
            double val = 0; file.read(reinterpret_cast<char*>(&val), sizeof(val)); ctx->cfg.ropeThetaGlobal = val;
        } else if (keyStr == "general.rope.dimension_count" || keyStr == "general.architecture.rope.dimension_count") {
            uint32_t val = 0; file.read(reinterpret_cast<char*>(&val), sizeof(val));
        } else if (keyStr == "tokenizer.ggml.tokens") {
            if (kvType == 9) {
                uint32_t arrayType = 0;
                uint64_t arrayLen = 0;
                file.read(reinterpret_cast<char*>(&arrayType), sizeof(arrayType));
                file.read(reinterpret_cast<char*>(&arrayLen), sizeof(arrayLen));
                if (arrayLen > 1000000) {
                    file.seekg(-12, std::ios::cur);
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
            } else if (kvType == 8) {
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
                SkipGGUFValue(kvType, file);
            }
        } else if (keyStr == "tokenizer.ggml.token_type") {
            SkipGGUFValue(kvType, file);
        } else if (keyStr == "tokenizer.ggml.merges") {
            SkipGGUFValue(kvType, file);
        } else if (keyStr == "tokenizer.ggml.bos_token_id" || keyStr == "tokenizer.ggml.eos_token_id" ||
                   keyStr == "tokenizer.ggml.unknown_token_id" || keyStr == "tokenizer.ggml.padding_token_id") {
            file.seekg(4, std::ios::cur);
        } else if (keyStr == "phi3.context_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.maxSeqLen = v; }
            else file.seekg(4, std::ios::cur);
        } else if (keyStr == "phi3.rope.scaling.original_context_length") {
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); }
            else file.seekg(4, std::ios::cur);
        } else {
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
    if (ctx->cfg.magic != 0x46554747) {
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
        meta.dataData = nullptr;
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

    // Dynamic Geometry Adaption Guard - only if config elements were omitted from GGUF metadata
    if (ctx->cfg.hiddenDim == 0 || ctx->cfg.intermediateDim == 0) {
        auto sample_wUp = ctx->tensors.find("blk.0.ffn_up.weight");
        if (sample_wUp != ctx->tensors.end() && sample_wUp->second.dims.size() >= 2) {
            // dims[0] = output_dim (intermediate), dims[1] = input_dim (hidden)
            if (ctx->cfg.intermediateDim == 0) ctx->cfg.intermediateDim = sample_wUp->second.dims[0];
            if (ctx->cfg.hiddenDim == 0) ctx->cfg.hiddenDim = sample_wUp->second.dims[1];
        }
    }

    fprintf(stderr, "[INIT] Deep2Engine::initialize hiddenDim=%zu vocabSize=%zu numLayers=%zu numHeads=%zu\n",
            ctx->cfg.hiddenDim, ctx->cfg.vocabSize, ctx->cfg.numLayers, ctx->cfg.numHeads);

    return true;
}

bool LoadUniversalBlobMultiShard(const std::vector<std::string>& shardPaths, EngineContext* ctx) {
    if (shardPaths.empty()) {
        fprintf(stderr, "[ERROR] No shard files provided\n");
        return false;
    }

    std::ifstream firstFile(shardPaths[0], std::ios::binary);
    if (!firstFile.is_open()) {
        fprintf(stderr, "[ERROR] Could not open first shard: %s\n", shardPaths[0].c_str());
        return false;
    }

    uint32_t magic, version;
    firstFile.read(reinterpret_cast<char*>(&magic), 4);
    firstFile.read(reinterpret_cast<char*>(&version), 4);
    if (magic != 0x46554747) {
        fprintf(stderr, "[ERROR] Invalid GGUF magic in first shard: 0x%08X\n", magic);
        return false;
    }

    firstFile.read(reinterpret_cast<char*>(&ctx->cfg.tensorCount), 8);
    firstFile.read(reinterpret_cast<char*>(&ctx->cfg.kvCount), 8);

    // Parse Dynamic Prefix Metadata arrays from first shard
    for (size_t i = 0; i < ctx->cfg.kvCount; ++i) {
        std::string key = ReadGGUFStr(firstFile);
        uint32_t type = 0;
        firstFile.read(reinterpret_cast<char*>(&type), sizeof(type));
        ParseUniversalGGUFMetadata(key, type, firstFile, ctx);
    }

    // Read Layer Allocation Layout indices from first shard
    for (size_t i = 0; i < ctx->cfg.tensorCount; ++i) {
        GGUFTensorMeta meta;
        meta.name = ReadGGUFStr(firstFile);
        uint32_t nDims = 0;
        firstFile.read(reinterpret_cast<char*>(&nDims), 4);
        meta.dims.resize(nDims);
        if (nDims > 0) firstFile.read(reinterpret_cast<char*>(meta.dims.data()), nDims * 8);
        firstFile.read(reinterpret_cast<char*>(&meta.type), 4);
        firstFile.read(reinterpret_cast<char*>(&meta.offset), 8);
        meta.dataData = nullptr;
        ctx->tensors[meta.name] = meta;
    }

    firstFile.close();

    // Calculate tensor data start offset for each shard
    std::vector<uint64_t> shardDataStarts(shardPaths.size());
    for (size_t s = 0; s < shardPaths.size(); ++s) {
        std::ifstream sf(shardPaths[s], std::ios::binary);
        if (!sf.is_open()) {
            fprintf(stderr, "[ERROR] Could not open shard %zu: %s\n", s, shardPaths[s].c_str());
            return false;
        }
        sf.seekg(24, std::ios::beg);
        for (size_t i = 0; i < ctx->cfg.kvCount; ++i) {
            std::string key = ReadGGUFStr(sf);
            uint32_t type = 0;
            sf.read(reinterpret_cast<char*>(&type), sizeof(type));
            SkipGGUFValue(type, sf);
        }
        uint64_t tensorInfoStart = sf.tellg();
        for (size_t i = 0; i < ctx->cfg.tensorCount; ++i) {
            std::string name = ReadGGUFStr(sf);
            uint32_t nDims = 0;
            sf.read(reinterpret_cast<char*>(&nDims), 4);
            sf.seekg(nDims * 8, std::ios::cur);
            sf.seekg(8, std::ios::cur);
        }
        uint64_t tensorInfoEnd = sf.tellg();
        shardDataStarts[s] = AlignUp(tensorInfoEnd, 64);
        sf.close();
    }

    // Read tensor data from each shard
    size_t totalBytesLoaded = 0;
    for (auto& pair : ctx->tensors) {
        GGUFTensorMeta& meta = pair.second;
        std::ifstream sourceBlob(shardPaths[0], std::ios::binary);
        if (!sourceBlob.is_open()) {
            fprintf(stderr, "[ERROR] Could not open shard 0: %s\n", shardPaths[0].c_str());
            return false;
        }
        sourceBlob.seekg(shardDataStarts[0] + meta.offset, std::ios::beg);
        if (!sourceBlob.good()) {
            fprintf(stderr, "[ERROR] Could not seek to tensor %s at offset %zu in shard 0\n",
                    meta.name.c_str(), meta.offset);
            return false;
        }

        uint64_t elements = 1;
        for (auto d : meta.dims) elements *= d;

        uint64_t bytesToRead = 0;
        switch (meta.type) {
            case 0:  bytesToRead = elements * 4; break;   // Q4_0
            case 1:  bytesToRead = elements * 2; break;   // Q4_1
            case 2:  bytesToRead = elements * 4; break;   // Q5_0
            case 3:  bytesToRead = elements * 4; break;   // Q5_1
            case 6:  bytesToRead = elements * 4; break;   // Q8_0
            case 7:  bytesToRead = elements * 1; break;   // Q8_1
            case 8:  bytesToRead = elements / 4 + 16; break; // Q2_K
            case 9:  bytesToRead = elements * 3 / 8 + 16; break; // Q3_K
            case 10: bytesToRead = elements / 2 + 16; break; // Q4_K
            case 11: bytesToRead = elements * 5 / 8 + 16; break; // Q5_K
            case 12: bytesToRead = elements * 6 / 8 + 16; break; // Q6_K
            case 13: bytesToRead = elements * 1; break;   // Q8_K
            default: bytesToRead = elements * 4; break;
        }

        std::vector<uint8_t> blockData(bytesToRead);
        sourceBlob.read(reinterpret_cast<char*>(blockData.data()), bytesToRead);

        if (!sourceBlob.good()) {
            fprintf(stderr, "[ERROR] Failed to read tensor data for %s at offset %zu in shard 0\n",
                    meta.name.c_str(), meta.offset);
            return false;
        }

        meta.dataData = ctx->tensorWeightsPool.data() + ctx->tensorWeightsPool.size();
        ctx->tensorWeightsPool.insert(ctx->tensorWeightsPool.end(), blockData.begin(), blockData.end());
        totalBytesLoaded += bytesToRead;
    }

    fprintf(stderr, "[INIT] Deep2Engine::initialize hiddenDim=%zu vocabSize=%zu numLayers=%zu numHeads=%zu\n",
            ctx->cfg.hiddenDim, ctx->cfg.vocabSize, ctx->cfg.numLayers, ctx->cfg.numHeads);

    return true;
}