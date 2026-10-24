#include "GGUFLoader.hpp"
#include <iostream>
#include <cstring>
#include <cmath>
#include <algorithm>

static const std::vector<std::string> ARCH_PREFIXES = {
    "llama", "qwen2", "qwen3", "gemma2", "gemma3", "phi3", "nemotron", "granite", "starcoder2", "glm"
};

uint64_t AlignUp(uint64_t offset, uint64_t alignment) {
    if (alignment == 0) return offset;
    return (offset + alignment - 1) & ~(alignment - 1);
}

void SkipArray(std::ifstream& f);

// The largest string body the loader keeps a copy of.
//
// A GGUF value can be much longer than this. A chat template is a few
// kilobytes, and a tokenizer vocabulary is thousands of entries. The copy is
// bounded so a corrupt length cannot ask for an allocation the size of the
// file, but the bound is on the copy and not on the read: the body is always
// consumed in full.
//
// The bound used to be applied to the read as well, and a value longer than
// it was skipped without its body being consumed. The cursor was then left
// inside the value, and every value after it was read from the wrong
// offset. On a Llama 3.2 file the value that did it was the chat template,
// and the result was that the loader reported 255 tensors and recovered one.
constexpr uint64_t kMaxRetainedGGUFStr = 1024 * 1024;

std::string ReadGGUFStr(std::ifstream& f) {
    uint64_t len = 0;
    f.read(reinterpret_cast<char*>(&len), sizeof(len));
    if (!f) return "";

    if (len <= kMaxRetainedGGUFStr) {
        std::vector<char> buf(static_cast<size_t>(len));
        if (len) f.read(buf.data(), static_cast<std::streamsize>(len));
        if (!f) return "";
        return std::string(buf.data(), static_cast<size_t>(len));
    }

    // Too long to keep, but still part of the stream. The body is read and
    // discarded so the cursor lands on the next value. It is read in chunks
    // so a corrupt length cannot turn into a single enormous read.
    uint64_t remaining = len;
    char scratch[4096];
    while (remaining > 0) {
        const std::streamsize want = static_cast<std::streamsize>(
            remaining < sizeof(scratch) ? remaining : sizeof(scratch));
        f.read(scratch, want);
        if (!f) return "";
        remaining -= static_cast<uint64_t>(want);
    }
    return "";
}

void SkipGGUFValue(uint32_t type, std::ifstream& f) {
    if (type <= 7) {
        uint32_t sz[] = {1, 1, 2, 2, 4, 4, 4, 1};
        f.seekg(sz[type & 7], std::ios::cur);
    } else if (type == 8) {
        ReadGGUFStr(f);
    } else if (type == 9) {
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
    // Handle known-problematic keys FIRST
    if (keyStr == "general.tags" || keyStr == "general.languages") {
        // These are arrays of strings. The array is skipped element by
        // element, because a fixed stride would be wrong for a value whose
        // elements are variable length.
        //
        // The value type decides how the value is skipped. Reading a length
        // here and treating it as the size of the value would be right for a
        // string and wrong for an array, and the two are distinguished by
        // the type rather than by whether the length happens to look
        // plausible.
        if (kvType == 8) {
            ReadGGUFStr(file);
        } else {
            SkipGGUFValue(kvType, file);
        }
        return;
    }

    bool keyHandled = false;

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
        } else if (keyStr == p + ".attention.head_count_kv") {
            // The key/value head count of a grouped-query attention. It is
            // the number the value and key projections are shared over, and
            // it is not the query head count, so it has to be read from the
            // file rather than inferred from the query count.
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.numKVHeads = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.numKVHeads = v; }
            else file.seekg(4, std::ios::cur);
            keyHandled = true;
        }
    }

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
        } else if (keyStr == "general.architecture") {
            if (kvType == 8) {
                ctx->cfg.architecture = ReadGGUFStr(file);
                fprintf(stderr, "[GGUF_META] general.architecture=%s\n", ctx->cfg.architecture.c_str());
            } else {
                SkipGGUFValue(kvType, file);
            }
        } else if (keyStr == "general.alignment") {
            // The alignment of the tensor data section. It decides where the
            // data begins, because a GGUF v3 file has no data offset in its
            // header, and every tensor's offset is relative to that start.
            if (kvType == 4) { uint32_t v = 0; file.read(reinterpret_cast<char*>(&v), 4); ctx->cfg.alignment = v; }
            else if (kvType == 5) { uint64_t v = 0; file.read(reinterpret_cast<char*>(&v), 8); ctx->cfg.alignment = static_cast<uint32_t>(v); }
            else file.seekg(4, std::ios::cur);
        } else if (keyStr == "general.rope.freq_base" || keyStr == "general.architecture.rope.freq_base") {
            double val = 0; file.read(reinterpret_cast<char*>(&val), sizeof(val)); ctx->cfg.ropeThetaGlobal = val;
        } else if (keyStr == "general.rope.dimension_count" || keyStr == "general.architecture.rope.dimension_count") {
            uint32_t val = 0; file.read(reinterpret_cast<char*>(&val), sizeof(val));
        } else if (keyStr == "tokenizer.ggml.tokens") {
            if (kvType == 9) {
                uint32_t arrayType = 0; uint64_t arrayLen = 0;
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
                uint32_t arrayType = 0; uint64_t arrayLen = 0;
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
        } else if (keyStr == "gemma3.context_length") {
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

    for (size_t i = 0; i < ctx->cfg.kvCount; ++i) {
        std::string key = ReadGGUFStr(f);
        uint32_t type = 0;
        f.read(reinterpret_cast<char*>(&type), sizeof(type));
        ParseUniversalGGUFMetadata(key, type, f, ctx);
    }

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

    // Where the tensor data begins.
    //
    // A GGUF v3 file has no data offset in its header. The data section
    // starts after the tensor directory, padded to the alignment the file
    // states, and every tensor's offset is relative to that start.
    //
    // The alignment used to be a hardcoded 64. The specification's default
    // is 32, and a writer that does not state an alignment uses 32, so
    // every tensor's data was read from 32 bytes past where it starts. The
    // bound that catches it is the last tensor in the file, whose end falls
    // outside the pool when the base is wrong.
    const uint64_t alignment = ctx->cfg.alignment ? ctx->cfg.alignment : 32;
    const uint64_t currentPos = static_cast<uint64_t>(f.tellg());
    const uint64_t alignedDataStart = (currentPos + alignment - 1) & ~(alignment - 1);
    f.seekg(static_cast<std::streamoff>(alignedDataStart), std::ios::beg);

    f.seekg(0, std::ios::end);
    uint64_t totalBytes = static_cast<uint64_t>(f.tellg()) - alignedDataStart;
    f.seekg(alignedDataStart, std::ios::beg);

    ctx->tensorWeightsPool.resize(totalBytes);
    f.read(reinterpret_cast<char*>(ctx->tensorWeightsPool.data()), totalBytes);

    for (auto& pair : ctx->tensors) {
        pair.second.dataData = ctx->tensorWeightsPool.data() + pair.second.offset;
    }

    if (ctx->cfg.hiddenDim == 0 || ctx->cfg.intermediateDim == 0) {
        auto sample_wUp = ctx->tensors.find("blk.0.ffn_up.weight");
        if (sample_wUp != ctx->tensors.end() && sample_wUp->second.dims.size() >= 2) {
            if (ctx->cfg.intermediateDim == 0) ctx->cfg.intermediateDim = sample_wUp->second.dims[0];
            if (ctx->cfg.hiddenDim == 0) ctx->cfg.hiddenDim = sample_wUp->second.dims[1];
        }
    }

    fprintf(stderr, "[GGUF_META] architecture_supported=%d\n",
            (ctx->cfg.architecture == "llama" || ctx->cfg.architecture == "qwen2" ||
             ctx->cfg.architecture == "qwen3" || ctx->cfg.architecture == "gemma2" ||
             ctx->cfg.architecture == "gemma3" || ctx->cfg.architecture == "phi3" ||
             ctx->cfg.architecture == "nemotron" || ctx->cfg.architecture == "granite" ||
             ctx->cfg.architecture == "starcoder2" || ctx->cfg.architecture == "glm") ? 1 : 0);
    fprintf(stderr, "[GGUF_META] embedding_length=%zu block_count=%zu attention.head_count=%zu attention.head_count_kv=%zu feed_forward_length=%zu context_length=%zu\n",
            ctx->cfg.hiddenDim, ctx->cfg.numLayers, ctx->cfg.numHeads, ctx->cfg.numKVHeads,
            ctx->cfg.intermediateDim, ctx->cfg.maxSeqLen);

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

    for (size_t i = 0; i < ctx->cfg.kvCount; ++i) {
        std::string key = ReadGGUFStr(firstFile);
        uint32_t type = 0;
        firstFile.read(reinterpret_cast<char*>(&type), sizeof(type));
        ParseUniversalGGUFMetadata(key, type, firstFile, ctx);
    }

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
            case 0:  bytesToRead = elements * 4; break;
            case 1:  bytesToRead = elements * 2; break;
            case 2:  bytesToRead = elements * 4; break;
            case 3:  bytesToRead = elements * 4; break;
            case 4:  bytesToRead = elements * 5 / 8 + 16; break;
            case 5:  bytesToRead = elements * 5 / 8 + 16; break;
            case 6:  bytesToRead = elements * 4; break;
            case 7:  bytesToRead = elements * 1; break;
            case 8:  bytesToRead = elements / 4 + 16; break;
            case 9:  bytesToRead = elements * 3 / 8 + 16; break;
            case 10: bytesToRead = elements / 2 + 16; break;
            case 11: bytesToRead = elements * 5 / 8 + 16; break;
            case 12: bytesToRead = elements * 6 / 8 + 16; break;
            case 13: bytesToRead = elements * 1; break;
            default: bytesToRead = elements * 4; break;
        }

        std::vector<uint8_t> blockData(bytesToRead);
        sourceBlob.read(reinterpret_cast<char*>(blockData.data()), bytesToRead);

        if (!sourceBlob.good()) {
            fprintf(stderr, "[ERROR] Failed to read tensor data for %s at offset %zu in shard 0\n",
                    meta.name.c_str(), meta.offset);
            return false;
        }

        uint64_t totalBytesLoaded = 0;

        meta.dataData = ctx->tensorWeightsPool.data() + ctx->tensorWeightsPool.size();
        ctx->tensorWeightsPool.insert(ctx->tensorWeightsPool.end(), blockData.begin(), blockData.end());
        totalBytesLoaded += bytesToRead;    }

    fprintf(stderr, "[INIT] Deep2Engine::initialize hiddenDim=%zu vocabSize=%zu numLayers=%zu numHeads=%zu\n",
            ctx->cfg.hiddenDim, ctx->cfg.vocabSize, ctx->cfg.numLayers, ctx->cfg.numHeads);

    return true;
}