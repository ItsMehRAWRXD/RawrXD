#include "GGUFLoader.hpp"
#include <iostream>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <limits>
#include <utility>
#include <new>

static const std::vector<std::string> ARCH_PREFIXES = {
    "llama", "qwen2", "gemma2", "phi3", "nemotron", "granite", "starcoder2", "glm"
};

namespace {
constexpr uint64_t kMaxMetadataString = 64ULL * 1024 * 1024;
constexpr uint64_t kMaxMetadataElements = 16ULL * 1024 * 1024;
constexpr unsigned kMaxMetadataDepth = 16;

bool SkipBytes(std::ifstream& f, uint64_t count) {
    const auto begin = f.tellg();
    if (begin < 0) { f.setstate(std::ios::failbit); return false; }
    f.seekg(0, std::ios::end);
    const auto end = f.tellg();
    if (end < begin || static_cast<uint64_t>(end - begin) < count) {
        f.setstate(std::ios::failbit);
        return false;
    }
    f.seekg(begin + static_cast<std::streamoff>(count), std::ios::beg);
    return static_cast<bool>(f);
}

bool SkipValue(std::ifstream& f, uint32_t type, unsigned depth);

bool SkipArrayValue(std::ifstream& f, unsigned depth) {
    uint32_t elementType = 0;
    uint64_t count = 0;
    f.read(reinterpret_cast<char*>(&elementType), sizeof(elementType));
    f.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!f || depth >= kMaxMetadataDepth || count > kMaxMetadataElements ||
        elementType > 12 || elementType == 9) {
        f.setstate(std::ios::failbit);
        return false;
    }
    // Fixed-width arrays are skipped as one checked extent, not millions of seeks.
    static constexpr uint8_t widths[13] = {1,1,2,2,4,4,4,1,0,0,8,8,8};
    if (widths[elementType] != 0) {
        if (count > UINT64_MAX / widths[elementType]) {
            f.setstate(std::ios::failbit); return false;
        }
        return SkipBytes(f, count * widths[elementType]);
    }
    for (uint64_t i = 0; i < count; ++i) {
        if (!SkipValue(f, elementType, depth + 1)) return false;
    }
    return true;
}

bool SkipValue(std::ifstream& f, uint32_t type, unsigned depth) {
    static constexpr uint8_t sizes[13] = {1,1,2,2,4,4,4,1,0,0,8,8,8};
    if (type > 12 || depth > kMaxMetadataDepth) {
        f.setstate(std::ios::failbit);
        return false;
    }
    if (type == 8) {
        uint64_t length = 0;
        f.read(reinterpret_cast<char*>(&length), sizeof(length));
        if (!f || length > kMaxMetadataString) {
            f.setstate(std::ios::failbit);
            return false;
        }
        return SkipBytes(f, length);
    }
    if (type == 9) return SkipArrayValue(f, depth);
    return SkipBytes(f, sizes[type]);
}
} // namespace

void SkipArray(std::ifstream& f) { (void)SkipArrayValue(f, 0); }

std::string ReadGGUFStr(std::ifstream& f) {
    uint64_t length = 0;
    f.read(reinterpret_cast<char*>(&length), sizeof(length));
    if (!f || length > kMaxMetadataString) {
        f.setstate(std::ios::failbit);
        return {};
    }
    std::string result;
    if (length > result.max_size()) {
        f.setstate(std::ios::failbit);
        return {};
    }
    result.resize(static_cast<size_t>(length));
    if (length) f.read(&result[0], static_cast<std::streamsize>(length));
    return f ? result : std::string{};
}

void SkipGGUFValue(uint32_t type, std::ifstream& f) {
    (void)SkipValue(f, type, 0);
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

void ParseUniversalGGUFMetadata(const std::string& key, uint32_t type,
                                std::ifstream& file, EngineContext* ctx) {
    if (!ctx) { file.setstate(std::ios::failbit); return; }
    // All keys are consumed according to their declared GGUF type.
    // Never guess an alternative encoding from the key name.
    const auto suffix = [&key](const char* part) {
        const std::string tail(part);
        return key.size() > tail.size() &&
               key.compare(key.size() - tail.size(), tail.size(), tail) == 0 &&
               key[key.size() - tail.size() - 1] == '.';
    };
    if (key == "general.alignment") {
        if (type != 4) { file.setstate(std::ios::failbit); return; }
        uint32_t alignment = 0;
        file.read(reinterpret_cast<char*>(&alignment), 4);
        if (!file || alignment < 8 || alignment > 4096 ||
            (alignment & (alignment - 1)) != 0) {
            file.setstate(std::ios::failbit); return;
        }
        ctx->cfg.ggufAlignment = alignment;
        return;
    }
    const bool isGeometry = suffix("embedding_length") || suffix("block_count") ||
        suffix("feed_forward_length") || suffix("attention.head_count") ||
        suffix("attention.head_count_kv") || suffix("context_length");
    if (isGeometry && type != 4 && type != 10) {
        file.setstate(std::ios::failbit); return;
    }
    if (isGeometry) {
        uint64_t value = 0;
        if (type == 4) {
            uint32_t v = 0;
            file.read(reinterpret_cast<char*>(&v), 4);
            value = v;
        } else {
            file.read(reinterpret_cast<char*>(&value), 8);
        }
        if (!file || value == 0 || value > UINT32_MAX) {
            file.setstate(std::ios::failbit); return;
        }
        if (suffix("embedding_length")) ctx->cfg.hiddenDim = static_cast<size_t>(value);
        else if (suffix("block_count")) ctx->cfg.numLayers = static_cast<size_t>(value);
        else if (suffix("feed_forward_length")) ctx->cfg.intermediateDim = static_cast<size_t>(value);
        else if (suffix("attention.head_count_kv")) ctx->cfg.numKVHeads = static_cast<size_t>(value);
        else if (suffix("attention.head_count")) ctx->cfg.numHeads = static_cast<size_t>(value);
        else if (suffix("context_length")) ctx->cfg.maxSeqLen = static_cast<size_t>(value);
        return;
    }
    if (key == "tokenizer.ggml.tokens" && type != 9) {
        file.setstate(std::ios::failbit); return;
    }
    if (key == "tokenizer.ggml.tokens") {
        const auto pos = file.tellg();
        uint32_t elementType = 0;
        uint64_t count = 0;
        file.read(reinterpret_cast<char*>(&elementType), 4);
        file.read(reinterpret_cast<char*>(&count), 8);
        if (!file || elementType != 8 || count > kMaxMetadataElements) {
            file.setstate(std::ios::failbit); return;
        }
        ctx->cfg.vocabSize = static_cast<size_t>(count);
        file.seekg(pos);
    }
    if (suffix("rope.freq_base") && type != 6) {
        file.setstate(std::ios::failbit); return;
    }
    if (suffix("rope.freq_base")) {
        float theta = 0;
        file.read(reinterpret_cast<char*>(&theta), 4);
        if (!file || !std::isfinite(theta) || theta <= 0) {
            file.setstate(std::ios::failbit); return;
        }
        ctx->cfg.ropeThetaGlobal = theta;
        return;
    }
    SkipGGUFValue(type, file);
}

bool LoadUniversalBlob(const std::string& path, EngineContext* ctx) {
    if (!ctx) return false;
    EngineContext parsed;
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        fprintf(stderr, "[ERROR] Could not open model file: %s\n", path.c_str());
        return false;
    }

    f.read(reinterpret_cast<char*>(&parsed.cfg.magic), 4);
    f.read(reinterpret_cast<char*>(&parsed.cfg.version), 4);
    if (!f) return false;
    if (parsed.cfg.magic != 0x46554747) {  // "GGUF"
        fprintf(stderr, "[ERROR] Invalid GGUF magic: 0x%08X\n", parsed.cfg.magic);
        return false;
    }

    f.read(reinterpret_cast<char*>(&parsed.cfg.tensorCount), 8);
    f.read(reinterpret_cast<char*>(&parsed.cfg.kvCount), 8);

    if (!f || parsed.cfg.version < 2 || parsed.cfg.version > 3 ||
        parsed.cfg.kvCount > kMaxMetadataElements ||
        parsed.cfg.tensorCount > kMaxMetadataElements) return false;

    // Parse Dynamic Prefix Metadata arrays
    for (size_t i = 0; i < parsed.cfg.kvCount; ++i) {
        std::string key = ReadGGUFStr(f);
        uint32_t type = 0;
        f.read(reinterpret_cast<char*>(&type), sizeof(type));
        if (!f || key.empty() || type > 12) return false;
        ParseUniversalGGUFMetadata(key, type, f, &parsed);
        if (!f) return false;
    }

    // Read Layer Allocation Layout indices
    for (size_t i = 0; i < parsed.cfg.tensorCount; ++i) {
        GGUFTensorMeta meta;
        meta.name = ReadGGUFStr(f);
        uint32_t nDims = 0;
        f.read(reinterpret_cast<char*>(&nDims), 4);
        if (!f || meta.name.empty() || nDims > 8) return false;
        meta.dims.resize(nDims);
        if (nDims > 0) f.read(reinterpret_cast<char*>(meta.dims.data()), nDims * 8);
        f.read(reinterpret_cast<char*>(&meta.type), 4);
        f.read(reinterpret_cast<char*>(&meta.offset), 8);
        if (!f || !parsed.tensors.emplace(meta.name, meta).second) return false;
    }

    // GGUF tensor data starts at the declared alignment (default 32).
    if (!f || f.tellg() < 0) return false;
    uint64_t currentPos = static_cast<uint64_t>(f.tellg());
    const uint64_t alignment = parsed.cfg.ggufAlignment;
    if (currentPos > UINT64_MAX - (alignment - 1)) return false;
    uint64_t pad = (currentPos + alignment - 1) & ~(alignment - 1);
    f.seekg(pad, std::ios::beg);
    if (!f || f.tellg() < 0) return false;
    uint64_t alignedDataStart = static_cast<uint64_t>(f.tellg());

    // Read physical weight arrays straight into aligned heap storage
    f.seekg(0, std::ios::end);
    if (!f || f.tellg() < 0 || static_cast<uint64_t>(f.tellg()) < alignedDataStart) return false;
    uint64_t totalBytes = static_cast<uint64_t>(f.tellg()) - alignedDataStart;
    if (totalBytes > static_cast<uint64_t>(std::numeric_limits<std::streamsize>::max()) ||
        totalBytes > parsed.tensorWeightsPool.max_size()) return false;
    f.seekg(alignedDataStart, std::ios::beg);

    try {
        parsed.tensorWeightsPool.resize(static_cast<size_t>(totalBytes));
    } catch (const std::bad_alloc&) {
        return false;
    }
    if (totalBytes) f.read(reinterpret_cast<char*>(parsed.tensorWeightsPool.data()), static_cast<std::streamsize>(totalBytes));
    if (!f) return false;

    // Bind raw internal device mapping coordinates
    for (auto& pair : parsed.tensors) {
        const auto& meta = pair.second;
        if (meta.offset % alignment != 0 || meta.offset >= totalBytes ||
            meta.dims.empty()) return false;
        // Validate full extent for scalar F32/F16 and common block-quantized types.
        // Other types remain bounded by their start offset until their
        // architecture-specific storage layouts are certified.
        uint64_t elements = 1;
        for (uint64_t dim : meta.dims) {
            if (dim == 0 || elements > UINT64_MAX / dim) return false;
            elements *= dim;
        }
        uint64_t bytes = 0;
        if (meta.type == 0 || meta.type == 1) {
            const uint64_t width = meta.type == 0 ? 4 : 2;
            if (elements > UINT64_MAX / width) return false;
            bytes = elements * width;
        } else if (meta.type == 2 || meta.type == 8) {
            // GGML Q4_0: 32 values/18 bytes; Q8_0: 32 values/34 bytes.
            if (elements % 32 != 0) return false;
            const uint64_t blockBytes = meta.type == 2 ? 18 : 34;
            if (elements / 32 > UINT64_MAX / blockBytes) return false;
            bytes = (elements / 32) * blockBytes;
        }
        if (bytes && bytes > totalBytes - meta.offset) return false;
        pair.second.dataData = parsed.tensorWeightsPool.data() + meta.offset;
    }

    // Dynamic Geometry Adaption Guard - ONLY if metadata not parsed from GGUF keys
    // (i.e., values still zero). Don't override correctly parsed phi3.* metadata.
    if (parsed.cfg.hiddenDim == 0 || parsed.cfg.intermediateDim == 0) {
        auto sample_wUp = parsed.tensors.find("blk.0.ffn_up.weight");
        if (sample_wUp != parsed.tensors.end() && sample_wUp->second.dims.size() >= 2) {
            // dims[0] = output_dim (intermediate), dims[1] = input_dim (hidden)
            if (parsed.cfg.intermediateDim == 0) parsed.cfg.intermediateDim = sample_wUp->second.dims[0];
            if (parsed.cfg.hiddenDim == 0) parsed.cfg.hiddenDim = sample_wUp->second.dims[1];
        }
    }

    *ctx = std::move(parsed);
    return true;
}