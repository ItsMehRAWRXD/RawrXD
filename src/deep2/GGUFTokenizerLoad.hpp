// ============================================================================
// GGUFTokenizerLoad.hpp — Load tokenizer.ggml.* + chat_template from GGUF
// Single production authority for vocab/scores/specials used by Deep2 encode.
// ============================================================================
#pragma once

#include "Tokenizer.hpp"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>

namespace Deep2 {

struct GGUFTokenizerBundle {
    std::vector<std::string> tokens;
    std::vector<float> scores;
    SpecialTokens special;
    std::string chatTemplate;
    bool addBos = true;
    bool addEos = false;
    bool ok = false;
    char error[256] = {0};
};

namespace detail {

inline bool readU32(FILE* fp, uint32_t& v) {
    return fread(&v, 1, 4, fp) == 4;
}
inline bool readU64(FILE* fp, uint64_t& v) {
    return fread(&v, 1, 8, fp) == 8;
}
inline bool readF32(FILE* fp, float& v) {
    return fread(&v, 1, 4, fp) == 4;
}
inline bool readI32(FILE* fp, int32_t& v) {
    return fread(&v, 1, 4, fp) == 4;
}

inline bool readString(FILE* fp, std::string& out) {
    uint64_t len = 0;
    if (!readU64(fp, len)) return false;
    if (len > (1ull << 28)) return false; // 256 MiB sanity
    out.assign(static_cast<size_t>(len), '\0');
    if (len == 0) return true;
    return fread(out.data(), 1, static_cast<size_t>(len), fp) == len;
}

inline bool skipValue(FILE* fp, uint32_t type);

inline bool skipArray(FILE* fp) {
    uint32_t elemType = 0;
    uint64_t count = 0;
    if (!readU32(fp, elemType) || !readU64(fp, count)) return false;
    if (count > (1ull << 26)) return false;
    for (uint64_t i = 0; i < count; ++i) {
        if (!skipValue(fp, elemType)) return false;
    }
    return true;
}

inline bool skipValue(FILE* fp, uint32_t type) {
    switch (type) {
        case 0: case 1: case 7: { // u8/i8/bool
            uint8_t b; return fread(&b, 1, 1, fp) == 1;
        }
        case 2: case 3: { // u16/i16
            uint16_t v; return fread(&v, 1, 2, fp) == 2;
        }
        case 4: case 5: case 6: { // u32/i32/f32
            uint32_t v; return fread(&v, 1, 4, fp) == 4;
        }
        case 10: case 11: case 12: { // u64/i64/f64
            uint64_t v; return fread(&v, 1, 8, fp) == 8;
        }
        case 8: { // string
            std::string s;
            return readString(fp, s);
        }
        case 9: // array
            return skipArray(fp);
        default:
            return false;
    }
}

inline bool readStringArray(FILE* fp, std::vector<std::string>& out) {
    uint32_t elemType = 0;
    uint64_t count = 0;
    if (!readU32(fp, elemType) || !readU64(fp, count)) return false;
    if (elemType != 8 /* STRING */) {
        // Wrong type — skip payload to keep stream aligned
        for (uint64_t i = 0; i < count; ++i) {
            if (!skipValue(fp, elemType)) return false;
        }
        return false;
    }
    if (count > 500000) return false;
    out.clear();
    out.reserve(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        std::string s;
        if (!readString(fp, s)) return false;
        out.push_back(std::move(s));
    }
    return true;
}

inline bool readFloatArray(FILE* fp, std::vector<float>& out) {
    uint32_t elemType = 0;
    uint64_t count = 0;
    if (!readU32(fp, elemType) || !readU64(fp, count)) return false;
    if (elemType != 6 /* FLOAT32 */) {
        for (uint64_t i = 0; i < count; ++i) {
            if (!skipValue(fp, elemType)) return false;
        }
        return false;
    }
    if (count > 500000) return false;
    out.resize(static_cast<size_t>(count));
    for (uint64_t i = 0; i < count; ++i) {
        if (!readF32(fp, out[static_cast<size_t>(i)])) return false;
    }
    return true;
}

} // namespace detail

// Parse only tokenizer-related KV from a GGUF file (does not load tensors).
inline GGUFTokenizerBundle LoadTokenizerFromGGUF(const char* filepath) {
    GGUFTokenizerBundle bundle;
    if (!filepath || !filepath[0]) {
        std::snprintf(bundle.error, sizeof(bundle.error), "null path");
        return bundle;
    }

    FILE* fp = nullptr;
#ifdef _MSC_VER
    if (fopen_s(&fp, filepath, "rb") != 0 || !fp) {
#else
    fp = std::fopen(filepath, "rb");
    if (!fp) {
#endif
        std::snprintf(bundle.error, sizeof(bundle.error), "open failed: %s", filepath);
        return bundle;
    }

    uint32_t magic = 0;
    if (!detail::readU32(fp, magic) || magic != 0x46554747u) {
        std::snprintf(bundle.error, sizeof(bundle.error), "bad magic");
        std::fclose(fp);
        return bundle;
    }

    uint32_t version = 0;
    uint64_t tensorCount = 0;
    uint64_t kvCount = 0;
    if (!detail::readU32(fp, version) ||
        !detail::readU64(fp, tensorCount) ||
        !detail::readU64(fp, kvCount)) {
        std::snprintf(bundle.error, sizeof(bundle.error), "header read failed");
        std::fclose(fp);
        return bundle;
    }

    for (uint64_t i = 0; i < kvCount; ++i) {
        std::string key;
        if (!detail::readString(fp, key)) {
            std::snprintf(bundle.error, sizeof(bundle.error), "kv key read failed @%llu",
                          (unsigned long long)i);
            std::fclose(fp);
            return bundle;
        }
        uint32_t vtype = 0;
        if (!detail::readU32(fp, vtype)) {
            std::snprintf(bundle.error, sizeof(bundle.error), "kv type read failed");
            std::fclose(fp);
            return bundle;
        }

        if (key == "tokenizer.ggml.tokens" && vtype == 9) {
            if (!detail::readStringArray(fp, bundle.tokens)) {
                std::snprintf(bundle.error, sizeof(bundle.error), "tokens array failed");
                std::fclose(fp);
                return bundle;
            }
            continue;
        }
        if (key == "tokenizer.ggml.scores" && vtype == 9) {
            if (!detail::readFloatArray(fp, bundle.scores)) {
                // Non-fatal: TinyLlama scores may be all zero; keep going if empty skip ok
                // readFloatArray already consumed or skipped
            }
            continue;
        }
        if (key == "tokenizer.chat_template" && vtype == 8) {
            if (!detail::readString(fp, bundle.chatTemplate)) {
                std::snprintf(bundle.error, sizeof(bundle.error), "chat_template read failed");
                std::fclose(fp);
                return bundle;
            }
            continue;
        }
        if (key == "tokenizer.ggml.bos_token_id" && (vtype == 4 || vtype == 5)) {
            int32_t v = 0;
            if (vtype == 4) {
                uint32_t u = 0;
                detail::readU32(fp, u);
                v = static_cast<int32_t>(u);
            } else {
                detail::readI32(fp, v);
            }
            bundle.special.bosId = v;
            continue;
        }
        if (key == "tokenizer.ggml.eos_token_id" && (vtype == 4 || vtype == 5)) {
            int32_t v = 0;
            if (vtype == 4) {
                uint32_t u = 0;
                detail::readU32(fp, u);
                v = static_cast<int32_t>(u);
            } else {
                detail::readI32(fp, v);
            }
            bundle.special.eosId = v;
            continue;
        }
        if (key == "tokenizer.ggml.unknown_token_id" && (vtype == 4 || vtype == 5)) {
            int32_t v = 0;
            if (vtype == 4) {
                uint32_t u = 0;
                detail::readU32(fp, u);
                v = static_cast<int32_t>(u);
            } else {
                detail::readI32(fp, v);
            }
            bundle.special.unkId = v;
            continue;
        }
        if (key == "tokenizer.ggml.padding_token_id" && (vtype == 4 || vtype == 5)) {
            int32_t v = 0;
            if (vtype == 4) {
                uint32_t u = 0;
                detail::readU32(fp, u);
                v = static_cast<int32_t>(u);
            } else {
                detail::readI32(fp, v);
            }
            bundle.special.padId = v;
            continue;
        }
        if (key == "tokenizer.ggml.add_bos_token" && vtype == 7) {
            uint8_t b = 0;
            fread(&b, 1, 1, fp);
            bundle.addBos = (b != 0);
            continue;
        }
        if (key == "tokenizer.ggml.add_eos_token" && vtype == 7) {
            uint8_t b = 0;
            fread(&b, 1, 1, fp);
            bundle.addEos = (b != 0);
            continue;
        }

        if (!detail::skipValue(fp, vtype)) {
            std::snprintf(bundle.error, sizeof(bundle.error),
                          "skip failed on key=%s type=%u", key.c_str(), vtype);
            std::fclose(fp);
            return bundle;
        }
    }

    std::fclose(fp);

    if (bundle.tokens.empty()) {
        std::snprintf(bundle.error, sizeof(bundle.error),
                      "tokenizer.ggml.tokens missing or empty");
        return bundle;
    }

    bundle.ok = true;
    return bundle;
}

inline bool ApplyTokenizerBundle(BPETokenizer& tok, const GGUFTokenizerBundle& bundle) {
    if (!bundle.ok || bundle.tokens.empty()) return false;
    if (!tok.LoadVocab(bundle.tokens)) return false;
    if (!bundle.scores.empty()) {
        tok.LoadScores(bundle.scores);
    }
    tok.SetSpecialTokens(bundle.special);
    return true;
}

} // namespace Deep2
