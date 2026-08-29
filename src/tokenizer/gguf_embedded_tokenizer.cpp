#include "gguf_embedded_tokenizer.hpp"
#include "sentencepiece_encode.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace RawrXD {

namespace {

constexpr uint32_t GGUF_MAGIC = 0x46554747;
constexpr uint32_t GGUF_VERSION = 3;

enum GGUFType : uint32_t {
    UINT8    = 0,
    INT8     = 1,
    UINT16   = 2,
    INT16    = 3,
    UINT32   = 4,
    INT32    = 5,
    FLOAT32  = 6,
    BOOL     = 7,
    STRING   = 8,
    ARRAY    = 9,
    UINT64   = 10,
    INT64    = 11,
    FLOAT64  = 12
};

template<typename T>
bool ReadScalar(
    const uint8_t*& p,
    const uint8_t* end,
    T& out)
{
    if (!p || !end || end < p ||
        static_cast<size_t>(end - p) < sizeof(T))
        return false;

    std::memcpy(&out, p, sizeof(T));
    p += sizeof(T);
    return true;
}

static int HexNibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse vocab byte-fallback name "<0xHH>" -> byte value, or -1.
static int ParseByteFallbackName(const std::string& tok) {
    if (tok.size() != 6) return -1;
    if (tok[0] != '<' || tok[1] != '0' || tok[2] != 'x' || tok[5] != '>')
        return -1;
    const int hi = HexNibble(tok[3]);
    const int lo = HexNibble(tok[4]);
    if (hi < 0 || lo < 0) return -1;
    return (hi << 4) | lo;
}

} // namespace

bool GGUFEmbeddedTokenizer::IsValidRange(
    const uint8_t* p,
    const uint8_t* end,
    size_t n)
{
    return p && end && end >= p &&
           static_cast<size_t>(end - p) >= n;
}

bool GGUFEmbeddedTokenizer::ReadU32(
    const uint8_t*& p,
    const uint8_t* end,
    uint32_t& out)
{
    return ReadScalar(p, end, out);
}

bool GGUFEmbeddedTokenizer::ReadU64(
    const uint8_t*& p,
    const uint8_t* end,
    uint64_t& out)
{
    return ReadScalar(p, end, out);
}

bool GGUFEmbeddedTokenizer::ReadI32(
    const uint8_t*& p,
    const uint8_t* end,
    int32_t& out)
{
    return ReadScalar(p, end, out);
}

bool GGUFEmbeddedTokenizer::ReadString(
    const uint8_t*& p,
    const uint8_t* end,
    std::string& out)
{
    uint64_t len = 0;

    if (!ReadU64(p, end, len))
        return false;

    if (len > 16ull * 1024ull * 1024ull)
        return false;

    if (!IsValidRange(p, end, static_cast<size_t>(len)))
        return false;

    out.assign(
        reinterpret_cast<const char*>(p),
        static_cast<size_t>(len));

    p += static_cast<size_t>(len);
    return true;
}

bool GGUFEmbeddedTokenizer::SkipValue(
    const uint8_t*& p,
    const uint8_t* end,
    uint32_t type)
{
    switch (type) {
    case UINT8:
    case INT8:
    case BOOL:
        return IsValidRange(p, end, 1) ? (p += 1, true) : false;

    case UINT16:
    case INT16:
        return IsValidRange(p, end, 2) ? (p += 2, true) : false;

    case UINT32:
    case INT32:
    case FLOAT32:
        return IsValidRange(p, end, 4) ? (p += 4, true) : false;

    case UINT64:
    case INT64:
    case FLOAT64:
        return IsValidRange(p, end, 8) ? (p += 8, true) : false;

    case STRING: {
        std::string ignored;
        return ReadString(p, end, ignored);
    }

    case ARRAY: {
        uint32_t elementType = 0;
        uint64_t count = 0;

        if (!ReadU32(p, end, elementType))
            return false;

        if (!ReadU64(p, end, count))
            return false;

        if (count > 100000000ull)
            return false;

        for (uint64_t i = 0; i < count; ++i) {
            if (!SkipValue(p, end, elementType))
                return false;
        }

        return true;
    }

    default:
        return false;
    }
}

void GGUFEmbeddedTokenizer::RebuildIndexes() {
    lookup_.clear();
    lookup_.reserve(tokens_.size() * 2);
    specialsSorted_.clear();
    byteFallback_.fill(-1);

    for (uint32_t id = 0;
         id < static_cast<uint32_t>(tokens_.size());
         ++id) {
        lookup_.emplace(tokens_[id], id);

        const int32_t tt =
            (id < tokenTypes_.size()) ? tokenTypes_[id] : 1;

        if (tt == TOKEN_CONTROL || tt == TOKEN_USER_DEFINED) {
            if (!tokens_[id].empty()) {
                specialsSorted_.emplace_back(tokens_[id], id);
            }
        }

        const int b = ParseByteFallbackName(tokens_[id]);
        if (b >= 0 && b < 256 && byteFallback_[static_cast<size_t>(b)] < 0) {
            byteFallback_[static_cast<size_t>(b)] = static_cast<int32_t>(id);
        }
    }

    // Also treat bos/eos strings as atomic even if type metadata missing
    auto ensureSpecial = [&](int32_t id) {
        if (id < 0 || static_cast<size_t>(id) >= tokens_.size()) return;
        const std::string& s = tokens_[static_cast<size_t>(id)];
        if (s.empty()) return;
        for (const auto& e : specialsSorted_) {
            if (e.second == static_cast<uint32_t>(id)) return;
        }
        specialsSorted_.emplace_back(s, static_cast<uint32_t>(id));
    };
    ensureSpecial(bosToken_);
    ensureSpecial(eosToken_);

    std::sort(specialsSorted_.begin(), specialsSorted_.end(),
              [](const auto& a, const auto& b) {
                  if (a.first.size() != b.first.size())
                      return a.first.size() > b.first.size();
                  return a.first < b.first;
              });
}

bool GGUFEmbeddedTokenizer::ParseGGUF(
    const uint8_t* data,
    size_t size)
{
    if (!data || size < 24)
        return false;

    const uint8_t* p = data;
    const uint8_t* end = data + size;

    uint32_t magic = 0;
    uint32_t version = 0;
    uint64_t tensorCount = 0;
    uint64_t metadataCount = 0;

    if (!ReadU32(p, end, magic))
        return false;

    if (!ReadU32(p, end, version))
        return false;

    if (!ReadU64(p, end, tensorCount))
        return false;

    if (!ReadU64(p, end, metadataCount))
        return false;

    if (magic != GGUF_MAGIC || version != GGUF_VERSION)
        return false;

    if (metadataCount > 1000000ull)
        return false;

    std::vector<std::string> tokens;
    std::vector<int32_t> tokenTypes;
    int32_t bos = -1;
    int32_t eos = -1;

    for (uint64_t i = 0; i < metadataCount; ++i) {
        std::string key;
        uint32_t type = 0;

        if (!ReadString(p, end, key))
            return false;

        if (!ReadU32(p, end, type))
            return false;

        if (key == "tokenizer.ggml.tokens" &&
            type == ARRAY) {

            uint32_t elementType = 0;
            uint64_t count = 0;

            if (!ReadU32(p, end, elementType))
                return false;

            if (!ReadU64(p, end, count))
                return false;

            if (elementType != STRING ||
                count == 0 ||
                count > 1000000ull)
                return false;

            tokens.reserve(static_cast<size_t>(count));

            for (uint64_t n = 0; n < count; ++n) {
                std::string token;

                if (!ReadString(p, end, token))
                    return false;

                tokens.emplace_back(std::move(token));
            }

            continue;
        }

        if (key == "tokenizer.ggml.token_type" &&
            type == ARRAY) {

            uint32_t elementType = 0;
            uint64_t count = 0;

            if (!ReadU32(p, end, elementType))
                return false;

            if (!ReadU64(p, end, count))
                return false;

            if (count > 1000000ull)
                return false;

            tokenTypes.reserve(static_cast<size_t>(count));

            for (uint64_t n = 0; n < count; ++n) {
                if (elementType == INT32) {
                    int32_t v = 0;
                    if (!ReadI32(p, end, v))
                        return false;
                    tokenTypes.push_back(v);
                } else if (elementType == UINT32) {
                    uint32_t v = 0;
                    if (!ReadU32(p, end, v))
                        return false;
                    tokenTypes.push_back(static_cast<int32_t>(v));
                } else {
                    if (!SkipValue(p, end, elementType))
                        return false;
                    tokenTypes.push_back(1); // NORMAL placeholder
                }
            }

            continue;
        }

        if (key == "tokenizer.ggml.bos_token_id" &&
            type == UINT32) {

            uint32_t v = 0;

            if (!ReadU32(p, end, v))
                return false;

            bos = static_cast<int32_t>(v);
            continue;
        }

        if (key == "tokenizer.ggml.eos_token_id" &&
            type == UINT32) {

            uint32_t v = 0;

            if (!ReadU32(p, end, v))
                return false;

            eos = static_cast<int32_t>(v);
            continue;
        }

        // INT32 variants of bos/eos also appear in some GGUFs
        if (key == "tokenizer.ggml.bos_token_id" && type == INT32) {
            int32_t v = 0;
            if (!ReadI32(p, end, v)) return false;
            bos = v;
            continue;
        }
        if (key == "tokenizer.ggml.eos_token_id" && type == INT32) {
            int32_t v = 0;
            if (!ReadI32(p, end, v)) return false;
            eos = v;
            continue;
        }

        if (!SkipValue(p, end, type))
            return false;
    }

    if (tokens.empty())
        return false;

    tokens_ = std::move(tokens);
    tokenTypes_ = std::move(tokenTypes);
    bosToken_ = bos;
    eosToken_ = eos;
    RebuildIndexes();
    return true;
}

bool GGUFEmbeddedTokenizer::LoadFromGGUF(
    const std::string& ggufPath)
{
    tokens_.clear();
    tokenTypes_.clear();
    lookup_.clear();
    specialsSorted_.clear();
    byteFallback_.fill(-1);
    bosToken_ = -1;
    eosToken_ = -1;

    std::ifstream file(
        ggufPath,
        std::ios::binary | std::ios::ate);

    if (!file)
        return false;

    const std::streamsize fileSize = file.tellg();

    if (fileSize <= 0)
        return false;

    if (static_cast<uint64_t>(fileSize) > 16ull * 1024ull * 1024ull * 1024ull)
        return false;

    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(
        static_cast<size_t>(fileSize));

    if (!file.read(
            reinterpret_cast<char*>(data.data()),
            fileSize))
        return false;

    return ParseGGUF(data.data(), data.size());
}

int32_t GGUFEmbeddedTokenizer::FindToken(
    std::string_view text) const
{
    auto it = lookup_.find(std::string(text));

    if (it == lookup_.end())
        return -1;

    return static_cast<int32_t>(it->second);
}

bool GGUFEmbeddedTokenizer::MatchSpecialAt(
    std::string_view text,
    size_t pos,
    size_t& matchedLen,
    uint32_t& matchedId) const
{
    const std::string_view rest = text.substr(pos);
    for (const auto& sp : specialsSorted_) {
        if (rest.size() < sp.first.size())
            continue;
        if (rest.compare(0, sp.first.size(), sp.first) == 0) {
            matchedLen = sp.first.size();
            matchedId = sp.second;
            return true;
        }
    }
    return false;
}

bool GGUFEmbeddedTokenizer::EncodeOrdinarySpan(
    std::string_view span,
    std::vector<uint32_t>& output) const
{
    if (span.empty())
        return true;

    // TOKENIZER-PARITY-002c: same Spm::encode as Deep2::BPETokenizer::Encode
    std::array<int, 256> fb{};
    for (size_t i = 0; i < fb.size(); ++i) {
        fb[i] = byteFallback_[i];
    }

    // lookup_ maps string -> uint32_t; Spm wants string -> int
    std::unordered_map<std::string, int> vocabInt;
    vocabInt.reserve(lookup_.size() * 2);
    for (const auto& e : lookup_) {
        vocabInt.emplace(e.first, static_cast<int>(e.second));
    }

    std::vector<int> ids;
    if (!RawrXD::Spm::encode(
            span, vocabInt, fb, /*scores=*/nullptr, /*unkId=*/0, ids)) {
        return false;
    }
    output.insert(output.end(), ids.begin(), ids.end());
    return true;
}

bool GGUFEmbeddedTokenizer::EncodeLongestMatch(
    std::string_view text,
    std::vector<uint32_t>& output) const
{
    output.clear();

    if (!IsLoaded())
        return false;

    if (text.empty())
        return true;

    size_t pos = 0;
    size_t ordinaryStart = 0;

    auto flushOrdinary = [&](size_t endPos) -> bool {
        if (endPos <= ordinaryStart)
            return true;
        return EncodeOrdinarySpan(
            text.substr(ordinaryStart, endPos - ordinaryStart),
            output);
    };

    while (pos < text.size()) {
        size_t spLen = 0;
        uint32_t spId = 0;
        if (MatchSpecialAt(text, pos, spLen, spId)) {
            if (!flushOrdinary(pos))
                return false;
            output.push_back(spId);
            pos += spLen;
            ordinaryStart = pos;
            continue;
        }
        ++pos;
    }

    if (!flushOrdinary(text.size()))
        return false;

    return !output.empty();
}

} // namespace RawrXD
