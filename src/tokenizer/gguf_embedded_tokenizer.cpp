#include "gguf_embedded_tokenizer.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace RawrXD {

namespace {

constexpr uint32_t GGUF_MAGIC = 0x46554747;
constexpr uint32_t GGUF_VERSION = 3;

// GGUF metadata value types.
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

    // Defensive limit. A tokenizer string should never be remotely
    // close to this size.
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

        if (!SkipValue(p, end, type))
            return false;
    }

    if (tokens.empty())
        return false;

    tokens_ = std::move(tokens);
    bosToken_ = bos;
    eosToken_ = eos;

    lookup_.clear();
    lookup_.reserve(tokens_.size() * 2);

    for (uint32_t id = 0;
         id < static_cast<uint32_t>(tokens_.size());
         ++id) {

        // Preserve the first occurrence if malformed GGUF contains
        // duplicate token strings.
        lookup_.emplace(tokens_[id], id);
    }

    return true;
}

bool GGUFEmbeddedTokenizer::LoadFromGGUF(
    const std::string& ggufPath)
{
    tokens_.clear();
    lookup_.clear();
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

    // VAL harness safety limit.
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

    while (pos < text.size()) {
        size_t bestLength = 0;
        uint32_t bestId = 0;

        // Longest-match search. Cap prevents pathological work.
        const size_t maxProbe =
            std::min<size_t>(64, text.size() - pos);

        for (size_t len = maxProbe; len > 0; --len) {
            const std::string_view candidate =
                text.substr(pos, len);

            auto it = lookup_.find(std::string(candidate));

            if (it != lookup_.end()) {
                bestLength = len;
                bestId = it->second;
                break;
            }
        }

        if (bestLength == 0) {
            // Try single-byte token.
            const unsigned char c =
                static_cast<unsigned char>(text[pos]);

            std::string oneByte(1, static_cast<char>(c));

            auto it = lookup_.find(oneByte);

            if (it == lookup_.end())
                return false;

            bestLength = 1;
            bestId = it->second;
        }

        output.push_back(bestId);
        pos += bestLength;
    }

    return !output.empty();
}

} // namespace RawrXD
