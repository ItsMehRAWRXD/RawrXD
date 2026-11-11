#include "gguf_embedded_tokenizer.hpp"
#include "sentencepiece_encode.hpp"
#include "deepseek_pretokenizer.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>

namespace RawrXD
{

    namespace
    {

        constexpr uint32_t GGUF_MAGIC = 0x46554747;
        constexpr uint32_t GGUF_VERSION = 3;

        enum GGUFType : uint32_t
        {
            UINT8 = 0,
            INT8 = 1,
            UINT16 = 2,
            INT16 = 3,
            UINT32 = 4,
            INT32 = 5,
            FLOAT32 = 6,
            BOOL = 7,
            STRING = 8,
            ARRAY = 9,
            UINT64 = 10,
            INT64 = 11,
            FLOAT64 = 12
        };

        template <typename T>
        bool ReadScalar(
            const uint8_t *&p,
            const uint8_t *end,
            T &out)
        {
            if (!p || !end || end < p ||
                static_cast<size_t>(end - p) < sizeof(T))
                return false;

            std::memcpy(&out, p, sizeof(T));
            p += sizeof(T);
            return true;
        }

        static int HexNibble(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        }

        // Parse vocab byte-fallback name "<0xHH>" -> byte value, or -1.
        static int ParseByteFallbackName(const std::string &tok)
        {
            if (tok.size() != 6)
                return -1;
            if (tok[0] != '<' || tok[1] != '0' || tok[2] != 'x' || tok[5] != '>')
                return -1;
            const int hi = HexNibble(tok[3]);
            const int lo = HexNibble(tok[4]);
            if (hi < 0 || lo < 0)
                return -1;
            return (hi << 4) | lo;
        }

        // RAWRXD tokenizer parity: DeepSeek-V2-Lite-Chat ships a SentencePiece vocab
        // with NO metaspace marker. Ids 0..187 hold the byte tokens as literal
        // characters ("!" -> 0, "A" -> 32), and no "<0xNN>" names exist at all. For
        // those vocabs the metaspace normalizer and the "<0xNN>" parser both miss, so
        // every space degrades to three unk tokens.
        static bool VocabHasMetaspace(const std::vector<std::string> &tokens)
        {
            static const std::string kMeta("\xE2\x96\x81"); // U+2581
            for (const auto &t : tokens)
            {
                if (t == kMeta)
                    return true;
            }
            return false;
        }

        // RAWRXD tokenizer parity: a GPT-2-style byte-level BPE vocab
        // (tokenizer.ggml.model=gpt2, e.g. DeepSeek-V2-Lite-Chat)
        // represents whitespace with the U+0120 (Ġ) marker, not the
        // SentencePiece metaspace. Detect it by the marker's presence
        // so the encoder applies the GPT-2 byte-to-Unicode mapping
        // (space -> Ġ) instead of degrading every space to unk.
        static bool VocabHasGpt2Space(const std::vector<std::string> &tokens)
        {
            static const std::string kGpt2Space("\xC4\xA0"); // U+0120 Ġ
            for (const auto &t : tokens)
            {
                if (t.find(kGpt2Space) != std::string::npos)
                    return true;
            }
            return false;
        }

        // Fill byteFallback_ from single-character tokens, so the encoder can emit
        // real byte tokens for characters the vocabulary has no merge for.
        static void FillByteFallbackFromLiteralTokens(
            std::vector<std::string> &tokens,
            std::array<int32_t, 256> &byteFallback)
        {
            for (uint32_t id = 0; id < static_cast<uint32_t>(tokens.size()); ++id)
            {
                if (id >= 256)
                    break;
                const std::string &t = tokens[id];
                if (t.size() != 1)
                    continue;
                const unsigned char b = static_cast<unsigned char>(t[0]);
                if (byteFallback[b] < 0)
                    byteFallback[b] = static_cast<int32_t>(id);
            }
        }

        // Fill byteFallback_ through the GPT-2 byte-to-Unicode map: byte b's
        // fallback token is the vocab entry equal to gpt2ByteEncode(b). Byte
        // tokens in these vocabs are two UTF-8 bytes ("Ġ", "Ċ"), which the
        // literal single-character filler skips.
        static void FillByteFallbackFromGpt2Map(
            const std::vector<std::string> &tokens,
            std::array<int32_t, 256> &byteFallback)
        {
            for (int b = 0; b < 256; ++b)
            {
                if (byteFallback[static_cast<size_t>(b)] >= 0)
                    continue;
                const std::string mapped = RawrXD::Spm::gpt2ByteEncode(
                    static_cast<unsigned char>(b));
                for (uint32_t id = 0;
                     id < static_cast<uint32_t>(tokens.size());
                     ++id)
                {
                    if (tokens[id] == mapped)
                    {
                        byteFallback[static_cast<size_t>(b)] =
                            static_cast<int32_t>(id);
                        break;
                    }
                }
            }
        }

    } // namespace

    bool GGUFEmbeddedTokenizer::IsValidRange(
        const uint8_t *p,
        const uint8_t *end,
        size_t n)
    {
        return p && end && end >= p &&
               static_cast<size_t>(end - p) >= n;
    }

    bool GGUFEmbeddedTokenizer::ReadU32(
        const uint8_t *&p,
        const uint8_t *end,
        uint32_t &out)
    {
        return ReadScalar(p, end, out);
    }

    bool GGUFEmbeddedTokenizer::ReadU64(
        const uint8_t *&p,
        const uint8_t *end,
        uint64_t &out)
    {
        return ReadScalar(p, end, out);
    }

    bool GGUFEmbeddedTokenizer::ReadI32(
        const uint8_t *&p,
        const uint8_t *end,
        int32_t &out)
    {
        return ReadScalar(p, end, out);
    }

    bool GGUFEmbeddedTokenizer::ReadString(
        const uint8_t *&p,
        const uint8_t *end,
        std::string &out)
    {
        uint64_t len = 0;

        if (!ReadU64(p, end, len))
            return false;

        if (len > 16ull * 1024ull * 1024ull)
            return false;

        if (!IsValidRange(p, end, static_cast<size_t>(len)))
            return false;

        out.assign(
            reinterpret_cast<const char *>(p),
            static_cast<size_t>(len));

        p += static_cast<size_t>(len);
        return true;
    }

    bool GGUFEmbeddedTokenizer::SkipValue(
        const uint8_t *&p,
        const uint8_t *end,
        uint32_t type)
    {
        switch (type)
        {
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

        case STRING:
        {
            std::string ignored;
            return ReadString(p, end, ignored);
        }

        case ARRAY:
        {
            uint32_t elementType = 0;
            uint64_t count = 0;

            if (!ReadU32(p, end, elementType))
                return false;

            if (!ReadU64(p, end, count))
                return false;

            if (count > 100000000ull)
                return false;

            for (uint64_t i = 0; i < count; ++i)
            {
                if (!SkipValue(p, end, elementType))
                    return false;
            }

            return true;
        }

        default:
            return false;
        }
    }

    void GGUFEmbeddedTokenizer::RebuildIndexes()
    {
        lookup_.clear();
        lookup_.reserve(tokens_.size() * 2);
        specialsSorted_.clear();
        byteFallback_.fill(-1);

        for (uint32_t id = 0;
             id < static_cast<uint32_t>(tokens_.size());
             ++id)
        {
            lookup_.emplace(tokens_[id], id);

            const int32_t tt =
                (id < tokenTypes_.size()) ? tokenTypes_[id] : 1;

            if (tt == TOKEN_CONTROL || tt == TOKEN_USER_DEFINED)
            {
                if (!tokens_[id].empty())
                {
                    specialsSorted_.emplace_back(tokens_[id], id);
                }
            }

            const int b = ParseByteFallbackName(tokens_[id]);
            if (b >= 0 && b < 256 && byteFallback_[static_cast<size_t>(b)] < 0)
            {
                byteFallback_[static_cast<size_t>(b)] = static_cast<int32_t>(id);
            }
        }

        // RAWRXD tokenizer parity: DeepSeek-V2-Lite has no metaspace marker and no
        // "<0xNN>" names, so the loop above never fills byteFallback_. Fall back to
        // the literal single-character byte tokens this vocab does ship, and switch
        // the encoder off the metaspace normalization.
        // unkId_: prefer an explicit <unk>/<UNK> token. Ids 0..255 are real byte
        // tokens in metaspace-free vocabs, so they must never be used as unk.
        for (uint32_t id = 256; id < static_cast<uint32_t>(tokens_.size()); ++id)
        {
            const std::string &s = tokens_[id];
            if (s == "<unk>" || s == "<UNK>" || s == "<UNKNOWN>")
            {
                unkId_ = static_cast<int32_t>(id);
                break;
            }
        }

        if (!VocabHasMetaspace(tokens_))
        {
            FillByteFallbackFromLiteralTokens(tokens_, byteFallback_);
            hasMetaspace_ = false;
            // GPT-2 byte-level BPE vocab: whitespace is the
            // U+0120 (Ġ) marker, applied by the GPT-2
            // normalizer before BPE merging.
            hasGpt2Space_ = VocabHasGpt2Space(tokens_);
            if (hasGpt2Space_)
            {
                FillByteFallbackFromGpt2Map(tokens_, byteFallback_);
            }
        }
        else
        {
            hasMetaspace_ = true;
            hasGpt2Space_ = false;
        }

        // Merge ranks (tokenizer.ggml.merges) drive the BPE merge order on the
        // byte-level path, the same table llama.cpp builds from
        // bpe_ranks. First occurrence of a pair wins.
        mergeRanks_.clear();
        mergeRanks_.reserve(merges_.size() * 2);
        for (size_t rank = 0; rank < merges_.size(); ++rank)
        {
            const std::string &line = merges_[rank];
            const size_t sp = line.find(' ');
            if (sp == std::string::npos || sp == 0 || sp + 1 >= line.size())
                continue;
            mergeRanks_.emplace(
                line.substr(0, sp) + " " + line.substr(sp + 1),
                static_cast<int>(rank));
        }

        // Also treat bos/eos strings as atomic even if type metadata missing
        auto ensureSpecial = [&](int32_t id)
        {
            if (id < 0 || static_cast<size_t>(id) >= tokens_.size())
                return;
            const std::string &s = tokens_[static_cast<size_t>(id)];
            if (s.empty())
                return;
            for (const auto &e : specialsSorted_)
            {
                if (e.second == static_cast<uint32_t>(id))
                    return;
            }
            specialsSorted_.emplace_back(s, static_cast<uint32_t>(id));
        };
        ensureSpecial(bosToken_);
        ensureSpecial(eosToken_);

        std::sort(specialsSorted_.begin(), specialsSorted_.end(),
                  [](const auto &a, const auto &b)
                  {
                      if (a.first.size() != b.first.size())
                          return a.first.size() > b.first.size();
                      return a.first < b.first;
                  });
    }

    bool GGUFEmbeddedTokenizer::ParseGGUF(
        const uint8_t *data,
        size_t size)
    {
        if (!data || size < 24)
            return false;

        const uint8_t *p = data;
        const uint8_t *end = data + size;

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
        std::vector<std::string> merges;
        std::vector<int32_t> tokenTypes;
        std::string preType;
        int32_t bos = -1;
        int32_t eos = -1;

        for (uint64_t i = 0; i < metadataCount; ++i)
        {
            std::string key;
            uint32_t type = 0;

            if (!ReadString(p, end, key))
                return false;

            if (!ReadU32(p, end, type))
                return false;

            if (key == "tokenizer.ggml.tokens" &&
                type == ARRAY)
            {

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

                for (uint64_t n = 0; n < count; ++n)
                {
                    std::string token;

                    if (!ReadString(p, end, token))
                        return false;

                    tokens.emplace_back(std::move(token));
                }

                continue;
            }

            if (key == "tokenizer.ggml.token_type" &&
                type == ARRAY)
            {

                uint32_t elementType = 0;
                uint64_t count = 0;

                if (!ReadU32(p, end, elementType))
                    return false;

                if (!ReadU64(p, end, count))
                    return false;

                if (count > 1000000ull)
                    return false;

                tokenTypes.reserve(static_cast<size_t>(count));

                for (uint64_t n = 0; n < count; ++n)
                {
                    if (elementType == INT32)
                    {
                        int32_t v = 0;
                        if (!ReadI32(p, end, v))
                            return false;
                        tokenTypes.push_back(v);
                    }
                    else if (elementType == UINT32)
                    {
                        uint32_t v = 0;
                        if (!ReadU32(p, end, v))
                            return false;
                        tokenTypes.push_back(static_cast<int32_t>(v));
                    }
                    else
                    {
                        if (!SkipValue(p, end, elementType))
                            return false;
                        tokenTypes.push_back(1); // NORMAL placeholder
                    }
                }

                continue;
            }

            if (key == "tokenizer.ggml.merges" &&
                type == ARRAY)
            {

                uint32_t elementType = 0;
                uint64_t count = 0;

                if (!ReadU32(p, end, elementType))
                    return false;

                if (!ReadU64(p, end, count))
                    return false;

                if (elementType != STRING ||
                    count > 5000000ull)
                    return false;

                merges.reserve(static_cast<size_t>(count));

                for (uint64_t n = 0; n < count; ++n)
                {
                    std::string merge;

                    if (!ReadString(p, end, merge))
                        return false;

                    merges.emplace_back(std::move(merge));
                }

                continue;
            }

        if (key == "tokenizer.ggml.pre" && type == STRING)
        {
            std::string v;

            if (!ReadString(p, end, v))
                return false;

            preType = v;
            continue;
        }

        if (key == "tokenizer.ggml.bos_token_id" &&
            type == UINT32)
        {


                uint32_t v = 0;

                if (!ReadU32(p, end, v))
                    return false;

                bos = static_cast<int32_t>(v);
                continue;
            }

            if (key == "tokenizer.ggml.eos_token_id" &&
                type == UINT32)
            {

                uint32_t v = 0;

                if (!ReadU32(p, end, v))
                    return false;

                eos = static_cast<int32_t>(v);
                continue;
            }

            // INT32 variants of bos/eos also appear in some GGUFs
            if (key == "tokenizer.ggml.bos_token_id" && type == INT32)
            {
                int32_t v = 0;
                if (!ReadI32(p, end, v))
                    return false;
                bos = v;
                continue;
            }
            if (key == "tokenizer.ggml.eos_token_id" && type == INT32)
            {
                int32_t v = 0;
                if (!ReadI32(p, end, v))
                    return false;
                eos = v;
                continue;
            }

            if (!SkipValue(p, end, type))
                return false;
        }

        if (tokens.empty())
            return false;

        tokens_ = std::move(tokens);
        merges_ = std::move(merges);
        preType_ = std::move(preType);
        tokenTypes_ = std::move(tokenTypes);
        bosToken_ = bos;
        eosToken_ = eos;
        RebuildIndexes();
        return true;
    }

    bool GGUFEmbeddedTokenizer::LoadFromGGUF(
        const std::string &ggufPath)
    {
        tokens_.clear();
        merges_.clear();
        mergeRanks_.clear();
        preType_.clear();
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
                reinterpret_cast<char *>(data.data()),
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
        size_t &matchedLen,
        uint32_t &matchedId) const
    {
        const std::string_view rest = text.substr(pos);
        for (const auto &sp : specialsSorted_)
        {
            if (rest.size() < sp.first.size())
                continue;
            if (rest.compare(0, sp.first.size(), sp.first) == 0)
            {
                matchedLen = sp.first.size();
                matchedId = sp.second;
                return true;
            }
        }
        return false;
    }

    bool GGUFEmbeddedTokenizer::EncodeOrdinarySpan(
        std::string_view span,
        std::vector<uint32_t> &output) const
    {
        if (span.empty())
            return true;

        // TOKENIZER-PARITY-002c: same Spm::encode as Deep2::BPETokenizer::Encode.
        // Vocabs without a metaspace marker (DeepSeek-V2-Lite) must be encoded from
        // the raw text: inserting the marker would split every word.
        std::array<int, 256> fb{};
        for (size_t i = 0; i < fb.size(); ++i)
        {
            fb[i] = byteFallback_[i];
        }

        // lookup_ maps string -> uint32_t; Spm wants string -> int
        std::unordered_map<std::string, int> vocabInt;
        vocabInt.reserve(lookup_.size() * 2);
        for (const auto &e : lookup_)
        {
            vocabInt.emplace(e.first, static_cast<int>(e.second));
        }

        std::vector<int> ids;
        // Byte-level BPE vocabs that ship merges (DeepSeek-V2-Lite:
        // tokenizer.ggml.model=gpt2) merge by merge rank, the same
        // bpe_ranks order llama.cpp uses. Vocabs that ship scores instead
        // keep the SentencePiece score-ordered path.
        const bool useRanks =
            hasGpt2Space_ && !hasMetaspace_ && !mergeRanks_.empty();

        bool ok = false;
        if (useRanks)
        {
            ok = true;
            // tokenizer.ggml.pre=deepseek-llm pre-tokenizes into words before
            // the byte-level BPE merge, so encode each word on its own.
            const std::vector<std::string> words =
                preType_ == "deepseek-llm"
                    ? RawrXD::Spm::SplitDeepseekLlm(span)
                    : std::vector<std::string>{std::string(span)};
            for (const std::string &word : words)
            {
                std::vector<int> part;
                if (!RawrXD::Spm::encodeGpt2Bpe(word, vocabInt, fb, mergeRanks_,
                                                unkId_, part))
                {
                    ok = false;
                    break;
                }
                ids.insert(ids.end(), part.begin(), part.end());
            }
        }
        else if (hasMetaspace_)
        {
            ok = RawrXD::Spm::encode(span, vocabInt, fb, /*scores=*/nullptr,
                                     unkId_, ids);
        }
        else if (hasGpt2Space_)
        {
            ok = RawrXD::Spm::encodeGpt2(span, vocabInt, fb, /*scores=*/nullptr,
                                         unkId_, ids);
        }
        else
        {
            ok = RawrXD::Spm::encodeNoMetaspace(span, vocabInt, fb,
                                                /*scores=*/nullptr,
                                                unkId_, ids);
        }
        if (!ok)
        {
            return false;
        }
        output.insert(output.end(), ids.begin(), ids.end());
        return true;
    }

    bool GGUFEmbeddedTokenizer::EncodeLongestMatch(
        std::string_view text,
        std::vector<uint32_t> &output) const
    {
        output.clear();

        if (!IsLoaded())
            return false;

        if (text.empty())
            return true;

        size_t pos = 0;
        size_t ordinaryStart = 0;

        auto flushOrdinary = [&](size_t endPos) -> bool
        {
            if (endPos <= ordinaryStart)
                return true;
            return EncodeOrdinarySpan(
                text.substr(ordinaryStart, endPos - ordinaryStart),
                output);
        };

        while (pos < text.size())
        {
            size_t spLen = 0;
            uint32_t spId = 0;
            if (MatchSpecialAt(text, pos, spLen, spId))
            {
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
