// ============================================================================
// deep2_tokenizer.hpp -- Shared SentencePiece/BPE tokenizer for Deep2 tools
// ============================================================================
// Extracted verbatim from tools/deep2_agentic_loop.cpp, which is the working
// reference implementation. Round-trip verified on qwen2.5-coder, tinyllama-chat.
//
// Handles:
//   * SentencePiece (U+2581) and GPT-2/BPE (U+0120) conventions, detected by
//     marker dominance in the vocabulary.
//   * Byte-alphabet mapping, byte-fallback tokens (<0xNN>), UTF-8 boundaries.
//   * BPE merges by rank, llama-3 split groups, byte-exact whitespace.
// ============================================================================
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "modelgenie/universal_gguf.hpp"

namespace deep2tools
{

using RawrXD::Deep2::Universal::Tokenizer;

// ---------------------------------------------------------------------------
// Token types (llama.cpp convention):
//   1 = NORMAL, 2 = UNKNOWN, 3 = CONTROL, 4 = USER_DEFINED,
//   6 = BYTE (a byte-fallback token "<0xNN>")
static constexpr int TT_NORMAL = 1, TT_UNKNOWN = 2, TT_CONTROL = 3, TT_BYTE = 6;

struct Encoded
{
    std::vector<int32_t> ids;
    bool ok = false;
    std::string why;
};

static int ByteToSymbol(char c)
{
    return (int)(unsigned char)c;
}
static std::string ByteFallbackToken(char c)
{
    char buf[8];
    std::snprintf(buf, sizeof(buf), "<0x%02X>", (unsigned)(unsigned char)c);
    return buf;
}

// GPT-2 byte encoder: the strict bytes_to_unicode bijection.
static bool CpIsLetter(unsigned cp)
{
    return (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') ||
           (cp >= 0x00AA && cp <= 0x2BFF && !(cp >= 0x2000 && cp <= 0x206F) && !(cp >= 0x2190 && cp <= 0x2BFF));
}

static size_t NextSplitEnd(const std::string& s, size_t p)
{
    const size_t n = s.size();
    auto isL = [](unsigned c) { return CpIsLetter(c); };
    auto isN = [](unsigned c) { return c >= '0' && c <= '9'; };
    auto isCRLF = [](unsigned c) { return c == '\n' || c == '\r'; };
    auto isWs = [](unsigned c) { return c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\n' || c == '\r'; };
    auto isOther = [](unsigned c) { return c >= 0x80; };

    const unsigned char c0 = (unsigned char)s[p];
    // contractions
    if (c0 == '\'')
    {
        const auto ci = [&](const char* a, size_t alen)
        {
            if (p + alen > n)
                return false;
            for (size_t k = 0; k < alen; ++k)
                if (std::tolower((unsigned char)s[p + k]) != (unsigned char)std::tolower(a[k]))
                    return false;
            return true;
        };
        if (ci("'s", 2) || ci("'t", 2) || ci("'m", 2) || ci("'d", 2) || ci("'re", 3) || ci("'ve", 3) || ci("'ll", 3))
        {
            size_t e = p + 2;
            if (e <= n && (s[p + 1] == 'r' || s[p + 1] == 'v' || s[p + 1] == 'l') && (n - p >= 3) &&
                (s[p + 2] == 'e' || s[p + 2] == 'l'))
                e = p + 3;
            return e;
        }
    }
    // [^\r\n\p{L}\p{N}]?\p{L}+
    {
        size_t q = p;
        if (!isL((unsigned)c0) && !isN((unsigned)c0) && !isCRLF((unsigned)c0))
        {
            if (q + 1 < n && isL((unsigned)(unsigned char)s[q + 1]))
                q += 1;
        }
        if (isL((unsigned)(unsigned char)s[q]) &&
            !(q == p && !isL((unsigned)c0) && q + !(p + 1 < n ? 1u : 0u) <= p && q == p))
        {
            if ((q != p || isL((unsigned)c0)))
            {
                size_t e = q;
                while (e + 1 <= n && e < n && isL((unsigned)(unsigned char)s[e]))
                    ++e;
                return e > p ? e : p + 1;
            }
        }
    }
    // \p{N}{1,3}
    if (isN((unsigned)c0))
    {
        size_t e = p;
        while (e < n && isN((unsigned)(unsigned char)s[e]) && e - p < 3)
            ++e;
        return e;
    }
    // ?[^\s L N]+[\r\n]*
    if (!isL((unsigned)c0) && !isN((unsigned)c0) && !isWs((unsigned)c0))
    {
        size_t e = p;
        while (e < n && (unsigned char)s[e] >= 0x21 && !isL((unsigned)(unsigned char)s[e]) &&
               !isN((unsigned)(unsigned char)s[e]))
            ++e;
        while (e < n && isCRLF((unsigned)(unsigned char)s[e]))
            ++e;
        return e > p ? e : p + 1;
    }
    // \s*[\r\n]+
    if (isWs((unsigned)c0) || isCRLF((unsigned)c0))
    {
        size_t j = p;
        while (j < n && isWs((unsigned)(unsigned char)s[j]) && !isCRLF((unsigned)(unsigned char)s[j]))
            ++j;
        if (j < n && isCRLF((unsigned)(unsigned char)s[j]))
        {
            while (j < n && isCRLF((unsigned)(unsigned char)s[j]))
                ++j;
            return j;
        }
        while (j < n && isWs((unsigned)(unsigned char)s[j]))
            ++j;
        return j > p ? j : p + 1;
    }
    if (isOther((unsigned)c0))
        return p + 1;
    return p + 1;
}

static std::string Utf8FromCp(unsigned cp)
{
    std::string s;
    if (cp < 0x80)
        s += (char)cp;
    else if (cp < 0x800)
    {
        s += (char)(0xC0 | (cp >> 6));
        s += (char)(0x80 | (cp & 0x3F));
    }
    else
    {
        s += (char)(0xE0 | (cp >> 12));
        s += (char)(0x80 | ((cp >> 6) & 0x3F));
        s += (char)(0x80 | (cp & 0x3F));
    }
    return s;
}

static unsigned Utf8CharAt(const std::string& s, size_t i, size_t* len)
{
    const unsigned char c0 = (unsigned char)s[i];
    *len = 1;
    unsigned cp = c0;
    if ((c0 & 0xE0) == 0xC0 && i + 1 < s.size())
    {
        cp = ((c0 & 0x1Fu) << 6) | ((unsigned char)s[i + 1] & 0x3F);
        *len = 2;
    }
    else if ((c0 & 0xF0) == 0xE0 && i + 2 < s.size())
    {
        cp = ((c0 & 0x0Fu) << 12) | (((unsigned char)s[i + 1] & 0x3F) << 6) | ((unsigned char)s[i + 2] & 0x3F);
        *len = 3;
    }
    else if ((c0 & 0xF8) == 0xF0 && i + 3 < s.size())
    {
        cp = ((c0 & 0x07u) << 18) | (((unsigned char)s[i + 1] & 0x3F) << 12) | (((unsigned char)s[i + 2] & 0x3F) << 6) |
             ((unsigned char)s[i + 3] & 0x3F);
        *len = 4;
    }
    return cp;
}

static int Gpt2SymbolToByte(unsigned cp)
{
    if ((cp >= 0xA1 && cp <= 0xAC) || (cp >= 0xAE && cp <= 0xFF))
        return (int)cp;
    if (cp >= 256 && cp <= 288)
        return (int)(cp - 256);  // 0x00-0x20
    if (cp >= 289 && cp <= 322)
        return (int)(cp - 289 + 0x7F);  // 0x7F-0xA0
    if (cp == 323)
        return 0xAD;  // 323
    return -1;
}

static std::string Gpt2ByteSymbol(unsigned char b)
{
    if (b >= '!' && b <= '~')
        return std::string(1, (char)b);
    if ((b >= 0xA1 && b <= 0xAC) || (b >= 0xAE && b <= 0xFF))
        return Utf8FromCp((unsigned)b);
    if (b <= 0x20)
        return Utf8FromCp(256u + b);  // 0x00-0x20 -> U+0100-U+0120
    if (b <= 0xA0)
        return Utf8FromCp(256u + 33u + (b - 0x7F));  // 0x7F-0xA0 -> U+0121-U+0142
    return Utf8FromCp(256u + 33u + 34u);             // 0xAD -> U+0143
}

static std::string TokenToVisible(const std::string& t, bool gpt2Conv, const std::string& marker)
{
    if (t.size() == 6 && t[0] == '<' && t[1] == '0' && t[2] == 'x' && t[5] == '>')
        return std::string(1, (char)(unsigned)std::strtoul(t.c_str() + 3, nullptr, 16));
    std::string out;
    out.reserve(t.size());
    for (size_t i = 0; i < t.size();)
    {
        if (!gpt2Conv && t.compare(i, marker.size(), marker) == 0)
        {
            out += ' ';
            i += marker.size();
            continue;
        }
        size_t len = 0;
        const unsigned cp = Utf8CharAt(t, i, &len);
        const int alphabetByte = gpt2Conv ? Gpt2SymbolToByte(cp) : -1;
        if (alphabetByte >= 0)
        {
            out += (char)alphabetByte;
        }
        else
        {
            if (i + len > t.size())
                len = t.size() - i;
            out.append(t, i, len);
        }
        i += len;
    }
    return out;
}

static const char* kSpMarker = "\xE2\x96\x81";  // U+2581
static const char* kGpt2Marker = "\xC4\xA0";    // U+0120

static const char* DetectSpaceMarker(const std::vector<std::string>& toks)
{
    size_t gpt2Hits = 0, spHits = 0;
    for (const auto& t : toks)
    {
        if (t.find(kGpt2Marker) != std::string::npos)
            ++gpt2Hits;
        if (t.find(kSpMarker) != std::string::npos)
            ++spHits;
    }
    if (gpt2Hits > spHits)
        return kGpt2Marker;
    return kSpMarker;
}

static std::string SpNormalize(const std::string& in, const char* marker)
{
    std::string out;
    out.reserve(in.size() * 2);
    bool pendingSpace = false;
    for (size_t i = 0; i < in.size(); ++i)
    {
        const unsigned char c = (unsigned char)in[i];
        if (c == ' ')
        {
            out += marker;
            continue;
        }
        if (c == '\t' || c == '\v' || c == '\f' || c == '\n' || c == '\r')
        {
            if (pendingSpace)
            {
                out += marker;
                pendingSpace = false;
            }
            out += (char)c;
            continue;
        }
        if (pendingSpace)
        {
            out += marker;
            pendingSpace = false;
        }
        out += (char)c;
    }
    if (pendingSpace)
        out += marker;
    return out;
}

static std::string DetokenizeWith(const std::vector<std::string>& toks, const std::vector<int32_t>& ids)
{
    const bool gpt2Conv = DetectSpaceMarker(toks)[0] == '\xC4';
    const std::string marker(DetectSpaceMarker(toks));
    std::string raw;
    for (int32_t id : ids)
    {
        if (id < 0 || (size_t)id >= toks.size())
            continue;
        raw += TokenToVisible(toks[(size_t)id], gpt2Conv, marker);
    }
    if (!gpt2Conv)
    {
        std::string out;
        out.reserve(raw.size());
        for (size_t i = 0; i < raw.size();)
        {
            if (raw.compare(i, marker.size(), marker) == 0)
            {
                out += ' ';
                i += marker.size();
                continue;
            }
            out += raw[i];
            ++i;
        }
        return out;
    }
    return raw;
}

static bool FindMerge(const std::vector<std::string>& merges, const std::string& a, const std::string& b,
                      std::string& merged)
{
    static std::vector<std::pair<std::string, std::string>> cache;
    static bool built = false;
    static size_t cacheFor = 0;
    if (!built || cacheFor != merges.size())
    {
        cache.clear();
        cache.reserve(merges.size());
        for (const auto& m : merges)
        {
            const size_t sp = m.find(' ');
            if (sp == std::string::npos || sp == 0)
                continue;
            cache.emplace_back(m.substr(0, sp), m.substr(sp + 1));
        }
        built = true;
        cacheFor = merges.size();
    }
    for (const auto& c : cache)
    {
        if (c.first == a && c.second == b)
        {
            merged = a + b;
            return true;
        }
    }
    return false;
}

struct SpEncoder
{
    bool ok = false;
    std::vector<std::string> tokens;  // id -> piece
    std::vector<std::string> mergeKeys;
    std::map<std::string, int32_t> rankOf;
    std::map<std::string, int32_t> idOf;
    std::string marker;

    SpEncoder() = default;

    void Build(const Tokenizer& tk)
    {
        tokens = tk.tokens;
        marker = DetectSpaceMarker(tk.tokens);
        ok = !tokens.empty();
        if (!ok)
            return;
        for (size_t i = 0; i < tokens.size(); ++i)
            if (!idOf.count(tokens[i]))
                idOf[tokens[i]] = (int32_t)i;
        rankOf.clear();
        mergeKeys.clear();
        for (size_t r = 0; r < tk.merges.size(); ++r)
        {
            const std::string& m = tk.merges[r];
            const size_t sp = m.find(' ');
            if (sp == std::string::npos || sp == 0)
                continue;
            mergeKeys.push_back(m);
            if (!rankOf.count(m))
                rankOf[m] = (int32_t)r;
        }
    }

    std::string Piece(uint32_t id) const
    {
        if (id >= tokens.size())
            return "";
        const bool gpt2Conv = (!marker.empty() && marker[0] == '\xC4');
        return TokenToVisible(tokens[id], gpt2Conv, marker);
    }

    static void ToSpChars(const std::string& s, std::vector<std::string>& out)
    {
        out.clear();
        size_t i = 0;
        while (i < s.size())
        {
            const unsigned char c = (unsigned char)s[i];
            size_t len = 1;
            if (c >= 0xF0)
                len = 4;
            else if (c >= 0xE0)
                len = 3;
            else if (c >= 0xC0)
                len = 2;
            if (i + len > s.size())
                len = 1;
            out.push_back(s.substr(i, len));
            i += len;
        }
    }

    bool Encode(const std::string& text, std::vector<int32_t>& ids)
    {
        ids.clear();
        if (!ok)
            return false;
        const bool gpt2Conv = (!marker.empty() && marker[0] == '\xC4');
        size_t gp = 0;
        while (gp < text.size())
        {
            const size_t gEnd = NextSplitEnd(text, gp);
            if (!EncodeCanon(text.substr(gp, gEnd - gp), ids, gpt2Conv))
                return false;
            gp = gEnd;
        }
        return true;
    }

    bool EncodeCanon(const std::string& text, std::vector<int32_t>& ids, bool gpt2Conv)
    {
        const std::string norm = SpNormalize(text, marker.c_str());
        std::vector<std::string> syms;
        if (gpt2Conv)
        {
            const size_t mlen = marker.size();
            syms.reserve(norm.size());
            for (size_t i = 0; i < norm.size();)
            {
                if (mlen == 2 && (unsigned char)norm[i] == 0xC4 && i + 1 < norm.size() &&
                    (unsigned char)norm[i + 1] == 0xA0)
                {
                    syms.push_back(marker);
                    i += mlen;
                    continue;
                }
                syms.push_back(Gpt2ByteSymbol((unsigned char)norm[i]));
                ++i;
            }
        }
        else
        {
            ToSpChars(norm, syms);
        }
        if (syms.empty())
            return true;

        for (int guard = 0; guard < (int)syms.size() * 8 + 256; ++guard)
        {
            int32_t bestRank = -1;
            size_t bestPos = 0;
            std::string bestKey;
            for (size_t i = 0; i + 1 < syms.size(); ++i)
            {
                const std::string key = syms[i] + " " + syms[i + 1];
                auto it = rankOf.find(key);
                if (it == rankOf.end())
                    continue;
                if (bestRank < 0 || it->second < bestRank)
                {
                    bestRank = it->second;
                    bestPos = i;
                    bestKey = key;
                }
            }
            if (bestRank < 0)
                break;
            syms[bestPos] += syms[bestPos + 1];
            syms.erase(syms.begin() + (long)bestPos + 1);
        }

        for (const auto& s : syms)
        {
            auto it = idOf.find(s);
            if (it != idOf.end())
            {
                ids.push_back(it->second);
                continue;
            }
            bool emitted = false;
            std::vector<std::string> chs;
            ToSpChars(s, chs);
            for (const auto& ch : chs)
            {
                auto suit = idOf.find(ch);
                if (suit != idOf.end())
                {
                    ids.push_back(suit->second);
                    emitted = true;
                    continue;
                }
                bool chOk = true;
                for (size_t k = 0; k < ch.size(); ++k)
                {
                    const unsigned char byte = (unsigned char)ch[k];
                    int32_t id = -1;
                    auto bit = idOf.find(ByteFallbackToken((char)byte));
                    if (bit != idOf.end())
                    {
                        id = bit->second;
                    }
                    else
                    {
                        auto git = idOf.find(Gpt2ByteSymbol(byte));
                        if (git != idOf.end())
                            id = git->second;
                    }
                    if (id < 0)
                    {
                        chOk = false;
                        break;
                    }
                    ids.push_back(id);
                }
                if (!chOk)
                {
                    emitted = false;
                    break;
                }
                emitted = true;
            }
            if (!emitted)
            {
                ids.push_back(0);
            }
        }
        return true;
    }
};

}  // namespace deep2tools
