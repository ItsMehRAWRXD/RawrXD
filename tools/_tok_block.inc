// Tokenizer helpers. SentencePiece-style BPE using the model's own tokens,
// token types and merges. No external dependency.
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

// The byte<->unicode mapping SentencePiece uses for byte-fallback tokens.
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

// GPT-2 byte encoder. GPT-2 remaps the 256 byte values onto printable Unicode
// so its vocabulary never contains a raw control character: byte 0x0A becomes
// U+010A ("Ã„Å "), space becomes U+0120 ("Ã„Â "). The mapping is the standard
// bytes_to_unicode() table, reproduced exactly rather than approximated.
static std::string Gpt2ByteSymbol(unsigned char b)
{
    // Printable ranges map to themselves (single-byte UTF-8).
    if ((b >= '!' && b <= '~') || (b >= 0xA1 && b <= 0xAC) || (b >= 0xAE && b <= 0xFF))
    {
        return std::string(1, (char)b);
    }
    // Everything else maps into U+0100..
    unsigned cp;
    if (b <= 0x20)
        cp = 256u + b;  // 0x00-0x20 -> U+0100-U+0120
    else if (b <= 0x7F)
        cp = 256u + b;  // unreachable (0x21-0x7E above)
    else if (b <= 0xA0)
        cp = 256u + 33u + (b - 0x7F);  // 0x7F-0xA0 -> U+0121-U+0142
    else
        cp = 256u + 33u + 34u;  // 0xAD       -> U+0143
    std::string s;
    if (cp < 0x800)
    {
        s += (char)(0xC0 | (cp >> 6));
        s += (char)(0x80 | (cp & 0x3F));
    }
    return s;
}

// Inverse of Gpt2ByteSymbol: mapped codepoint back to the original byte.
// Returns -1 for a codepoint that is not part of the remapped range.
static int Gpt2SymbolToByte(unsigned cp)
{
    if (cp < 256 || cp > 323)
        return -1;
    if (cp <= 288)
        return (int)(cp - 256);  // 0x00-0x20
    if (cp <= 322)
        return (int)(cp - 289 + 0x7F);  // 0x7F-0xA0
    return 0xAD;                        // 323
}

// True when the token text is a remapped GPT-2 byte pair (U+0100..U+0143).
static bool Gpt2RemappedToken(const std::string& t, int& byteOut)
{
    if (t.size() != 2)
        return false;
    const unsigned char b0 = (unsigned char)t[0];
    const unsigned char b1 = (unsigned char)t[1];
    if (b0 != 0xC4)
        return false;  // U+0100..U+0143 encodes as C4 xx
    if ((b1 & 0xC0) != 0x80)
        return false;
    const unsigned cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F);
    const int b = Gpt2SymbolToByte(cp);
    if (b < 0)
        return false;
    byteOut = b;
    return true;
}

// Normalise text the way llama.cpp's llm_tokenizer does for SentencePiece:
// each run of whitespace becomes one space marker, and the space marker for
// THIS vocab is DISCOVERED, not assumed.
//
// Two conventions exist:
//   * SentencePiece models use U+2581 ("Ã¢â€“Â", bytes E1 96 81)
//   * GPT-2/BPE-style vocabularies (DeepSeek, Qwen, CodeLlama...) use U+0120
//     ("G" with dot above, bytes C4 A0), which is why the merge table reads
//     "Ã¢â€“Â add" as "Ã„Â  Ã„Â add".
// The marker is picked by testing which one the token set actually contains,
// so a wrong assumption is a reported failure rather than a wrong encoding.
static const char* kSpMarker = "\xE1\x96\x81";  // U+2581
static const char* kGpt2Marker = "\xC4\xA0";    // U+0120

static const char* DetectSpaceMarker(const std::vector<std::string>& toks)
{
    for (const auto& t : toks)
    {
        if (t.find(kGpt2Marker) != std::string::npos)
            return kGpt2Marker;
    }
    for (const auto& t : toks)
    {
        if (t.find(kSpMarker) != std::string::npos)
            return kSpMarker;
    }
    return kSpMarker;  // default
}

static std::string SpNormalize(const std::string& in, const char* marker)
{
    std::string out;
    out.reserve(in.size() * 2);
    bool pendingSpace = false;
    for (size_t i = 0; i < in.size(); ++i)
    {
        const unsigned char c = (unsigned char)in[i];
        if (c == ' ' || c == '\t' || c == '\v' || c == '\f')
        {
            // One space marker per horizontal whitespace character.
            //
            // Collapsing a run to a single marker is SentencePiece behaviour,
            // not GPT-2's. GPT-2's BPE regex is " ?\p{L}+", so it emits one "Ä "
            // token per space, which is what preserves indentation: the previous
            // collapse turned "\n    return" into "\n return" and left the
            // byte-exact round-trip check failing on every indented block.
            out += marker;
            continue;
        }
        // NEWLINES ARE NOT WHITESPACE-COLLAPSIBLE.
        //
        // The previous behaviour folded '\n' into the space marker too, so
        // "def add(a, b):\n    return a + b" encoded as
        // "def add(a, b): return a + b" and every decode(encode(x)) round-trip on
        // multi-line text failed. For a GPT-2 vocabulary a newline is its own
        // token (U+000A), so it has to survive normalisation as a literal
        // character; BPE then either matches a real newline token or falls back
        // to byte tokens, and the detokenizer reproduces it exactly.
        if (c == '\n' || c == '\r')
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
    const std::string marker(DetectSpaceMarker(toks));
    std::string raw;
    for (int32_t id : ids)
    {
        if (id < 0 || (size_t)id >= toks.size())
            continue;
        const std::string& t = toks[(size_t)id];
        // Byte-fallback pieces assemble a raw byte string.
        if (t.size() == 6 && t[0] == '<' && t[1] == '0' && t[2] == 'x')
        {
            raw += (char)(unsigned)std::strtoul(t.c_str() + 3, nullptr, 16);
            continue;
        }
        // GPT-2 vocabularies store remapped bytes as multi-byte UTF-8: decode
        // U+0100..U+0143 back to the original byte. Without this a newline is
        // stored as "Ã„Å " and detokenizes to those two UTF-8 bytes rather than
        // 0x0A, so decode(encode(x)) never equals x on multi-line text.
        int gpt2Byte = 0;
        if (Gpt2RemappedToken(t, gpt2Byte))
        {
            raw += (char)gpt2Byte;
            continue;
        }
        raw += t;
    }
    // Replace the marker with a real space.
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

// Merge two adjacent symbols if the model's merge table allows it.
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
            // llama.cpp merge entries are "A B".
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

// SentencePiece BPE encoding, matching llama.cpp's approach:
//   1. Map every byte to its SentencePiece symbol character (byte fallback).
//   2. Seed the symbol list with single characters.
//   3. Repeatedly apply the LOWEST-RANK merge in the table until none applies.
// Greedy longest-match first is wrong: it picks different pieces than the
// merge-rank procedure, which is what the tokenizer was actually trained with.
struct SpEncoder
{
    bool ok = false;
    std::vector<std::string> tokens;  // id -> piece
    // "A B" -> rank. The rank ordering is what makes BPE correct.
    std::vector<std::string> mergeKeys;
    std::map<std::string, int32_t> rankOf;
    // id -> piece, for detokenising unknown pieces through byte fallback.
    std::map<std::string, int32_t> idOf;

    SpEncoder() = default;

    std::string marker;

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

    // Split the normalised text into SentencePiece characters (UTF-8 aware).
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

        const std::string norm = SpNormalize(text, marker.c_str());
        std::vector<std::string> syms;
        ToSpChars(norm, syms);
        if (syms.empty())
            return true;

        // BPE: repeatedly apply the lowest-rank merge that matches adjacent symbols.
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
            // Not a single token: emit byte-fallback pieces if the model has them.
            //
            // Two conventions are tried, because the vocab decides which one
            // applies, and guessing wrong is what produced <unk> for newlines:
            //   * the explicit byte tokens <0x0A> used by SentencePiece models
            //   * the GPT-2 byte-encoder symbol for the same byte ("Ã„Å ")
            bool emitted = false;
            for (size_t c = 0; c < s.size(); ++c)
            {
                const unsigned char byte = (unsigned char)s[c];
                int32_t id = -1;
                auto bit = idOf.find(ByteFallbackToken(s[c]));
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
                    emitted = false;
                    break;
                }
                ids.push_back(id);
                emitted = true;
            }
            if (!emitted)
            {
                ids.push_back(0);
            }
        }
        return true;
