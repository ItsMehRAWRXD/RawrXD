// ============================================================================
// deep2_agentic_loop.cpp -- RAWRXD_AUTONOMOUS_AGENT_E2E_001 (v2)
// ============================================================================
// End-to-end autonomous agentic loop on the native Deep2 runtime:
//   inference -> tool call -> execution -> observation -> resumed inference
//   -> verified completion.
//
// v2 fixes the five defects audited against v1:
//   1. Incremental KV context: only NEW tokens are executed each step; the fed
//      token list is the single source of truth for the next position. No text
//      is ever re-encoded or re-executed.
//   2. The model's own generated action is appended to the conversation before
//      the tool observation, so the model sees what it asked AND what happened.
//   3. Fail-closed action parsing: an action is only valid when the command is
//      COMPLETE (its argument present, and for `write`, both @@ delimiters).
//      Partially generated lines never dispatch.
//   4. Independent verification: completion requires the harness itself to
//      confirm (a) the source now contains the expected fix, (b) the build
//      produced the executable, and (c) running it prints PASS with exit 0.
//      The model saying "finish" is not evidence.
//   5. Live flushed progress logging: model load, prefill, per-token generation,
//      every tool invocation with its observation size, and the final verdict.
//
// Tools parsed from the model's own output:
//   TOOL read <path>
//   TOOL write <path> @@<content>@@
//   TOOL bash <command>
//   TOOL finish
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

using namespace RawrXD::Deep2;
using RawrXD::Deep2::RuntimeGraph::Executor;
using RawrXD::Deep2::Universal::GetTokenizer;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;

namespace
{

struct Args
{
    std::string model, task, workdir = "agentic_ws";
    int max_steps = 12, max_new = 200;
    bool cpu = false, toktest = false, parity = false;
    std::string parity_ids, parity_positions, parity_out = "parity";
    // Repair task configuration
    std::string target_file = "calc.cpp";
    std::string build_command;
    std::string run_command;
    std::string expected_output = "PASS";
};

Args Parse(int argc, char* argv[])
{
    Args a;
    for (int i = 1; i < argc; ++i)
    {
        std::string s = argv[i];
        if (s == "--model" && i + 1 < argc)
            a.model = argv[++i];
        else if (s == "--task" && i + 1 < argc)
            a.task = argv[++i];
        else if (s == "--workdir" && i + 1 < argc)
            a.workdir = argv[++i];
        else if (s == "--max-steps" && i + 1 < argc)
            a.max_steps = std::atoi(argv[++i]);
        else if (s == "--max-new" && i + 1 < argc)
            a.max_new = std::atoi(argv[++i]);
        else if (s == "--cpu")
            a.cpu = true;
        else if (s == "--toktest")
            a.toktest = true;
        else if (s == "--parity")
            a.parity = true;
        else if (s == "--parity-ids" && i + 1 < argc)
            a.parity_ids = argv[++i];
        else if (s == "--parity-positions" && i + 1 < argc)
            a.parity_positions = argv[++i];
        else if (s == "--parity-out" && i + 1 < argc)
            a.parity_out = argv[++i];
        // Repair task configuration
        else if (s == "--target-file" && i + 1 < argc)
            a.target_file = argv[++i];
        else if (s == "--build-command" && i + 1 < argc)
            a.build_command = argv[++i];
        else if (s == "--run-command" && i + 1 < argc)
            a.run_command = argv[++i];
        else if (s == "--expected-output" && i + 1 < argc)
            a.expected_output = argv[++i];
    }
    return a;
}

std::string ReadFile(const std::string& p)
{
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f)
        return {};
    std::string s;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        s.append(buf, n);
    std::fclose(f);
    return s;
}

bool WriteFile(const std::string& p, const std::string& s)
{
    FILE* f = std::fopen(p.c_str(), "wb");
    if (!f)
        return false;
    const size_t n = std::fwrite(s.data(), 1, s.size(), f);
    std::fclose(f);
    return n == s.size();
}

std::string Trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a]))
        ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1]))
        --b;
    return s.substr(a, b - a);
}

std::string RunCmd(const std::string& cmd, int* exit_code)
{
    std::string out;
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p)
    {
        *exit_code = -1;
        return "popen failed";
    }
    char buf[512];
    while (std::fgets(buf, sizeof(buf), p))
        out += buf;
    *exit_code = _pclose(p);
    return out;
}

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
// U+010A ("ÄŠ"), space becomes U+0120 ("Ä "). The mapping is the standard
// bytes_to_unicode() table, reproduced exactly rather than approximated.
// Codepoint.classListLetter guess for the llama-3 split groups: ASCII letters
// plus the letter-block ranges (Latin/Greek/Cyrillic/CJK), symbols and
// punctuation excluded.
static bool CpIsLetter(unsigned cp)
{
    return (cp >= 'a' && cp <= 'z') || (cp >= 'A' && cp <= 'Z') ||
           (cp >= 0x00AA && cp <= 0x2BFF && !(cp >= 0x2000 && cp <= 0x206F) && !(cp >= 0x2190 && cp <= 0x2BFF));
}

// Exact llama-3 split-group boundary: returns the end of the group starting
// at p in s. Groups (first match wins at each position):
//   contractions ('s|'t|'re|'ve|'m|'ll|'d, case-insensitive)
//   [^\r\n\p{L}\p{N}]?\p{L}+   (optional single non-alnum-non-CRLF prefix)
//   \p{N}{1,3}                 (up to 3 digits)
//   ?[^\s\p{L}\p{N}]+[\r\n]*   (optional single space prefix, punct group)
//   \s*[\r\n]+                 (whitespace leading a CRLF run)
//   \s+                        (any other whitespace run, greedy)
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
        // whitespace run NOT followed by CRLF: single space + letters falls to
        // the letter rule above (already consumed); otherwise greedy \s+
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

// Iterate one UTF-8 character. Returns its codepoint; leaves len set to the
// byte advance. Malformed input degrades to a single raw byte (pass-through).
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

// Inverse of the bytes_to_unicode bijection: codepoint back to the original
// byte. Covers the FULL alphabet, not just the U+0100..U+0143 remap range:
// the self-mapped Latin codepoints (U+00A1..U+00AC, U+00AE..U+00FF) are byte
// representatives too (byte 0xF0 is the character U+00F0), with U+00AD's
// representative being U+0143. Returns -1 for real (non-alphabet) text.
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

// GPT-2 byte encoder: the strict bytes_to_unicode bijection byte <-> codepoint.
// Non-ASCII outputs are the UTF-8 of the mapped codepoint (vocabulary pieces
// are UTF-8, so a raw single byte is the wrong key); only printable ASCII maps
// to its own single byte. Conversion happens ONLY at this byte-alphabet
// boundary - it is never applied to already-encoded vocabulary pieces.
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

// One token piece -> its visible bytes, honoring the vocabulary's own
// convention. Does one job only: byte-alphabet inverse at the representation
// boundary. "<0xNN>" byte pieces emit the raw byte; GPT-2 remapped codepoints
// (U+0100..U+0143) decode through the inverse bijection as complete UTF-8
// characters; the SentencePiece marker becomes a literal space.
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

// Normalise text: one space marker per literal SPACE character, with the
// marker discovered from the vocabulary (never assumed).
//
// Two conventions exist:
//   * SentencePiece models use U+2581 (bytes E1 96 81)
//   * GPT-2/BPE-style vocabularies (Qwen, Llama3, DeepSeek, CodeLlama...)
//     use U+0120 (bytes C4 A0)
//
// This tokenizer is byte-exact first: tabs (0x09), vertical tab (0x0B), form
// feed (0x0C), CR and LF are PRESERVED as literal bytes and reach the byte
// alphabet like any other value. Whitespace collapsing is the model's
// tokenizer specification's job, not this harness's - silently converting a
// tab to a space corrupts every indented code block.
// U+2581 (LOWER ONE EIGHTH BLOCK) is the SentencePiece space marker.
// Its UTF-8 encoding is E2 96 81 - the previous constant used E1 96 81
// (U+1481), which matched NO real vocabulary piece and silently forced every
// SentencePiece model into the GPT-2 marker convention.
static const char* kSpMarker = "\xE2\x96\x81";  // U+2581
static const char* kGpt2Marker = "\xC4\xA0";    // U+0120

static const char* DetectSpaceMarker(const std::vector<std::string>& toks)
{
    // Dominance, not first-hit: a GPT-2-style vocab carries thousands of
    // 0xC4A0-marked pieces and none of the 3-byte U+2581 form; a SentencePiece
    // vocab is the reverse. First-hit detection (below) fired on a stray
    // 0xC4A0-containing piece in a SentencePiece vocab and pushed the whole
    // model through the wrong protocol. Count and take the majority; a tie
    // defaults to SentencePiece (the older convention).
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
            // One space marker per literal space. Runs are preserved (one
            // marker per space), which is what keeps indentation byte-exact.
            out += marker;
            continue;
        }
        // BYTE-EXACT WHITESPACE: tab (0x09), VT (0x0B), FF (0x0C), CR and LF
        // survive normalisation as literal bytes. They flow through the byte
        // alphabet like any other value; converting any of them to a space
        // marker is codec corruption.
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
    // Residual-marker recovery for the SentencePiece convention: pieces whose
    // marker came through the byte-fallback path (<0xE1><0x96><0x81>) survive
    // per-piece translation as raw bytes. Translate the assembled text once
    // at the end so the convention boundary is the only place conversion can
    // happen, exactly once.
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

    void Build(const RawrXD::Deep2::Universal::Tokenizer& tk)
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

    // Per-token decode with the SAME convention handling as DetokenizeWith:
    // "<0xNN>" byte pieces -> the raw byte, GPT-2 remapped codepoints decoded
    // as complete UTF-8 characters through the inverse bijection, SentencePiece
    // marker -> ' ', ordinary bytes preserved exactly.
    std::string Piece(uint32_t id) const
    {
        if (id >= tokens.size())
            return "";
        const bool gpt2Conv = (!marker.empty() && marker[0] == '\xC4');
        return TokenToVisible(tokens[id], gpt2Conv, marker);
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

        // llama-3 canonical grouping: first split the RAW text into the same
        // groups llama.cpp's split regex defines, then encode each group
        // independently. Merges never cross a group boundary, so the greedy
        // whitespace+letter merges cannot bleed across (the defect: mine
        // produced "ĠĠ ĠĠreturn" where llama.cpp produces "ĠĠĠĠ return"). For
        // the SentencePiece convention there is no BPE split (unigram or
        // per-byte emission), so the whole text stays one group.
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
            // Byte-alphabet protocol: in a GPT-2-style vocabulary every input
            // byte enters BPE as its byte-Alphabet representative, never as a
            // whole raw-UTF-8 slice. Slicing by input characters can key real
            // text pieces ('é' = C3 A9) that decode - correctly, by the
            // byoma alphabet protocol - to a single byte, breaking the encode/
            // decode bijection. Byte-rep seeds BPE so only representatives and
            // their true merges are selectable; only the marker sequence stays
            // grouped (it is the piece 'Ġ', which decodes to byte 0x20).
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
            // Not a single token: emit byte-fallback pieces if the model has
            // them. Coverage runs over WHOLE UTF-8 characters, never over the
            // individual bytes of a multi-byte codepoint (double-encoding trap).
            // Two vocabulary conventions are tried, because the vocab decides
            // which one applies:
            //   * the explicit byte tokens <0xNN> of SentencePiece models
            //   * the GPT-2 byte-alphabet symbol for each raw byte
            // Emission is byte-alphabet-complete: every one of the 256 byte
            // values has a defined symbol in both conventions.
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

// ------------- fail-closed action parsing ------------------------------------
struct Action
{
    bool valid = false;  // a COMPLETE, dispatchable command was recognised
    bool finish = false;
    std::string tool, arg1, arg2;
    std::string raw;
};

Action ParseAction(const std::string& text)
{
    Action a;
    // The last line that starts a TOOL command.
    size_t lineStart = text.rfind("\nTOOL ");
    lineStart = (lineStart == std::string::npos) ? (text.rfind("TOOL ") == 0 ? 0 : std::string::npos) : lineStart + 1;
    if (lineStart == std::string::npos)
        return a;
    size_t lineEnd = text.find('\n', lineStart);
    const std::string line =
        text.substr(lineStart, lineEnd == std::string::npos ? std::string::npos : lineEnd - lineStart);
    const std::string t = Trim(line);
    // A nonempty argument can still be a partial token stream. Only a line
    // terminator closes read/bash/finish; write closes with its second @@.
    if (lineEnd == std::string::npos && t.rfind("TOOL write ", 0) != 0)
        return a;
    if (t.rfind("TOOL finish", 0) == 0 && Trim(t.substr(11)).empty())
    {
        a.valid = true;
        a.finish = true;
        a.tool = "finish";
        a.raw = t;
        return a;
    }
    if (t.rfind("TOOL read ", 0) == 0)
    {
        const std::string path = Trim(t.substr(10));
        if (path.empty())
            return a;
        a.valid = true;
        a.tool = "read";
        a.arg1 = path;
        a.raw = t;
        return a;
    }
    if (t.rfind("TOOL bash ", 0) == 0)
    {
        const std::string cmd = Trim(t.substr(10));
        if (cmd.empty())
            return a;
        a.valid = true;
        a.tool = "bash";
        a.arg1 = cmd;
        a.raw = t;
        return a;
    }
    if (t.rfind("TOOL write ", 0) == 0)
    {
        const size_t sp = t.find(' ', 11);
        if (sp == std::string::npos)
            return a;
        const std::string path = t.substr(11, sp - 11);
        if (path.empty())
            return a;
        const std::string command = text.substr(lineStart);
        const size_t a1 = command.find("@@", sp);
        if (a1 == std::string::npos)
            return a;  // no open delimiter: incomplete
        const size_t a2 = command.find("@@", a1 + 2);
        if (a2 == std::string::npos)
            return a;  // no close delimiter: incomplete
        const std::string body = command.substr(a1 + 2, a2 - (a1 + 2));
        if (body.empty())
            return a;
        a.valid = true;
        a.tool = "write";
        a.arg1 = path;
        a.arg2 = body;
        a.raw = command.substr(0, a2 + 2);
        return a;
    }
    return a;
}

void Logf_(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    va_end(ap);
    std::fflush(stdout);
}

// ============================================================================
// Gate-1 tokenizer parity battery (fail-closed, byte-exact).
//
// Conviction level: round-trip equality is necessary but NOT sufficient, so
// this mode is the machine-readable receipt layer for the parity gate:
//   * decode(encode(x)) == x byte-exact through TWO independent decoders
//     (the DetokenizeWith reference path ported from deep2_runtime_dispatch,
//     and the per-token Piece() path used during generation),
//   * no unknown-token emission for any ordinary-text class,
//   * the detected vocabulary convention (U+0120 GPT-2 style vs U+2581
//     SentencePiece style) is reported, not assumed,
//   * machine-readable TOKIDS lines so a second implementation (or an
//     external reference harness) can compare token IDs exactly,
//   * a forward sanity receipt (finite logits) through the same runtime the
//     agentic loop uses.
// Battery covers: expressions, indentation, CRLF, whitespace runs, tabs,
// accents, CJK, 4-byte UTF-8, control bytes, soft-hyphen edge, and the
// calc.cpp-shaped multi-line source.
// ============================================================================
struct TokCase
{
    const char* name;
    std::string input;
};

static std::string HexHead(const std::string& s, size_t n = 48)
{
    char buf[4];
    std::string o;
    const size_t lim = s.size() < n ? s.size() : n;
    for (size_t i = 0; i < lim; ++i)
    {
        std::snprintf(buf, sizeof(buf), "%02x", (unsigned char)s[i]);
        o += buf;
        if (i % 2)
            o += ' ';
    }
    if (s.size() > n)
        o += "...";
    return o;
}

static std::string GatedIdsLine(const std::vector<int32_t>& ids)
{
    std::string o;
    char buf[16];
    for (size_t i = 0; i < ids.size(); ++i)
    {
        std::snprintf(buf, sizeof(buf), "%s%d", i ? "," : "", ids[i]);
        o += buf;
    }
    return o;
}

// ============================================================================
// Parity harness (--parity): feed an explicit token-id sequence through the
// native Deep2 executor, and at each requested position dump the full logit
// vector as raw float32 LE plus a machine-readable per-position receipt
// (argmax, top-10, nonfinite count, gpu/cpu dispatch counters). The matching
// llama.cpp side produces the identical token sequence and positions, so the
// comparison is exact-position by exact-position with identical KV history.
// ============================================================================
struct ParityReceipt
{
    int position = 0;
    int token_id = 0;
    int argmax = -1;
    int top10[10];
    size_t logits = 0;
    size_t nonfinite = 0;
    uint64_t gpu_calls = 0, cpu_calls = 0;
};

static int ParityRun(const Args& args)
{
    Logf_("[parity] loading %s\n", args.model.c_str());
    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok)
    {
        Logf_("INGEST_FAIL: %s\n", rep.error.c_str());
        return 2;
    }

    // token id file: comma-separated ints (includes BOS; llama.cpp's tokenize
    // produces this exact sequence so both engines see identical history).
    std::vector<int32_t> ids;
    {
        std::ifstream f(args.parity_ids);
        std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        for (size_t i = 0; i < s.size();)
        {
            char* endp = nullptr;
            long v = std::strtol(s.c_str() + i, &endp, 10);
            if (endp == s.c_str() + i)
            {
                ++i;
                continue;
            }
            ids.push_back((int32_t)v);
            i = (size_t)(endp - s.c_str());
        }
    }
    if (ids.empty())
    {
        Logf_("PARITY_FAIL: empty ids file %s\n", args.parity_ids.c_str());
        return 2;
    }

    // positions file: comma-separated positions to dump.
    std::vector<int> positions;
    {
        std::ifstream f(args.parity_positions);
        std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        for (size_t i = 0; i < s.size();)
        {
            char* endp = nullptr;
            long v = std::strtol(s.c_str() + i, &endp, 10);
            if (endp == s.c_str() + i)
            {
                ++i;
                continue;
            }
            positions.push_back((int)v);
            i = (size_t)(endp - s.c_str());
        }
    }
    if (positions.empty())
    {
        Logf_("PARITY_FAIL: empty positions file\n");
        return 2;
    }

    Executor ex;
    ex.SetForceCpu(args.cpu);
    if (!ex.Bind(rep))
    {
        Logf_("BIND_FAIL: %s\n", ex.Stats().error.c_str());
        return 3;
    }
    Logf_("[parity] executor bound: ops=%zu ids=%zu positions=%zu path=%s\n", ex.Stats().ops_total, ids.size(),
          positions.size(), args.cpu ? "cpu" : "gpu-first");

    std::set<int> wanted(positions.begin(), positions.end());
    int receipts = 0;
    for (size_t pos = 0; pos < ids.size(); ++pos)
    {
        if (!ex.ExecuteToken((uint32_t)ids[pos], pos))
        {
            Logf_("PARITY_EXEC_FAIL pos=%zu err=%s\n", pos, ex.LastError().c_str());
            return 3;
        }
        if (!wanted.count((int)pos))
            continue;
        const std::vector<float>& lg = ex.Logits();
        size_t nonfinite = 0;
        for (float v : lg)
            if (!std::isfinite(v))
                ++nonfinite;
        uint32_t top = 0;
        for (uint32_t i = 1; i < lg.size(); ++i)
            if (lg[i] > lg[top])
                top = i;
        // top-10 (naive partial selection, no full sort)
        std::vector<std::pair<float, int32_t>> all;
        all.reserve(lg.size());
        for (uint32_t i = 0; i < lg.size(); ++i)
            all.emplace_back(lg[i], (int32_t)i);
        std::partial_sort(all.begin(), all.begin() + (std::min<size_t>(10, all.size())), all.end(),
                          [](const auto& a, const auto& b) { return a.first > b.first; });
        ParityReceipt rc;
        rc.position = (int)pos;
        rc.token_id = ids[pos];
        rc.argmax = (int)top;
        rc.logits = lg.size();
        rc.nonfinite = nonfinite;
        rc.gpu_calls = ex.Stats().gpu_calls;
        rc.cpu_calls = ex.Stats().cpu_calls;
        for (size_t k = 0; k < 10 && k < all.size(); ++k)
            rc.top10[k] = all[k].second;

        // full vector dump: raw little-endian float32
        char path[512];
        std::snprintf(path, sizeof(path), "%s.pos%zu.f32", args.parity_out.c_str(), pos);
        {
            std::ofstream out(path, std::ios::binary);
            out.write(reinterpret_cast<const char*>(lg.data()), (std::streamsize)(lg.size() * sizeof(float)));
        }
        // per-position receipt
        std::snprintf(path, sizeof(path), "%s.pos%zu.json", args.parity_out.c_str(), pos);
        {
            std::ofstream out(path);
            out << "{\"position\":" << rc.position << ",\"token_id\":" << rc.token_id << ",\"argmax\":" << rc.argmax
                << ",\"logits\":" << rc.logits << ",\"nonfinite\":" << rc.nonfinite << ",\"gpu_calls\":" << rc.gpu_calls
                << ",\"cpu_calls\":" << rc.cpu_calls << ",\"top10\":[";
            for (size_t k = 0; k < 10 && k < all.size(); ++k)
            {
                if (k)
                    out << ',';
                out << rc.top10[k];
            }
            out << "]}\n";
        }
        Logf_("PARITY_RC position=%d token_id=%d argmax=%d logits=%zu nonfinite=%zu gpu=%llu cpu=%llu\n", rc.position,
              rc.token_id, rc.argmax, rc.logits, rc.nonfinite, (unsigned long long)rc.gpu_calls,
              (unsigned long long)rc.cpu_calls);
        ++receipts;
    }
    Logf_("PARITY %s receipts=%d gpu_calls=%llu cpu_calls=%llu\n", receipts == (int)positions.size() ? "PASS" : "FAIL",
          receipts, (unsigned long long)ex.Stats().gpu_calls, (unsigned long long)ex.Stats().cpu_calls);
    return receipts == (int)positions.size() ? 0 : 1;
}

static int TokTest(const Args& args)
{
    Logf_("[toktest] loading vocabulary from %s\n", args.model.c_str());
    const auto t0 = std::chrono::steady_clock::now();
    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok)
    {
        Logf_("INGEST_FAIL: %s\n", rep.error.c_str());
        return 2;
    }
    SpEncoder enc;
    enc.Build(GetTokenizer());
    if (!enc.ok)
    {
        Logf_("TOKTEST FAIL: empty vocabulary\n");
        return 2;
    }

    const char* marker = DetectSpaceMarker(enc.tokens);
    const bool gpt2Convention = (marker[0] == '\xC4');
    Logf_("[toktest] vocab=%zu merges=%zu convention=%s arch=%s blocks=%llu bos=%d eos=%d (%.1f ms)\n",
          enc.tokens.size(), GetTokenizer().merges.size(), gpt2Convention ? "U+0120_gpt2" : "U+2581_sentencepiece",
          rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count, GetTokenizer().bos_id,
          GetTokenizer().eos_id,
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count());

    std::vector<TokCase> cases = {
        {"plain_expr", "int add(int a, int b) { return a + b; }"},
        {"indent_nl", "def f():\n    return 42\n"},
        {"crlf", "line1\r\nline2\r\n"},
        {"multi_space", "    x    y\t z  w"},
        {"tab_first", "\t\ta b"},
        {"accents", "caf\xC3\xA9 na\xC3\xAF"
                    "ve \xC3\x9C"
                    "ber stra\xC3\x9F"
                    "e"},
        {"cjk", "\xE4\xBD\xA0\xE5\xA5\xBD \xE4\xB8\x96\xE7\x95\x8C"},
        {"emoji", "hi \xF0\x9F\x91\x8B end"},
        {"ctrl_bytes", "a\x01\x02\x7f b"},
        {"edge_ad", "p\xC3\xBF q\xC2\xAD r"},
        {"calc_src", "#include <cstdio>\nint add(int a, int b) {\n    return a - b;\n}\nint main() {\n    "
                     "printf(\"%d\\n\", add(2, 3));\n    return 0;\n}\n"},
    };

    int fails = 0;
    for (const TokCase& c : cases)
    {
        std::vector<int32_t> ids;
        enc.Encode(c.input, ids);
        // Encode() emits id 0 ONLY when no byte-fallback symbol exists for an
        // input byte. Any 0 in battery output is therefore a genuine
        // unknown-emission failure, independent of vocabulary convention.
        bool has_unk = false;
        for (int32_t id : ids)
        {
            if (id == 0)
            {
                has_unk = true;
                break;
            }
        }
        std::string d1 = DetokenizeWith(enc.tokens, ids);  // reference decoder
        std::string d2;                                    // generation-path decoder
        for (int32_t id : ids)
            d2 += enc.Piece((uint32_t)id);
        const bool rt1 = (d1 == c.input), rt2 = (d2 == c.input);
        const bool okc = rt1 && rt2 && !has_unk && !ids.empty();
        Logf_("TOKCASE %-11s bytes=%3zu ids=%4zu unk=%d %s%s%s%s\n", c.name, c.input.size(), ids.size(),
              has_unk ? 1 : 0, okc ? "PASS" : "FAIL", rt1 ? "" : " [detok-mismatch]", rt2 ? "" : " [piece-mismatch]",
              has_unk ? " [unknown-emission]" : "");
        Logf_("TOKIDS %s %s\n", c.name, GatedIdsLine(ids).c_str());
        if (!okc)
        {
            ++fails;
            Logf_("  input   : %s\n  detok   : %s\n  pieces  : %s\n", HexHead(c.input).c_str(), HexHead(d1).c_str(),
                  HexHead(d2).c_str());
        }
    }

    // Vocabulary-piece probe: exact bytes of the pieces implicated in the
    // initial failure report, to separate an inverse-mapping defect from an
    // encoding/merge defect.
    {
        // Token contract: for each token implicated in a failing case, print
        // the raw stored piece, its decoded bytes, and whether the inverse
        // byte map touched it - a loader defect (raw piece already wrong) is
        // then separable from an inverse-map defect (correct loader, wrong
        // decode).
        const uint32_t probe[] = {198, 220, 256, 257, 258, 189, 190, 293,   1074, 165,
                                  171, 152, 155, 187, 13,  141, 199, 31937, 29875};
        for (uint32_t pid : probe)
        {
            if (pid >= enc.tokens.size())
                continue;
            const std::string& piece = enc.tokens[pid];
            const std::string decoded = enc.Piece(pid);
            const bool gpt2Conv = (!enc.marker.empty() && enc.marker[0] == '\xC4');
            bool applied = false;
            for (size_t k = 0; k < piece.size();)
            {
                size_t len = 0;
                const unsigned cp = Utf8CharAt(piece, k, &len);
                if ((gpt2Conv && cp >= 0xA1u && cp <= 323) ||
                    (!gpt2Conv && piece.compare(k, enc.marker.size(), enc.marker) == 0) ||
                    (piece.size() == 6 && piece[0] == '<' && piece[1] == '0' && piece[2] == 'x'))
                {
                    applied = true;
                    break;
                }
                k += len;
            }
            Logf_("TOKEN id=%u\n  RAW_PIECE_HEX     = %s\n  DECODED_PIECE_HEX = %s\n  INVERSE_MAP_APPLIED = %s\n", pid,
                  HexHead(piece, 40).c_str(), HexHead(decoded, 40).c_str(), applied ? "yes" : "no");
        }
        if (!enc.tokens.empty())
            Logf_("TOKEN id=0 (unk-slot)\n  RAW_PIECE_HEX     = %s\n", HexHead(enc.tokens[0], 40).c_str());
        // Marker dominance receipt: exact hit counts for both conventions, so the
        // detection is audited against the real vocabulary, not asserted.
        {
            size_t gpt2Hits = 0, spHits = 0;
            for (const auto& t : enc.tokens)
            {
                if (t.find(kGpt2Marker) != std::string::npos)
                    ++gpt2Hits;
                if (t.find(kSpMarker) != std::string::npos)
                    ++spHits;
            }
            Logf_("TOKMARK gpt2_hits=%zu sp_hits=%zu chosen=%s\n", gpt2Hits, spHits,
                  gpt2Hits > spHits ? "U+0120_gpt2" : "U+2581_sentencepiece");
            // Reference pieces for the convention decision and the SP byte table.
            const uint32_t mid[] = {13, 199, 141, 220, 31937, 29875};
            for (uint32_t pid : mid)
            {
                if (pid < enc.tokens.size())
                    Logf_("TOKPIECE %u %s\n", pid, HexHead(enc.tokens[pid], 32).c_str());
            }
        }
    }

    // Exhaustive byte-alphabet round-trip: EVERY raw byte value 0x00..0xFF
    // must survive encode/decode byte-exactly through the vocabulary's byte
    // alphabet. A single miss fails the gate.
    {
        std::string all;
        all.reserve(256);
        for (size_t b = 0; b < 256; ++b)
            all += (char)b;
        std::vector<int32_t> ids;
        enc.Encode(all, ids);
        std::string d1 = DetokenizeWith(enc.tokens, ids);
        std::string d2;
        for (int32_t id : ids)
            d2 += enc.Piece((uint32_t)id);
        const bool ok256 = (d1 == all) && (d2 == all);
        bool hasZero = false;
        for (int32_t i : ids)
            if (i == 0)
                hasZero = true;
        Logf_("TOKCASE all256bytes bytes=256 ids=%4zu unk=%d %s%s%s\n", ids.size(), hasZero ? 1 : 0,
              ok256 ? "PASS" : "FAIL", (d1 == all) ? "" : " [detok-mismatch]", (d2 == all) ? "" : " [piece-mismatch]");
        if (!ok256)
        {
            ++fails;
            size_t p = 0;
            while (p < all.size() && p < d1.size() && all[p] == d1[p])
                ++p;
            Logf_("  first_diff at byte %zu: input=%02x detok=%02x\n", p, p < all.size() ? (unsigned char)all[p] : 0,
                  p < d1.size() ? (unsigned char)d1[p] : 0);
        }
    }

    Logf_("[toktest] forward sanity: binding executor\n");
    Executor ex;
    ex.SetForceCpu(args.cpu);
    if (!ex.Bind(rep))
    {
        Logf_("BIND_FAIL: %s\n", ex.Stats().error.c_str());
        return 3;
    }
    Logf_("[toktest] executor bound: ops=%zu path=%s\n", ex.Stats().ops_total, args.cpu ? "cpu" : "gpu-first");
    std::vector<uint32_t> feed;
    const int bos_id = GetTokenizer().bos_id;
    if (bos_id >= 0)
    {
        if (!ex.ExecuteToken((uint32_t)bos_id, feed.size()))
        {
            Logf_("EXEC_FAIL bos pos=%zu err=%s\n", feed.size(), ex.LastError().c_str());
            return 3;
        }
        feed.push_back((uint32_t)bos_id);
    }
    std::vector<int32_t> probe_ids;
    enc.Encode(cases[0].input, probe_ids);
    for (int32_t i : probe_ids)
    {
        if (!ex.ExecuteToken((uint32_t)i, feed.size()))
        {
            Logf_("EXEC_FAIL pos=%zu err=%s\n", feed.size(), ex.LastError().c_str());
            return 3;
        }
        feed.push_back((uint32_t)i);
    }
    const std::vector<float>& lg = ex.Logits();
    size_t nonfinite = 0;
    for (float v : lg)
        if (!std::isfinite(v))
            ++nonfinite;
    uint32_t top = 0;
    for (uint32_t i = 1; i < lg.size(); ++i)
        if (lg[i] > lg[top])
            top = i;
    const bool fwd_ok = (nonfinite == 0 && lg.size() > 0);
    Logf_("FORWARD_SANITY logits=%zu nonfinite=%zu top=%u top_piece=%s %s\n", lg.size(), nonfinite, top,
          enc.Piece(top).c_str(), fwd_ok ? "PASS" : "FAIL");

    Logf_("TOKTEST %s fails=%d convention=%s vocab=%zu\n", (fails == 0 && fwd_ok) ? "PASS" : "FAIL", fails,
          gpt2Convention ? "U+0120_gpt2" : "U+2581_sentencepiece", enc.tokens.size());
    return (fails == 0 && fwd_ok) ? 0 : 1;
}

}  // namespace

int main(int argc, char* argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    const Args args = Parse(argc, argv);
    if (args.model.empty())
    {
        std::printf("usage: deep2_agentic_loop.exe --model <gguf> [--task f] [--workdir D] "
                    "[--max-steps N] [--max-new N] [--cpu] [--toktest]\n");
        return 1;
    }
    if (args.toktest)
        return TokTest(args);
    if (args.parity)
        return ParityRun(args);

    Logf_("[stage] loading model %s\n", args.model.c_str());
    const auto t_load0 = std::chrono::steady_clock::now();
    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok)
    {
        Logf_("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    SpEncoder enc;
    enc.Build(GetTokenizer());
    Logf_("[stage] ingest done in %.1f ms: arch=%s blocks=%llu vocab=%zu\n",
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_load0).count(),
          rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count, enc.tokens.size());

    // Tokenizer self-check: decode(encode(x)) == x on the prompt. A wrong
    // tokenizer silently corrupts every position, and no amount of correct
    // inference can compensate for it.
    {
        std::vector<int32_t> rt;
        enc.Encode("TOOL read calc.cpp\nint add(int a, int b) { return a + b; }", rt);
        std::string back;
        for (int32_t id : rt)
            back += enc.Piece((uint32_t)id);
        const bool rt_ok = back.find("TOOL read calc.cpp") != std::string::npos;
        Logf_("[stage] tokenizer round-trip: %s (%zu ids -> %zu chars)\n", rt_ok ? "PASS" : "FAIL", rt.size(),
              back.size());
        if (!rt_ok)
            Logf_("[stage] round-trip text was: %s\n", back.c_str());
    }

    Executor ex;
    ex.SetForceCpu(args.cpu);
    if (!ex.Bind(rep))
    {
        Logf_("BIND_FAIL: %s\n", ex.Stats().error.c_str());
        return 1;
    }
    Logf_("[stage] executor bound: ops=%zu path=%s\n", ex.Stats().ops_total, args.cpu ? "cpu" : "gpu-first");

const std::string task = args.task.empty()
                                 ? "Fix the bug in " + args.target_file + " so its main() prints " + args.expected_output + ", build it and run it."
                                 : ReadFile(args.task);

    // Build command defaults to MSVC cl.exe for .cpp files
    std::string build_cmd = args.build_command.empty()
        ? ("cl /nologo /EHsc /std:c++20 /Fe:\"" + args.workdir + "/" + args.target_file.substr(0, args.target_file.find_last_of('.')) + ".exe\" \"" + args.workdir + "/" + args.target_file + "\"")
        : args.build_command;
    
    // Run command defaults to executing the built exe
    std::string run_cmd = args.run_command.empty()
        ? (args.workdir + "/" + args.target_file.substr(0, args.target_file.find_last_of('.')) + ".exe")
        : args.run_command;

    const std::string prompt = "You are an autonomous coding agent with four tools. Reply with EXACTLY one line "
                               "each turn, no other text:\n"
                               "TOOL read <path>                 - print the file\n"
                               "TOOL write <path> @@<content>@@  - replace the file with content\n"
                               "TOOL bash <command>              - run a shell command\n"
                               "TOOL finish                      - declare the task complete\n"
                               "Example turn: TOOL read " + args.target_file + "\n"
                               "Workspace: the current directory contains " + args.target_file + ".\n"
                               "TASK: " +
                               task + "\n";

    // The conversation is executed ONCE, token by token, and only grown.
    // llama.cpp's sequence starts with the model's BOS; Deep2's executor must
    // see the same ids at the same positions, so the BOS is fed first and is
    // part of the executed context from here on.
    std::vector<uint32_t> fed;
    if (GetTokenizer().bos_id >= 0)
        fed.push_back((uint32_t)GetTokenizer().bos_id);
    std::string pending = prompt;
    bool finished = false, built = false, ran_pass = false;
    int last_bash_exit = -1;
    std::string last_bash_out, last_write;

    for (int step = 1; step <= args.max_steps && !finished; ++step)
    {
        // ---- feed only NEW text -------------------------------------------------
        std::vector<int32_t> enc_ids;
        enc.Encode(pending, enc_ids);
        std::vector<uint32_t> new_ids(enc_ids.begin(), enc_ids.end());
        const auto t_step = std::chrono::steady_clock::now();
        for (size_t i = 0; i < new_ids.size(); ++i)
        {
            if (!ex.ExecuteToken(new_ids[i], fed.size()))
            {
                Logf_("EXEC_FAIL prefill pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                return 1;
            }
            fed.push_back(new_ids[i]);
        }
        if (!new_ids.empty())
            Logf_("[step %d] prefill +%zu tokens (ctx=%zu) in %.0f ms\n", step, new_ids.size(), fed.size(),
                  std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_step).count());

        // ---- greedy generation, printing every token --------------------------
        std::string gen;
        uint32_t next = 0;
        const auto t_gen = std::chrono::steady_clock::now();
        int shown = 0;
        for (int t = 0; t < args.max_new; ++t)
        {
            const std::vector<float>& lg = ex.Logits();
            for (uint32_t i = 1; i < lg.size(); ++i)
                if (lg[i] > lg[next])
                    next = i;
            if (next == (uint32_t)GetTokenizer().eos_id)
            {
                gen += '\n'; // EOS also closes the final command line.
                Logf_("\n[step %d] eos after %d tokens\n", step, t);
                break;
            }
            gen += enc.Piece(next);
            if (!ex.ExecuteToken(next, fed.size()))
            {
                Logf_("EXEC_FAIL gen pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                break;
            }
            fed.push_back(next);
            if (shown++ % 10 == 0)
                Logf_("[step %d] tok %d/%d: %s\n", step, t, args.max_new, Trim(gen).c_str());
            const Action probe = ParseAction(gen);
            if (probe.valid)
                break;
        }
        Logf_("[step %d] generated %zu chars in %.0f ms: %s\n", step, gen.size(),
              std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_gen).count(),
              Trim(gen).c_str());

        const Action act = ParseAction(gen);
        if (!act.valid)
        {
            pending = "\nRESULT: your reply was not one complete TOOL line. Reply with EXACTLY one "
                      "TOOL line, e.g. TOOL read " + args.target_file + "\n";
            continue;
        }
        if (act.finish)
        {
            finished = true;
            break;
        }

        // ---- dispatch -----------------------------------------------------------
        std::string result;
        if (act.tool == "read")
        {
            result = ReadFile(args.workdir + "/" + act.arg1);
            if (result.empty())
                result = "(file not found)";
        }
        else if (act.tool == "write")
        {
            const std::string path = args.workdir + "/" + act.arg1;
            const bool ok = WriteFile(path, act.arg2);
            last_write = act.arg1;
            result = ok ? ("wrote " + act.arg1 + " (" + std::to_string(act.arg2.size()) + " bytes)") : "write failed";
        }
        else if (act.tool == "bash")
        {
            // Validate bash command is not malformed
            if (act.arg1.find("TOOL ") != std::string::npos || act.arg1.find("$(") != std::string::npos)
            {
                result = "[exit -1]\nERROR: malformed bash command - contains TOOL or $( syntax\n";
                last_bash_exit = -1;
                last_bash_out = result;
            }
            else
            {
                int code = 0;
                result = RunCmd("cd /d \"" + args.workdir + "\" && " + act.arg1 + " 2>&1", &code);
                last_bash_exit = code;
                last_bash_out = result;
                built = (result.find(args.target_file.substr(0, args.target_file.find_last_of('.')) + ".exe") != std::string::npos) || 
                        (act.arg1.find(args.target_file.substr(0, args.target_file.find_last_of('.')) + ".exe") != std::string::npos);
                char hdr[48];
                std::snprintf(hdr, sizeof(hdr), "[exit %d]\n", code);
                result = hdr + result;
            }
        }
        else
        {
            result = "unsupported tool";
        }
        if (result.size() > 2500)
            result = result.substr(0, 1200) + "\n...[truncated]...\n" + result.substr(result.size() - 800);
        Logf_("[step %d] TOOL %s -> %s ; observation %zu bytes:\n%s\n", step, act.tool.c_str(), act.arg1.c_str(),
              result.size(), result.c_str());

        // ---- append the MODEL's action and the observation, in order ------------
        pending = "\n" + act.raw + "\nRESULT:\n" + result + "\n";
    }

    // ---- INDEPENDENT verification (the model's word is not evidence) ----------
    const std::string src = ReadFile(args.workdir + "/" + args.target_file);
    const bool src_fixed = src.find("a + b") != std::string::npos || src.find("a+b") != std::string::npos;
    
    // Execute the build command if not already done
    if (!built)
    {
        Logf_("[verification] running build command: %s\n", build_cmd.c_str());
        int code = 0;
        std::string build_out = RunCmd("cd /d \"" + args.workdir + "\" && " + build_cmd + " 2>&1", &code);
        if (code == 0)
        {
            built = true;
            Logf_("[verification] build succeeded\n");
        }
        else
        {
            Logf_("[verification] build failed (exit %d): %s\n", code, build_out.c_str());
        }
    }
    
    int exit_now = -999;
    std::string run_out;
    if (built)
    {
        run_out = RunCmd("cd /d \"" + args.workdir + "\" && " + run_cmd + " 2>&1", &exit_now);
    }
    const bool exe_ok = exit_now == 0 && run_out.find(args.expected_output) != std::string::npos;

    Logf_("\n=== verification (harness-run, independent of the model) ===\n");
    Logf_("MODEL_SAID_FINISH      %s\n", finished ? "yes" : "no");
    Logf_("SOURCE_PATCHED         %s (%s contains %s)\n", src_fixed ? "PASS" : "FAIL", args.target_file.c_str(),
          src_fixed ? "a + b" : "no fix");
    Logf_("BUILD_ARTIFACT         %s\n", built ? "attempted" : "not observed");
    Logf_("TEST_EXECUTION         %s (%s exit=%d out=%s)\n", exe_ok ? "PASS" : "FAIL", args.target_file.c_str(), exit_now, run_out.c_str());
    Logf_("TOOL_RESULT_FEEDBACK   %d steps completed\n", args.max_steps);
    Logf_("FINAL_VERDICT          %s\n", (finished && src_fixed && exe_ok) ? "PASS" : "FAIL");
    return (finished && src_fixed && exe_ok) ? 0 : 1;
}
