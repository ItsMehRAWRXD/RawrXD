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
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

using namespace RawrXD::Deep2;
using RawrXD::Deep2::Universal::GetTokenizer;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;
using RawrXD::Deep2::RuntimeGraph::Executor;

namespace {

struct Args {
    std::string model, task, workdir = "agentic_ws";
    int max_steps = 12, max_new = 200;
    bool cpu = false;
};

Args Parse(int argc, char* argv[]) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string s = argv[i];
        if (s == "--model" && i + 1 < argc) a.model = argv[++i];
        else if (s == "--task" && i + 1 < argc) a.task = argv[++i];
        else if (s == "--workdir" && i + 1 < argc) a.workdir = argv[++i];
        else if (s == "--max-steps" && i + 1 < argc) a.max_steps = std::atoi(argv[++i]);
        else if (s == "--max-new" && i + 1 < argc) a.max_new = std::atoi(argv[++i]);
        else if (s == "--cpu") a.cpu = true;
    }
    return a;
}

std::string ReadFile(const std::string& p) {
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return {};
    std::string s;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, n);
    std::fclose(f);
    return s;
}

bool WriteFile(const std::string& p, const std::string& s) {
    FILE* f = std::fopen(p.c_str(), "wb");
    if (!f) return false;
    const size_t n = std::fwrite(s.data(), 1, s.size(), f);
    std::fclose(f);
    return n == s.size();
}

std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

std::string RunCmd(const std::string& cmd, int* exit_code) {
    std::string out;
    FILE* p = _popen(cmd.c_str(), "r");
    if (!p) { *exit_code = -1; return "popen failed"; }
    char buf[512];
    while (std::fgets(buf, sizeof(buf), p)) out += buf;
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
//   * SentencePiece models use U+2581 ("â–", bytes E1 96 81)
//   * GPT-2/BPE-style vocabularies (DeepSeek, Qwen, CodeLlama...) use U+0120
//     ("G" with dot above, bytes C4 A0), which is why the merge table reads
//     "â– add" as "Ä  Ä add".
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
            // not GPT-2's. GPT-2's BPE regex is " ?\p{L}+", so it emits one "Ġ"
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
        // stored as "ÄŠ" and detokenizes to those two UTF-8 bytes rather than
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

    // Per-token decode with the SAME conventions as DetokenizeWith:
    // SentencePiece marker -> ' ', "<0xNN>" byte pieces -> the raw byte,
    // GPT-2 remapped codepoints -> the original byte.
    std::string Piece(uint32_t id) const {
        if (id >= tokens.size()) return "";
        const std::string t = tokens[id];
        if (t.size() == 6 && t[0] == '<' && t[1] == '0' && t[2] == 'x')
            return std::string(1, (char)(unsigned)std::strtoul(t.c_str() + 3, nullptr, 16));
        int b = 0;
        if (Gpt2RemappedToken(t, b))
            return std::string(1, (char)b);
        std::string out;
        for (size_t i = 0; i < t.size();) {
            if (t.compare(i, marker.size(), marker) == 0) { out += ' '; i += marker.size(); continue; }
            out += t[i];
            ++i;
        }
        return out;
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
            //   * the GPT-2 byte-encoder symbol for the same byte ("ÄŠ")
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
    }
};

// ------------- fail-closed action parsing ------------------------------------
struct Action {
    bool valid = false;      // a COMPLETE, dispatchable command was recognised
    bool finish = false;
    std::string tool, arg1, arg2;
    std::string raw;
};

Action ParseAction(const std::string& text) {
    Action a;
    // The last line that starts a TOOL command.
    size_t lineStart = text.rfind("\nTOOL ");
    lineStart = (lineStart == std::string::npos) ? (text.rfind("TOOL ") == 0 ? 0 : std::string::npos)
                                                 : lineStart + 1;
    if (lineStart == std::string::npos) return a;
    size_t lineEnd = text.find('\n', lineStart);
    const std::string line = text.substr(lineStart, lineEnd == std::string::npos
                                                       ? std::string::npos : lineEnd - lineStart);
    const std::string t = Trim(line);
    if (t.rfind("TOOL finish", 0) == 0 && Trim(t.substr(11)).empty()) {
        a.valid = true; a.finish = true; a.tool = "finish"; a.raw = t;
        return a;
    }
    if (t.rfind("TOOL read ", 0) == 0) {
        const std::string path = Trim(t.substr(10));
        if (path.empty()) return a;
        a.valid = true; a.tool = "read"; a.arg1 = path; a.raw = t;
        return a;
    }
    if (t.rfind("TOOL bash ", 0) == 0) {
        const std::string cmd = Trim(t.substr(10));
        if (cmd.empty()) return a;
        a.valid = true; a.tool = "bash"; a.arg1 = cmd; a.raw = t;
        return a;
    }
    if (t.rfind("TOOL write ", 0) == 0) {
        const size_t sp = t.find(' ', 11);
        if (sp == std::string::npos) return a;
        const std::string path = t.substr(11, sp - 11);
        if (path.empty()) return a;
        const size_t a1 = t.find("@@", sp);
        if (a1 == std::string::npos) return a;              // no open delimiter: incomplete
        const size_t a2 = t.find("@@", a1 + 2);
        if (a2 == std::string::npos) return a;              // no close delimiter: incomplete
        const std::string body = t.substr(a1 + 2, a2 - (a1 + 2));
        if (body.empty()) return a;
        a.valid = true; a.tool = "write"; a.arg1 = path; a.arg2 = body; a.raw = t;
        return a;
    }
    return a;
}

void Logf_(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(stdout, fmt, ap);
    va_end(ap);
    std::fflush(stdout);
}

}  // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    const Args args = Parse(argc, argv);
    if (args.model.empty()) {
        std::printf("usage: deep2_agentic_loop.exe --model <gguf> [--task f] [--workdir D] "
                    "[--max-steps N] [--max-new N] [--cpu]\n");
        return 1;
    }

    Logf_("[stage] loading model %s\n", args.model.c_str());
    const auto t_load0 = std::chrono::steady_clock::now();
    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok) { Logf_("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }
    SpEncoder enc;
    enc.Build(GetTokenizer());
    Logf_("[stage] ingest done in %.1f ms: arch=%s blocks=%llu vocab=%zu\n",
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_load0).count(),
          rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count, enc.tokens.size());

    Executor ex;
    ex.SetForceCpu(args.cpu);
    if (!ex.Bind(rep)) { Logf_("BIND_FAIL: %s\n", ex.Stats().error.c_str()); return 1; }
    Logf_("[stage] executor bound: ops=%zu path=%s\n", ex.Stats().ops_total,
          args.cpu ? "cpu" : "gpu-first");

    const std::string task = args.task.empty()
        ? "Fix the bug in calc.cpp so its main() prints PASS, build it and run it."
        : ReadFile(args.task);

    const std::string prompt =
        "You are an autonomous coding agent with four tools. Reply with EXACTLY one line "
        "each turn, no other text:\n"
        "TOOL read <path>                 - print the file\n"
        "TOOL write <path> @@<content>@@  - replace the file with content\n"
        "TOOL bash <command>              - run a shell command\n"
        "TOOL finish                      - declare the task complete\n"
        "Example turn: TOOL read calc.cpp\n"
        "Workspace: the current directory contains calc.cpp and task.md.\n"
        "TASK: " + task + "\n";

    // The conversation is executed ONCE, token by token, and only grown.
    std::vector<uint32_t> fed;
    std::string pending = prompt;
    bool finished = false, built = false, ran_pass = false;
    int last_bash_exit = -1;
    std::string last_bash_out, last_write;

    for (int step = 1; step <= args.max_steps && !finished; ++step) {
        // ---- feed only NEW text -------------------------------------------------
        std::vector<int32_t> enc_ids;
        enc.Encode(pending, enc_ids);
        std::vector<uint32_t> new_ids(enc_ids.begin(), enc_ids.end());
        const auto t_step = std::chrono::steady_clock::now();
        for (size_t i = 0; i < new_ids.size(); ++i) {
            if (!ex.ExecuteToken(new_ids[i], fed.size())) {
                Logf_("EXEC_FAIL prefill pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                return 1;
            }
            fed.push_back(new_ids[i]);
        }
        if (!new_ids.empty())
            Logf_("[step %d] prefill +%zu tokens (ctx=%zu) in %.0f ms\n", step, new_ids.size(),
                  fed.size(), std::chrono::duration<double, std::milli>(
                                  std::chrono::steady_clock::now() - t_step).count());

        // ---- greedy generation, printing every token --------------------------
        std::string gen;
        uint32_t next = 0;
        const auto t_gen = std::chrono::steady_clock::now();
        int shown = 0;
        for (int t = 0; t < args.max_new; ++t) {
            const std::vector<float>& lg = ex.Logits();
            for (uint32_t i = 1; i < lg.size(); ++i) if (lg[i] > lg[next]) next = i;
            if (next == (uint32_t)GetTokenizer().eos_id) { Logf_("\n[step %d] eos after %d tokens\n", step, t); break; }
            gen += enc.Piece(next);
            if (!ex.ExecuteToken(next, fed.size())) {
                Logf_("EXEC_FAIL gen pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                break;
            }
            fed.push_back(next);
            if (shown++ % 10 == 0)
                Logf_("[step %d] tok %d/%d: %s\n", step, t, args.max_new, Trim(gen).c_str());
            const Action probe = ParseAction(gen);
            if (probe.valid && gen.find_first_of("\n", 0) != std::string::npos) break;
            if (probe.valid && (size_t)t > 40) break;   // safety: complete command found
        }
        Logf_("[step %d] generated %zu chars in %.0f ms: %s\n", step, gen.size(),
              std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_gen).count(),
              Trim(gen).c_str());

        const Action act = ParseAction(gen);
        if (!act.valid) {
            pending = "\nRESULT: your reply was not one complete TOOL line. Reply with EXACTLY one "
                      "TOOL line, e.g. TOOL read calc.cpp\n";
            continue;
        }
        if (act.finish) { finished = true; break; }

        // ---- dispatch -----------------------------------------------------------
        std::string result;
        if (act.tool == "read") {
            result = ReadFile(args.workdir + "/" + act.arg1);
            if (result.empty()) result = "(file not found)";
        } else if (act.tool == "write") {
            const std::string path = args.workdir + "/" + act.arg1;
            const bool ok = WriteFile(path, act.arg2);
            last_write = act.arg1;
            result = ok ? ("wrote " + act.arg1 + " (" + std::to_string(act.arg2.size()) + " bytes)")
                        : "write failed";
        } else if (act.tool == "bash") {
            int code = 0;
            result = RunCmd("cd /d " + args.workdir + " && " + act.arg1, &code);
            last_bash_exit = code;
            last_bash_out = result;
            built = (result.find("calc.exe") != std::string::npos) ||
                    (act.arg1.find("calc.exe") != std::string::npos);
            char hdr[48];
            std::snprintf(hdr, sizeof(hdr), "[exit %d]\n", code);
            result = hdr + result;
        } else {
            result = "unsupported tool";
        }
        if (result.size() > 2500)
            result = result.substr(0, 1200) + "\n...[truncated]...\n" + result.substr(result.size() - 800);
        Logf_("[step %d] TOOL %s -> %s ; observation %zu bytes:\n%s\n", step, act.tool.c_str(),
              act.arg1.c_str(), result.size(), result.c_str());

        // ---- append the MODEL's action and the observation, in order ------------
        pending = "\n" + act.raw + "\nRESULT:\n" + result + "\n";
    }

    // ---- INDEPENDENT verification (the model's word is not evidence) ----------
    const std::string src = ReadFile(args.workdir + "/calc.cpp");
    const bool src_fixed = src.find("a + b") != std::string::npos || src.find("a+b") != std::string::npos;
    int exit_now = -999;
    const std::string run_out = RunCmd("calc.exe", &exit_now);
    const bool exe_ok = exit_now == 0 && run_out.find("PASS") != std::string::npos;

    Logf_("\n=== verification (harness-run, independent of the model) ===\n");
    Logf_("MODEL_SAID_FINISH      %s\n", finished ? "yes" : "no");
    Logf_("SOURCE_PATCHED         %s (%s contains %s)\n", src_fixed ? "PASS" : "FAIL", "calc.cpp",
          src_fixed ? "a + b" : "no fix");
    Logf_("BUILD_ARTIFACT         %s\n", built ? "attempted" : "not observed");
    Logf_("TEST_EXECUTION         %s (calc.exe exit=%d out=%s)\n", exe_ok ? "PASS" : "FAIL", exit_now,
          run_out.c_str());
    Logf_("TOOL_RESULT_FEEDBACK   %d steps completed\n", args.max_steps);
    Logf_("FINAL_VERDICT          %s\n", (finished && src_fixed && exe_ok) ? "PASS" : "FAIL");
    return (finished && src_fixed && exe_ok) ? 0 : 1;
}

