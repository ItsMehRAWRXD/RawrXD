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
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <iomanip>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#include <io.h>
#include <process.h>
#pragma comment(lib, "advapi32.lib")
#endif

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "deep2_snap.hpp"
#include "snap_process_guard.hpp"
#include "../deep2_debugger/deep2_flight_recorder.hpp"
#include "../deep2/Deep2Log.hpp"   // single shared definition of Logf_()
#include "agent_esp.hpp"
#include "esp_runtime.hpp"
#include "esp_metrics.hpp"
#include "esp_cli.hpp"
#include "../src/agentic/MotdAuthorization.h"

#include "../cloud_api_client.h"

using namespace RawrXD::Deep2;
using RawrXD::Deep2::RuntimeGraph::Executor;
using RawrXD::Deep2::Universal::GetTokenizer;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;

namespace rawrxd::esp {
using Kind = rawrxd::esp::Kind;
using Bus = rawrxd::esp::Bus;
using Recorder = rawrxd::esp::Recorder;
using Event = rawrxd::esp::Event;
using ConsoleView = rawrxd::esp::ConsoleView;
}

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
    // H02/SNAP budgets and diagnostics
    int max_retries = 3;
    int max_total_tokens = 8192;
    int max_wall_time_sec = 300;
    bool single_turn = false;      // Test A: static prompt, one response, no loop
    bool single_turn_repair = false; // Test B: one tool command, execute, verify, exit
    bool full_prefill = false;  // baseline: re-feed the whole render each turn
    bool quiet = false;
    bool motd_selftest = false;       // Gate test; does not load a model or initialize GPU inference
    bool batched_prefill = true;  // PrefillBatch: P dots per op, one submission
    // FIRST-TOKEN PARITY: render a plain prompt (no tool protocol), prefill it,
    // and report the first generated token's full ranking with the EOS rank
    // called out explicitly, then continue greedily. Run with and without --cpu
    // and diff: identical output proves the GPU path is numerically faithful,
    // divergent output means the kernels - not the prompt - are wrong.
    std::string plain_prompt;
    int plain_tokens = 24;
    // FIRST-TOKEN PARITY certification: compare two raw float32 logit dumps
    // produced by --plain (one per backend) and emit the parity verdict.
    std::string diff_a, diff_b;
    // SAMPLING: configurable temperature instead of hard-coded greedy (temp=0)
    float temperature = 0.8f;
    // CONTEXT: minuscule context sizes for local models (e.g. 128 tokens)
    int context_size = 128;
    // CLOUD ROUTING: --provider selects inference backend
    //   deep2 = local GGUF via Deep2Engine (default)
    //   kilo = Kilo Gateway (free models)
    //   openrouter = OpenRouter (free models)
    std::string provider = "deep2";
    std::string api_key;  // Read from env if not set
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
        else if (s == "--parity" && i + 1 < argc)
            a.parity = true;
        else if (s == "--plain" && i + 1 < argc)
            a.plain_prompt = argv[++i];
        else if (s == "--plain-tokens" && i + 1 < argc)
            a.plain_tokens = std::atoi(argv[++i]);
        else if (s == "--diff-a" && i + 1 < argc)
            a.diff_a = argv[++i];
        else if (s == "--diff-b" && i + 1 < argc)
            a.diff_b = argv[++i];
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
        // H02/SNAP budgets and diagnostics
        else if (s == "--max-retries" && i + 1 < argc)
            a.max_retries = std::atoi(argv[++i]);
        else if (s == "--max-total-tokens" && i + 1 < argc)
            a.max_total_tokens = std::atoi(argv[++i]);
        else if (s == "--max-wall-time" && i + 1 < argc)
            a.max_wall_time_sec = std::atoi(argv[++i]);
        else if (s == "--single-turn")
            a.single_turn = true;
        else if (s == "--single-turn-repair")
        {
            a.single_turn_repair = true;
            a.single_turn = true; // implies single-turn behavior
        }
        else if (s == "--full-prefill")
            a.full_prefill = true;
        else if (s == "--quiet")
            a.quiet = true;
        else if (s == "--motd-selftest")
            a.motd_selftest = true;
        else if (s == "--batched-prefill" && i + 1 < argc)
            a.batched_prefill = std::atoi(argv[++i]) != 0;
        else if (s == "--temperature" && i + 1 < argc)
            a.temperature = static_cast<float>(std::atof(argv[++i]));
        else if (s == "--context-size" && i + 1 < argc)
            a.context_size = std::atoi(argv[++i]);
        else if (s == "--provider" && i + 1 < argc)
            a.provider = argv[++i];
        else if (s == "--api-key" && i + 1 < argc)
            a.api_key = argv[++i];
        else if (s == "--env-api-key" && i + 1 < argc)
        {
            const char* env_val = std::getenv(argv[++i]);
            if (env_val) a.api_key = env_val;
        }
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

// Make control characters visible in a log line. Token text is the primary
// evidence for chat-template defects (a missing '\n' or a stray EOS is
// invisible in raw output), so newlines/tabs/CIDs are rendered explicitly.
std::string EscapeForLog(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case 0x1A: out += "<SUB>"; break;   // Windows Ctrl+Z EOF in a pipe
        default:
            if (c < 0x20 || c == 0x7F)
            {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\x%02X", (unsigned)c);
                out += buf;
            }
            else
            {
                out += (char)c;
            }
        }
    }
    return out;
}

// Diagnostic-only: dump the exact bytes the model produced when the host
// rejects them. Keeps generated text local (it can echo file contents).
// This does not alter parser or generation behavior.
static void dump_snap_output(const char* tag, const std::string& output, int eos_id = -1,
                             const std::vector<uint32_t>* token_ids = nullptr)
{
    std::fprintf(stderr, "[%s RAW] bytes=%zu text=\"", tag, output.size());
    for (unsigned char c : output)
    {
        if (c == '\n') std::fputs("\\n", stderr);
        else if (c == '\r') std::fputs("\\r", stderr);
        else if (c == '\t') std::fputs("\\t", stderr);
        else if (c == '\\') std::fputs("\\\\", stderr);
        else if (c == '"') std::fputs("\\\"", stderr);
        else if (c >= 32 && c < 127) std::fputc(c, stderr);
        else std::fprintf(stderr, "\\x%02X", c);
    }
    std::fputs("\"\n", stderr);
    if (eos_id >= 0)
        std::fprintf(stderr, "[%s META] eos_id=%d\n", tag, eos_id);
    if (token_ids && !token_ids->empty())
    {
        std::fprintf(stderr, "[%s TOKENS] n=%zu ids=", tag, token_ids->size());
        for (size_t i = 0; i < token_ids->size() && i < 64; ++i)
            std::fprintf(stderr, "%s%u", i ? "," : "", (*token_ids)[i]);
        std::fprintf(stderr, "\n");
    }
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

// ---------------------------------------------------------------------------
// MSVC environment discovery.
//
// `cl` is not on PATH unless the process was started from a Developer prompt.
// The agentic loop must build real C++ to verify a repair, so it locates
// vcvars64.bat through vswhere and prefixes every build/test command with the
// initialization. Without this, a visually correct patch fails with
// "'cl' is not recognized" and the run reports a model failure.
//
// Fails closed on the FIRST build: the returned wrapper records whether a
// usable toolchain was found so the receipt can distinguish "the patch is wrong"
// from "there is no compiler".
// ---------------------------------------------------------------------------
struct MsvcEnv
{
    bool initialized = false;   // vcvars found and accepted
    std::string prefix;         // "" when cl is already on PATH
    std::string detail;         // human-readable decision trail
    std::string cl_path;        // resolved cl.exe, empty if none
};

static bool ExistsOnPath(const char* exe)
{
    // `where` is a cmd builtin; use GetEnvironmentVariable on PATH directly so
    // no shell is spawned (the shell is exactly what may not exist yet).
    char* path = nullptr;
    size_t len = 0;
    if (_dupenv_s(&path, &len, "PATH") != 0 || !path)
        return false;
    std::string p(path);
    free(path);
    size_t start = 0;
    while (start <= p.size())
    {
        size_t end = p.find(';', start);
        if (end == std::string::npos)
            end = p.size();
        std::string dir = p.substr(start, end - start);
        if (!dir.empty())
        {
            std::string cand = dir;
            if (cand.back() != '\\' && cand.back() != '/')
                cand += '\\';
            cand += exe;
            DWORD a = GetFileAttributesA(cand.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY))
                return true;
        }
        start = end + 1;
    }
    return false;
}

static MsvcEnv InitMsvcEnv()
{
    MsvcEnv env;

    // 1. Already usable? Then do not touch the command line at all.
    if (ExistsOnPath("cl.exe"))
    {
        env.initialized = true;
        env.detail = "cl.exe already on PATH";
        return env;
    }

    // 2. Locate vswhere. The IDE deepens nothing here: vswhere is installed by
    //    the Visual Studio Installer under the standard x86 Program Files path.
    const char* pf86 = getenv("ProgramFiles(x86)");
    if (!pf86)
        pf86 = getenv("ProgramFiles");
    if (!pf86)
    {
        env.detail = "no ProgramFiles(x86); cannot locate vswhere";
        return env;
    }
    std::string vswhere = std::string(pf86) + "\\Microsoft Visual Studio\\Installer\\vswhere.exe";
    if (GetFileAttributesA(vswhere.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        env.detail = "vswhere not found at " + vswhere;
        return env;
    }

    int code = 0;
    const std::string vs_path = Trim(RunCmd("\"" + vswhere + "\" -latest -products * -property installationPath 2>&1", &code));
    if (code != 0 || vs_path.empty())
    {
        env.detail = "vswhere failed or returned no installation (exit " + std::to_string(code) + ")";
        return env;
    }

    std::string vcvars = vs_path + "\\VC\\Auxiliary\\Build\\vcvars64.bat";
    if (GetFileAttributesA(vcvars.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        env.detail = "vcvars64.bat not found under " + vs_path;
        return env;
    }

    // 3. Verify the toolchain actually works before accepting it. This is the
    //    step that turns "a .bat exists" into "cl will build C++".
    //    `where cl` prints the resolved path and returns 0 only when the
    //    executable is genuinely reachable after initialization. `cl /Bv` is NOT
    //    usable as the probe: it prints its banner and then exits non-zero with
    //    D8003 ("missing source filename"), which makes a working toolchain look
    //    broken.
    const std::string probe =
        "cmd /d /s /c \"call \"" + vcvars + "\" >nul && where cl\"";
    const std::string probe_out = Trim(RunCmd(probe, &code));
    const bool cl_reachable = (code == 0) &&
        (probe_out.find("cl.exe") != std::string::npos);
    if (!cl_reachable)
    {
        env.detail = "vcvars64.bat ran but cl is still unreachable (exit " +
                     std::to_string(code) + "): " + (probe_out.empty() ? "<no output>" : probe_out);
        return env;
    }

    env.initialized = true;
    // /d skips AutoRun scripts, /s forces the quoted-call form used here, /c
    // runs then exits. The redirect keeps vcvars' banner out of the build log.
    env.prefix = "cmd /d /s /c \"call \"" + vcvars + "\" >nul && ";
    env.cl_path = probe_out;
    env.detail = "MSVC environment initialized via vcvars64.bat (cl=" +
                 probe_out.substr(0, probe_out.find_first_of("\r\n")) + ")";
    return env;
}

// Wrap a build/test command so it runs inside the MSVC environment. When cl is
// already on PATH the command is returned unchanged (zero overhead, no shell
// nesting). When no toolchain could be verified the command is still run so the
// real error text reaches the receipt.
static std::string WithMsvcEnv(const MsvcEnv& env, const std::string& cmd)
{
    if (env.prefix.empty())
        return cmd;
    return env.prefix + cmd + "\"";
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

    bool Encode(const std::string& text, std::vector<int32_t>& ids) const
    {
        ids.clear();
        if (!ok)
            return false;

        // llama-3 canonical grouping: first split the RAW text into the same
        // groups llama.cpp's split regex defines, then encode each group
        // independently. Merges never cross a group boundary, so the greedy
        // whitespace+letter merges cannot bleed across (the defect: mine
        // produced "GG GGreturn" where llama.cpp produces "GGGG return"). For
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

    bool EncodeCanon(const std::string& text, std::vector<int32_t>& ids, bool gpt2Conv) const
    {
        const std::string norm = SpNormalize(text, marker.c_str());
        std::vector<std::string> syms;
        if (gpt2Conv)
        {
            // Byte-alphabet protocol: in a GPT-2-style vocabulary every input
            // byte enters BPE as its byte-Alphabet representative, never as a
            // whole raw-UTF-8 slice. Slicing by input characters can key real
            // text pieces ('ï¿½' = C3 A9) that decode - correctly, by the
            // byoma alphabet protocol - to a single byte, breaking the encode/
            // decode bijection. Byte-rep seeds BPE so only representatives and
            // their true merges are selectable; only the marker sequence stays
            // grouped (it is the piece 'G', which decodes to byte 0x20).
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

// ============================================================================
// Chat-template-faithful prompt construction.
//
// The GGUF ships tokenizer.chat_template. Rendering the conversation with the
// model's OWN markers (and its own BOS/EOS placement) is what makes the model
// follow the tool protocol; an unwrapped raw prompt produces prose, which is
// exactly what earlier runs showed ("I apologize for the confusion...").
// ============================================================================

struct ChatMarkers
{
    bool has_template = false;
    std::string system_pre, system_suf;
    std::string user_pre = "User: ", user_suf;
    std::string asst_pre = "Assistant: ", asst_suf;
    std::string gen_prompt = "Assistant:";
    bool bos_in_template = false;
    // Per-role: the template appends eos_token instead of a literal suffix.
    // TinyLlama's template terminates EVERY message with eos_token:
    //
    //   {{ '<|user|>\n' + message['content'] + eos_token }}
    //
    // The previous code only recorded this for "assistant" and passed a
    // `dummy` bool for system/user, so those two messages lost their EOS and
    // the rendered prompt no longer matched the template.
    bool system_eos_suffix = false;
    bool user_eos_suffix = false;
    bool eos_in_asst_suffix = false;
};

// Extract the first single-quoted literal at/after pos.
static std::string ExtractQuoted(const std::string& s, size_t pos)
{
    size_t a = s.find('\'', pos);
    if (a == std::string::npos) return "";
    size_t b = s.find('\'', a + 1);
    if (b == std::string::npos) return "";
    return s.substr(a + 1, b - a - 1);
}

// Find the {{ 'pre' + message['content'] + 'suf' }} block for a role.
static bool ExtractRoleFormat(const std::string& tmpl, const char* role, std::string& pre,
                              std::string& suf, bool& suffix_is_eos)
{
    const std::string key = std::string("== '") + role + "'";
    size_t p = tmpl.find(key);
    if (p == std::string::npos)
        return false;
    size_t c = tmpl.find("message['content']", p);
    if (c == std::string::npos)
        return false;
    size_t block = tmpl.rfind("{{", c);
    if (block == std::string::npos)
        return false;
    pre = ExtractQuoted(tmpl, block);
    size_t after = c + std::string("message['content']").size();
    size_t close = tmpl.find("}}", after);
    if (close == std::string::npos)
        return false;
    std::string tail = tmpl.substr(after, close - after);
    suffix_is_eos = tail.find("eos_token") != std::string::npos;
    if (!suffix_is_eos)
        suf = ExtractQuoted(tmpl, after);
    else
        suf.clear();
    return true;
}

static ChatMarkers ParseChatMarkers(const std::string& t)
{
    ChatMarkers m;
    if (t.empty())
        return m;  // plain prompt mode; caller falls back
    m.has_template = true;
    m.bos_in_template = t.find("{{ bos_token }}") != std::string::npos;
    if (!ExtractRoleFormat(t, "system", m.system_pre, m.system_suf, m.system_eos_suffix))
    {
        m.system_pre.clear();
        m.system_suf = "\n";
    }
    if (!ExtractRoleFormat(t, "user", m.user_pre, m.user_suf, m.user_eos_suffix))
    {
        m.user_pre = "User: ";
        m.user_suf = "\n";
    }
    if (!ExtractRoleFormat(t, "assistant", m.asst_pre, m.asst_suf, m.eos_in_asst_suffix))
    {
        m.asst_pre = "Assistant: ";
        m.asst_suf.clear();
        m.eos_in_asst_suffix = true;
    }
    // Generation prompt marker: the literal in the add_generation_prompt branch.
    //
    // The literal is NOT necessarily adjacent to the tag. TinyLlama's template
    // puts a newline between them:
    //
    //   {% if loop.last and add_generation_prompt %}
    //   {{ '<|assistant|>' }}
    //   {% endif %}
    //
    // The previous search for "add_generation_prompt %}{{" required the two tags
    // to touch, so it silently missed and left the generic "Assistant:" default
    // in place. TinyLlama was therefore asked to continue from a marker it had
    // never seen in training and answered with immediate EOS.
    {
        size_t ap = t.find("add_generation_prompt");
        while (ap != std::string::npos)
        {
            // The branch's output expression: the first {{ ... }} AFTER the
            // keyword (not before it), which is what the model actually emits.
            size_t expr_open = t.find("{{", ap);
            if (expr_open == std::string::npos)
                break;
            // Skip the loop own-marker branch: `{% if add_generation_prompt %}`
            // inside the for-body is followed by the message expressions, so
            // require the expression to be within a short distance of the tag.
            size_t expr_close = t.find("}}", expr_open);
            if (expr_close == std::string::npos)
                break;
            std::string body = t.substr(expr_open, expr_close - expr_open);
            // A branch may be empty ("{{ ' ' }}") - take the first quoted
            // literal inside it, which is the generation prefix.
            std::string lit = ExtractQuoted(body, 0);
            if (!lit.empty())
            {
                m.gen_prompt = lit;
                break;
            }
            ap = t.find("add_generation_prompt", ap + 1);
        }
    }
    return m;
}

struct ChatMessage
{
    std::string role;
    std::string content;
};

// Render the message list to TOKENS, template-faithfully: BOS, each message's
// own markers, the assistant EOS token id, and the generation prefix. This is a
// pure function of the message list, so its prefix is stable across turns.
static std::vector<uint32_t> RenderChatTokens(
    const ChatMarkers& m,
    const std::vector<ChatMessage>& msgs,
    bool add_generation_prompt,
    const SpEncoder& enc,
    int32_t bos_id,
    int32_t eos_id)
{
    std::vector<uint32_t> out;
    auto feed_text = [&](const std::string& s)
    {
        std::vector<int32_t> ids;
        enc.Encode(s, ids);
        out.insert(out.end(), ids.begin(), ids.end());
    };

    // BOS placement must match the seeding logic exactly. The model's own
    // template either already emits bos_token (then adding another is a
    // duplicate that shifts every later position) or it does not (then BOS must
    // be prepended, which is what the `fed` seed does). The previous condition
    // was inverted relative to the seed, so the fresh render and the
    // incremental stream diverged at position 0 and the KV cache held a prefix
    // that did not match the prompt.
    if (!m.bos_in_template && bos_id >= 0)
        out.push_back((uint32_t)bos_id);
    for (const auto& msg : msgs)
    {
        if (msg.role == "system")
        {
            feed_text(m.system_pre + msg.content);
            if (m.system_eos_suffix && eos_id >= 0)
                out.push_back((uint32_t)eos_id);   // the template's eos_token
            else
                feed_text(m.system_suf);
        }
        else if (msg.role == "user")
        {
            feed_text(m.user_pre + msg.content);
            if (m.user_eos_suffix && eos_id >= 0)
                out.push_back((uint32_t)eos_id);   // the template's eos_token
            else
                feed_text(m.user_suf);
        }
        else if (msg.role == "assistant")
        {
            feed_text(m.asst_pre + msg.content);
            if (m.eos_in_asst_suffix && eos_id >= 0)
                out.push_back((uint32_t)eos_id);  // the template's eos_token
            else
                feed_text(m.asst_suf);
        }
    }
    if (add_generation_prompt && !m.gen_prompt.empty())
        feed_text(m.gen_prompt);
    return out;
}

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
    // The last line whose FIRST non-whitespace token is "TOOL ". Leading
    // indentation is tolerated (models emit it freely); anything else before
    // the verb still fails closed, so prose can never dispatch.
    size_t lineStart = std::string::npos;
    for (size_t pos = text.rfind("TOOL "); pos != std::string::npos;
         pos = pos ? text.rfind("TOOL ", pos - 1) : std::string::npos)
    {
        const size_t ls = text.rfind('\n', pos);
        const size_t line_begin = (ls == std::string::npos) ? 0 : ls + 1;
        bool only_whitespace = true;
        for (size_t k = line_begin; k < pos; ++k)
        {
            if (!std::isspace((unsigned char)text[k]))
            {
                only_whitespace = false;
                break;
            }
        }
        if (only_whitespace)
        {
            lineStart = line_begin;
            break;
        }
    }
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
    if (t == "TOOL read_motd")
    {
        a.valid = true;
        a.tool = "read_motd";
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

// Logf_ is defined exactly once, in src/deep2/Deep2Log.cpp, and declared by
// src/deep2/Deep2Log.hpp (pulled in above). The definition that used to live
// here was removed: keeping two collides at link time.

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

// ---------------------------------------------------------------------------
// FIRST-TOKEN PARITY (P0).
//
// The question this answers: when TinyLlama answers a tool protocol with an
// immediate EOS, is that the model's own behaviour, or is the engine handing it
// a prompt whose logits are wrong?
//
// A plain continuation prompt is used because it has a single unambiguous
// correct answer that does not depend on prompt wording, so the comparison is
// against arithmetic rather than against a judgement call. The report gives:
//   - the exact token ids fed (so the same sequence can be replayed elsewhere)
//   - the top-10 first-token predictions with their logit values
//   - the RANK of EOS among all logits (the decisive number)
//   - the greedy continuation for N tokens
//
// Run it twice, once per backend, and diff the receipts. Identical output means
// the GPU kernels reproduce the CPU reference; differing output means the
// kernels are wrong and no conclusion about the model is valid yet.
// ---------------------------------------------------------------------------
static int PlainPromptRun(const Args& args)
{
    Logf_("[plain] loading %s\n", args.model.c_str());
    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok)
    {
        Logf_("INGEST_FAIL: %s\n", rep.error.c_str());
        return 2;
    }

    // SpEncoder is inert until Build() copies the vocabulary and merge ranks
    // out of the tokenizer. A default-constructed encoder's Encode() silently
    // returns zero tokens, which would render the prompt as [BOS, EOS] and make
    // the model answer an empty prompt - a defect that looks exactly like "the
    // model refuses" from the outside.
    SpEncoder enc;
    enc.Build(GetTokenizer());
    if (!enc.ok)
    {
        Logf_("PLAIN_FAIL: tokenizer build produced an empty vocabulary\n");
        return 2;
    }
    const ChatMarkers markers = ParseChatMarkers(GetTokenizer().chat_template);

    // The prompt is rendered with the model's OWN template, because that is the
    // sequence the model was trained on. A bare string would answer a different
    // question than the one being asked.
    std::vector<ChatMessage> msgs;
    msgs.push_back({"user", args.plain_prompt});
    const std::vector<uint32_t> ids =
        RenderChatTokens(markers, msgs, true, enc, GetTokenizer().bos_id, GetTokenizer().eos_id);

    Logf_("[plain] path=%s eos_id=%d bos_id=%d\n", args.cpu ? "cpu" : "gpu-first",
          GetTokenizer().eos_id, GetTokenizer().bos_id);
    {
        std::string s;
        for (size_t i = 0; i < ids.size(); ++i)
        {
            s += std::to_string(ids[i]);
            if (i + 1 < ids.size()) s += ",";
        }
        Logf_("[plain] TOKEN_IDS=%s\n", s.c_str());
        std::string t;
        for (uint32_t id : ids) t += enc.Piece(id);
        Logf_("[plain] DECODED_PROMPT='%s'\n", EscapeForLog(t).c_str());
    }

    Executor ex;
    ex.SetForceCpu(args.cpu);
    if (!ex.Bind(rep))
    {
        Logf_("BIND_FAIL: %s\n", ex.Stats().error.c_str());
        return 3;
    }
    Logf_("[plain] bound: ops=%zu\n", ex.Stats().ops_total);

    const auto t_pre = std::chrono::steady_clock::now();
    for (size_t pos = 0; pos < ids.size(); ++pos)
    {
        if (!ex.ExecuteToken(ids[pos], pos))
        {
            Logf_("EXEC_FAIL prefill pos=%zu err=%s\n", pos, ex.LastError().c_str());
            return 3;
        }
    }
    const double pre_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t_pre).count();
    Logf_("[plain] prefill %zu tokens in %.1f ms (%.3f tok/s) gpu=%llu cpu=%llu\n",
          ids.size(), pre_ms, ids.size() / (pre_ms / 1000.0),
          (unsigned long long)ex.Stats().gpu_calls, (unsigned long long)ex.Stats().cpu_calls);

    // ---- First generated token: full ranking, EOS rank called out ----------
    const std::vector<float>& lg0 = ex.Logits();
    if (lg0.empty())
    {
        Logf_("PLAIN_FAIL: no logits after prefill\n");
        return 4;
    }

    // Rank of every token by logit, descending. EOS rank is 1-based so "rank 1"
    // reads as "the single most likely token", which is the intuitive meaning.
    std::vector<std::pair<float, int32_t>> all;
    all.reserve(lg0.size());
    for (uint32_t i = 0; i < lg0.size(); ++i)
        all.emplace_back(lg0[i], (int32_t)i);
    std::sort(all.begin(), all.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });

    int eos_rank = -1;
    float eos_logit = 0.0f;
    for (size_t r = 0; r < all.size(); ++r)
    {
        if (all[r].second == GetTokenizer().eos_id)
        {
            eos_rank = (int)(r + 1);
            eos_logit = all[r].first;
            break;
        }
    }

    size_t nonfinite = 0;
    float mn = all.back().first, mx = all.front().first;
    for (float v : lg0)
        if (!std::isfinite(v)) ++nonfinite;

    Logf_("[plain] vocab=%zu nonfinite=%zu logit_range=[%.4f, %.4f]\n",
          lg0.size(), nonfinite, mn, mx);
    Logf_("[plain] EOS_ID=%d EOS_RANK=%d/%zu EOS_LOGIT=%.6f (top logit=%.6f, gap=%.6f)\n",
          GetTokenizer().eos_id, eos_rank, lg0.size(), eos_logit, all.front().first,
          all.front().first - eos_logit);
    Logf_("[plain] TOP10:");
    for (size_t k = 0; k < 10 && k < all.size(); ++k)
        Logf_(" %d(%s)=%.4f", all[k].second, EscapeForLog(enc.Piece((uint32_t)all[k].second)).c_str(),
              all[k].first);
    Logf_("\n");

    // Machine-readable receipt: the two backends' outputs are diffed on this
    // line, so it must be stable and complete enough to stand alone.
    {
        std::string top;
        for (size_t k = 0; k < 10 && k < all.size(); ++k)
        {
            if (k) top += ",";
            top += std::to_string(all[k].second);
        }
        Logf_("PLAIN_FIRST_TOKEN argmax=%d eos_rank=%d vocab=%zu nonfinite=%zu top10=%s gpu=%llu cpu=%llu\n",
              all.front().second, eos_rank, lg0.size(), nonfinite, top.c_str(),
              (unsigned long long)ex.Stats().gpu_calls, (unsigned long long)ex.Stats().cpu_calls);

        // Full logits dump for byte-level diffing against the other backend.
        std::string path = args.workdir + "/plain_logits." +
                           std::string(args.cpu ? "cpu" : "gpu") + ".f32";
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(lg0.data()),
                  (std::streamsize)(lg0.size() * sizeof(float)));
        Logf_("[plain] logits dumped: %s\n", path.c_str());
    }

    // ---- Greedy continuation ----------------------------------------------
    std::vector<uint32_t> fed(ids.begin(), ids.end());
    std::string gen;
    const auto t_gen = std::chrono::steady_clock::now();
    int produced = 0;
    for (int t = 0; t < args.plain_tokens; ++t)
    {
        if (ex.NonFiniteLogits() != 0)
        {
            Logf_("[plain] STOP: non-finite logits (%zu)\n", ex.NonFiniteLogits());
            break;
        }
            const std::vector<float>& lg = ex.Logits();
            uint32_t next = 0;
            // Sampling with configurable temperature; temperature <= 0 means greedy
            if (args.temperature <= 0.0f)
            {
                next = 0;
                for (uint32_t i = 1; i < lg.size(); ++i)
                    if (lg[i] > lg[next]) next = i;
            }
            else
            {
                // Temperature-scaled softmax sampling
                const float inv_t = 1.0f / args.temperature;
                float max_logit = lg[0];
                for (uint32_t i = 1; i < lg.size(); ++i)
                    if (lg[i] > max_logit) max_logit = lg[i];
                float sum = 0.0f;
                static thread_local std::vector<float> probs;
                probs.resize(lg.size());
                for (uint32_t i = 0; i < lg.size(); ++i)
                {
                    probs[i] = std::exp((lg[i] - max_logit) * inv_t);
                    sum += probs[i];
                }
                float r = static_cast<float>(rand()) / static_cast<float>(RAND_MAX) * sum;
                float acc = 0.0f;
                next = lg.size() - 1;
                for (uint32_t i = 0; i < lg.size(); ++i)
                {
                    acc += probs[i];
                    if (r <= acc) { next = i; break; }
                }
            }

            // Token integrity diagnostic
            if (t < 5 || t % 10 == 0)
            {
                float maxLogit = lg[next];
                float minLogit = lg[next];
                bool finite = true;
                for (float v : lg)
                {
                    if (v > maxLogit) maxLogit = v;
                    if (v < minLogit) minLogit = v;
                    if (!std::isfinite(v)) finite = false;
                }
                Logf_("[TOKEN_DIAG] t=%d selected=%d argmax=%d vocab=%zu finite=%d "
                      "sel_logit=%.9g max=%.9g min=%.9g\n",
                      t, next, next, lg.size(), finite ? 1 : 0,
                      lg[next], maxLogit, minLogit);
            }

        // Token integrity diagnostic
        if (t < 5 || t % 10 == 0)
        {
            float maxLogit = lg[next];
            float minLogit = lg[next];
            bool finite = true;
            for (float v : lg)
            {
                if (v > maxLogit) maxLogit = v;
                if (v < minLogit) minLogit = v;
                if (!std::isfinite(v)) finite = false;
            }
            Logf_("[TOKEN_DIAG] t=%d selected=%d argmax=%d vocab=%zu finite=%d "
                  "sel_logit=%.9g max=%.9g min=%.9g\n",
                  t, next, next, lg.size(), finite ? 1 : 0,
                  lg[next], maxLogit, minLogit);
        }

        if (next == (uint32_t)GetTokenizer().eos_id)
        {
            Logf_("[plain] STOP: EOS after %d generated tokens\n", produced);
            break;
        }
        if (!ex.ExecuteToken(next, fed.size()))
        {
            Logf_("[plain] EXEC_FAIL decode pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
            break;
        }
        fed.push_back(next);
        gen += enc.Piece(next);
        ++produced;
    }
    const double gen_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t_gen).count();
    Logf_("[plain] greedy %d tokens in %.1f ms (%.3f tok/s)\n", produced, gen_ms,
          produced > 0 && gen_ms > 0 ? produced / (gen_ms / 1000.0) : 0.0);
    Logf_("[plain] CONTINUATION='%s'\n", EscapeForLog(gen).c_str());
    Logf_("PLAIN_CONTINUATION %s '%s'\n", args.cpu ? "cpu" : "gpu", EscapeForLog(gen).c_str());

    // Verdict: a plain continuation prompt is NOT a model-capacity question
    // until the logits are known good. EOS at rank 1 with a correct greedy
    // continuation is model behaviour; EOS at rank 1 on a prompt whose other
    // logits are also wrong is arithmetic.
    const bool logits_healthy = (nonfinite == 0) && produced > 0;
    Logf_("PLAIN_VERDICT %s eos_rank=%d generated=%d nonfinite=%zu\n",
          logits_healthy ? "LOGITS_HEALTHY" : "SUSPECT", eos_rank, produced, nonfinite);
    return logits_healthy ? 0 : 1;
}

// ---------------------------------------------------------------------------
// PARITY CERTIFICATION (P0).
//
// Compares two raw float32 logit dumps produced by --plain (one per backend)
// and emits the verdict. The numbers that matter:
//
//   cosine similarity  - direction agreement over the whole vocabulary. This is
//                        the primary signal: it is insensitive to any global
//                        scale or offset and degrades only when the
//                        distributions genuinely disagree.
//   max abs error      - the worst single-token disagreement, which is what a
//                        cos-difference hides.
//   top-10 agreement   - whether the ranked candidates are the same SET. Greedy
//                        decoding only ever consumes the argmax, so argmax
//                        agreement is necessary but not sufficient.
//   argmax agreement   - whether the two backends would emit the same token.
//
// A quantized GPU kernel and the float CPU reference are NOT expected to be
// bit-identical: Q8_K activations, fp16 KV storage and a different summation
// order all move the low-order bits. The gate is therefore thresholded, and the
// thresholds are printed next to the measurements so a reviewer can see what
// was required rather than trusting a bare PASS.
// ---------------------------------------------------------------------------
static int DiffRun(const Args& args)
{
    auto load = [](const std::string& path, std::vector<float>& out) -> bool {
        std::ifstream f(path, std::ios::binary);
        if (!f) return false;
        out.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (out.size() % sizeof(float) != 0)
            out.resize((out.size() / sizeof(float)) * sizeof(float) / sizeof(float) *
                       sizeof(float) / sizeof(float) * sizeof(float));  // trim to whole floats
        const size_t n = out.size() / sizeof(float);
        std::vector<float> v(n);
        std::memcpy(v.data(), out.data(), n * sizeof(float));
        out = std::move(v);
        return true;
    };

    std::vector<float> A, B;
    if (!load(args.diff_a, A))
    {
        Logf_("DIFF_FAIL: cannot read %s\n", args.diff_a.c_str());
        return 2;
    }
    if (!load(args.diff_b, B))
    {
        Logf_("DIFF_FAIL: cannot read %s\n", args.diff_b.c_str());
        return 2;
    }
    if (A.size() != B.size() || A.empty())
    {
        Logf_("DIFF_FAIL: size mismatch a=%zu b=%zu\n", A.size(), B.size());
        return 2;
    }

    const size_t n = A.size();
    double dot = 0.0, na = 0.0, nb = 0.0, max_abs = 0.0;
    size_t nonfinite = 0;
    for (size_t i = 0; i < n; ++i)
    {
        if (!std::isfinite(A[i]) || !std::isfinite(B[i])) { ++nonfinite; continue; }
        dot += (double)A[i] * (double)B[i];
        na += (double)A[i] * (double)A[i];
        nb += (double)B[i] * (double)B[i];
        const double d = std::fabs((double)A[i] - (double)B[i]);
        if (d > max_abs) max_abs = d;
    }
    const double cosine = (na > 0.0 && nb > 0.0) ? dot / (std::sqrt(na) * std::sqrt(nb)) : 0.0;

    // Argmax and top-10 per side, compared as an unordered SET.
    auto ranked = [&](const std::vector<float>& v, size_t k) {
        std::vector<std::pair<float, int32_t>> all(v.size());
        for (size_t i = 0; i < v.size(); ++i) all[i] = {v[i], (int32_t)i};
        const size_t kk = std::min(k, all.size());
        std::partial_sort(all.begin(), all.begin() + kk, all.end(),
                          [](const auto& a, const auto& b) { return a.first > b.first; });
        return all;
    };
    const auto ra = ranked(A, 10), rb = ranked(B, 10);
    const uint32_t am_a = (uint32_t)ra[0].second, am_b = (uint32_t)rb[0].second;

    std::set<int32_t> setA, setB;
    for (const auto& p : ra) setA.insert(p.second);
    for (const auto& p : rb) setB.insert(p.second);
    size_t overlap = 0;
    for (int32_t id : setA) if (setB.count(id)) ++overlap;
    // Order-preserving agreement is stricter than set overlap; both are
    // reported because near-tied logits legitimately reorder.
    size_t same_order = 0;
    for (size_t i = 0; i < ra.size() && i < rb.size(); ++i)
        if (ra[i].second == rb[i].second) ++same_order;

    Logf_("[diff] a=%s (%zu logits)\n", args.diff_a.c_str(), n);
    Logf_("[diff] b=%s\n", args.diff_b.c_str());
    Logf_("[diff] cosine_similarity = %.9f\n", cosine);
    Logf_("[diff] max_abs_logit_err = %.6f\n", max_abs);
    Logf_("[diff] nonfinite          = %zu\n", nonfinite);
    Logf_("[diff] argmax             = %u vs %u  %s\n", am_a, am_b,
          am_a == am_b ? "AGREE" : "DISAGREE");
    Logf_("[diff] top10 set overlap  = %zu/10 ; same order = %zu/10\n", overlap, same_order);
    Logf_("[diff] top10 a =");
    for (const auto& p : ra) Logf_(" %d(%.4f)", p.second, p.first);
    Logf_("\n[diff] top10 b =");
    for (const auto& p : rb) Logf_(" %d(%.4f)", p.second, p.first);
    Logf_("\n");

    // Thresholds are printed, not hidden: a reviewer must be able to see the
    // bar that was applied.
    constexpr double kMinCosine = 0.9995;   // quantized-vs-reference expectation
    constexpr double kMaxAbsErr = 2.0;      // one logit may differ by this much
    const bool cosine_ok = cosine >= kMinCosine;
    const bool abs_ok = max_abs <= kMaxAbsErr;
    const bool finite_ok = nonfinite == 0;
    const bool argmax_ok = am_a == am_b;
    const bool top_ok = same_order >= 8;    // near-ties may reorder the tail
    const bool pass = cosine_ok && abs_ok && finite_ok && argmax_ok && top_ok;

    Logf_("DIFF_GATES cosine>=%.4f:%s max_abs<=%.1f:%s nonfinite==0:%s argmax:%s top10_order>=8:%s\n",
          kMinCosine, cosine_ok ? "PASS" : "FAIL",
          kMaxAbsErr, abs_ok ? "PASS" : "FAIL",
          finite_ok ? "PASS" : "FAIL",
          argmax_ok ? "PASS" : "FAIL",
          top_ok ? "PASS" : "FAIL");
    Logf_("PARITY_VERDICT %s (cosine=%.9f max_abs=%.6f argmax=%s top10=%zu/10)\n",
          pass ? "PASS" : "FAIL", cosine, max_abs, argmax_ok ? "agree" : "disagree", same_order);
    return pass ? 0 : 1;
}

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

// ============================================================================
// SNAP: event-driven stop control + bounded retry state (H02).
//
// Decoding halts the instant a complete tool command, EOS, a limit, or
// cancellation is observed. Hard deadlines are a watchDOG only, never the
// normal stopping mechanism. Every verdict is host-decided.
// ============================================================================

namespace deep2::agent
{

enum class StopReason : uint8_t
{
    None,
    ToolReady,
    Finish,
    EOS,
    Cancelled,
    Invalid,
    TokenLimit,
    NonFinite
};

const char* StopReasonName(StopReason r)
{
    switch (r)
    {
        case StopReason::None:       return "NONE";
        case StopReason::ToolReady:  return "TOOL_READY";
        case StopReason::Finish:     return "FINISH";
        case StopReason::EOS:        return "EOS";
        case StopReason::Cancelled:  return "CANCELLED";
        case StopReason::Invalid:    return "INVALID";
        case StopReason::TokenLimit: return "TOKEN_LIMIT";
        case StopReason::NonFinite:  return "NON_FINITE";
    }
    return "UNKNOWN";
}

struct StopController
{
    std::atomic<bool> cancel{false};
    uint32_t generated = 0;
    uint32_t max_tokens = 300;
    StopReason reason = StopReason::None;

    StopReason inspect(uint32_t token, uint32_t eos_token, bool complete_valid_tool,
                       bool complete_finish, bool unrecoverable_invalid)
    {
        if (cancel.load(std::memory_order_relaxed))
            return reason = StopReason::Cancelled;
        ++generated;
        if (token == eos_token)
            return reason = StopReason::EOS;
        if (complete_finish)
            return reason = StopReason::Finish;
        if (complete_valid_tool)
            return reason = StopReason::ToolReady;
        if (unrecoverable_invalid)
            return reason = StopReason::Invalid;
        if (generated >= max_tokens)
            return reason = StopReason::TokenLimit;
        return StopReason::None;
    }

    void reset()
    {
        generated = 0;
        reason = StopReason::None;
    }
};

}  // namespace deep2::agent

// Process-wide cancellation: set by the console handler on Ctrl+C / close, and
// polled at every token and every prefill step (the safe dispatch boundaries).
static std::atomic<bool> g_cancel_flag{false};

#ifdef _WIN32
static BOOL WINAPI Deep2ConsoleCtrlHandler(DWORD ctrl_type)
{
    switch (ctrl_type)
    {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
            g_cancel_flag.store(true, std::memory_order_relaxed);
            return TRUE;
        default:
            return FALSE;
    }
}
#endif

// ---- H02 ledger / budget / transaction state ---------------------------------
struct ToolCallReceipt
{
    int step = 0;
    std::string tool, target, raw_command, observation;
    int observation_bytes = 0;
    int bash_exit_code = 0;
    bool tool_valid = false;
    std::chrono::steady_clock::time_point timestamp;
};

struct PatchTransaction
{
    std::string file_path, before_content, after_content, last_error;
    bool committed = false;
    bool rolled_back = false;
};

struct RetryState
{
    int attempt = 0;
    int max_attempts = 3;
    int tokens_used = 0;
    int max_tokens = 8192;
    std::chrono::steady_clock::time_point start_time;
    int max_wall_time_sec = 300;
    int identical_failures = 0;
    std::string last_failure_signature;
    bool stalled = false;
    // Number of VALID tool dispatches the model itself requested. This is the
    // difference between "the file happens to contain a fix" and "the agent
    // repaired the file": only the latter can be attributed to the model.
    uint32_t tool_calls = 0;
    uint32_t rejected_tool_calls = 0;

    bool can_retry() const
    {
        if (attempt >= max_attempts) return false;
        if (tokens_used >= max_tokens) return false;
        if (stalled) return false;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - start_time).count();
        return elapsed < max_wall_time_sec;
    }

    void record_failure(const std::string& signature)
    {
        if (signature == last_failure_signature)
        {
            if (++identical_failures >= 2) stalled = true;
        }
        else
        {
            identical_failures = 1;
            last_failure_signature = signature;
        }
    }

    void record_tool_call(const ToolCallReceipt& r)
    {
        if (r.tool_valid)
            ++tool_calls;
        else
            ++rejected_tool_calls;
        tokens_used += r.observation_bytes / 4;
    }
};

static std::string SHA256_Hash(const std::string& data)
{
#ifdef _WIN32
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string hash_str;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return "";
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    if (!CryptHashData(hHash, (const BYTE*)data.data(), (DWORD)data.size(), 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }
    DWORD hash_len = 32;
    BYTE hash[32];
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hash_len, 0))
    {
        char hex[65];
        for (DWORD i = 0; i < hash_len; ++i)
            sprintf_s(hex + i * 2, 3, "%02x", hash[i]);
        hash_str = std::string(hex, 64);
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return hash_str;
#else
    return std::to_string(std::hash<std::string>{}(data));
#endif
}

// Snapshot/apply/verify/commit-or-rollback for source patches.
class PatchManager
{
    std::vector<PatchTransaction> transactions_;
    std::string workdir_;

public:
    explicit PatchManager(const std::string& workdir) : workdir_(workdir) {}

    bool snapshot(const std::string& rel_path)
    {
        std::string content = ReadFile(workdir_ + "/" + rel_path);
        if (content.empty()) return false;
        PatchTransaction tx;
        tx.file_path = rel_path;
        tx.before_content = content;
        transactions_.push_back(tx);
        return true;
    }

    bool apply(const std::string& rel_path, const std::string& new_content)
    {
        if (transactions_.empty()) return false;
        auto& tx = transactions_.back();
        if (tx.file_path != rel_path) return false;
        if (!WriteFile(workdir_ + "/" + rel_path, new_content)) return false;
        tx.after_content = new_content;
        return true;
    }

    bool verify(const std::string& build_cmd, const std::string& run_cmd,
                const std::string& expected_output, const std::string& workdir)
    {
        if (transactions_.empty()) return false;
        auto& tx = transactions_.back();
        int code = 0;
        std::string out = RunCmd("cd /d \"" + workdir + "\" && " + build_cmd + " 2>&1", &code);
        if (code != 0)
        {
            tx.last_error = "compile failed (exit " + std::to_string(code) + "): " + out;
            return false;
        }
        out = RunCmd("cd /d \"" + workdir + "\" && " + run_cmd + " 2>&1", &code);
        if (code != 0 || out.find(expected_output) == std::string::npos)
        {
            tx.last_error = "test failed (exit " + std::to_string(code) + "): " + out;
            return false;
        }
        tx.committed = true;
        return true;
    }

    bool rollback(const std::string& rel_path)
    {
        if (transactions_.empty()) return false;
        auto& tx = transactions_.back();
        if (tx.file_path != rel_path) return false;
        const bool ok = WriteFile(workdir_ + "/" + rel_path, tx.before_content);
        tx.rolled_back = ok;
        return ok;
    }

    void commit(const std::string& rel_path)
    {
        if (!transactions_.empty() && transactions_.back().file_path == rel_path)
            transactions_.back().committed = true;
    }

    const PatchTransaction* last() const
    {
        return transactions_.empty() ? nullptr : &transactions_.back();
    }
};

// Append-only JSONL ledger of every host/model transition.
class ExecutionLedger
{
    std::ofstream ledger_;
    int entry_count_ = 0;

    static std::string escape_json(const std::string& s)
    {
        std::string out;
        out.reserve(s.size() + 16);
        for (char c : s)
        {
            switch (c)
            {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out += c;      break;
            }
        }
        return out;
    }

    static long long now_ms()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void log_event(const std::string& type, const std::string& payload)
    {
        if (!ledger_.is_open()) return;
        ledger_ << "{\"type\":\"" << type << "\",\"entry\":" << entry_count_++
                << ",\"payload\":" << payload << "}\n";
        ledger_.flush();
    }

public:
    explicit ExecutionLedger(const std::string& workdir)
        : ledger_(workdir + "/execution_ledger.jsonl", std::ios::app)
    {
        if (ledger_.is_open())
            log_event("LEDGER_START", "{}");
    }

    ~ExecutionLedger()
    {
        if (ledger_.is_open())
        {
            log_event("LEDGER_END", "{\"total_entries\":" + std::to_string(entry_count_) + "}");
            ledger_.close();
        }
    }

    void log_tool_call(int step, const std::string& tool, const std::string& target,
                       const std::string& observation, int exit_code, bool valid)
    {
        log_event("TOOL_CALL", "{\"step\":" + std::to_string(step) +
                   ",\"tool\":\"" + escape_json(tool) +
                   "\",\"target\":\"" + escape_json(target) +
                   "\",\"observation_bytes\":" + std::to_string(observation.size()) +
                   ",\"exit_code\":" + std::to_string(exit_code) +
                   ",\"valid\":" + (valid ? "true" : "false") +
                   ",\"timestamp\":" + std::to_string(now_ms()) + "}");
    }

    void log_patch(int step, const std::string& file, const std::string& before_hash,
                   const std::string& after_hash, bool committed, bool rolled_back)
    {
        log_event("PATCH", "{\"step\":" + std::to_string(step) +
                   ",\"file\":\"" + escape_json(file) +
                   "\",\"before_hash\":\"" + escape_json(before_hash) +
                   "\",\"after_hash\":\"" + escape_json(after_hash) +
                   "\",\"committed\":" + (committed ? "true" : "false") +
                   ",\"rolled_back\":" + (rolled_back ? "true" : "false") +
                   ",\"timestamp\":" + std::to_string(now_ms()) + "}");
    }

    void log_retry(int attempt, const std::string& reason, bool can_continue)
    {
        log_event("RETRY", "{\"attempt\":" + std::to_string(attempt) +
                   ",\"reason\":\"" + escape_json(reason) +
                   "\",\"can_continue\":" + (can_continue ? "true" : "false") +
                   ",\"timestamp\":" + std::to_string(now_ms()) + "}");
    }

    void log_verification(bool passed, const std::string& details)
    {
        log_event("VERIFICATION", std::string("{\"passed\":") + (passed ? "true" : "false") +
                   ",\"details\":\"" + escape_json(details) +
                   "\",\"timestamp\":" + std::to_string(now_ms()) + "}");
    }
};

// Per-phase latency profile with real token counts.
struct PerfProfiler
{
    struct PhaseTiming
    {
        std::string phase;
        double ms = 0.0;
        size_t tokens = 0;
    };

    std::vector<PhaseTiming> timings;
    std::chrono::steady_clock::time_point phase_start;
    std::string current_phase;
    size_t phase_tokens = 0;

    void start_phase(const std::string& phase, size_t tokens = 0)
    {
        if (!current_phase.empty()) end_phase();
        current_phase = phase;
        phase_tokens = tokens;
        phase_start = std::chrono::steady_clock::now();
    }

    void add_tokens(size_t n) { phase_tokens += n; }

    void end_phase()
    {
        if (current_phase.empty()) return;
        const double elapsed = (double)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - phase_start).count();
        timings.push_back({current_phase, elapsed, phase_tokens});
        current_phase.clear();
        phase_tokens = 0;
    }

    void report() const
    {
        double total = 0;
        Logf_("\n=== PERFORMANCE PROFILE ===\n");
        for (const auto& t : timings)
        {
            Logf_("  %-14s %9.0f ms  tokens=%6zu  tok/s=%.3f\n", t.phase.c_str(), t.ms, t.tokens,
                  (t.tokens > 0 && t.ms > 0) ? (double)t.tokens / (t.ms / 1000.0) : 0.0);
            total += t.ms;
        }
        Logf_("  %-14s %9.0f ms  TOTAL\n", "TOTAL", total);
    }
};

int main(int argc, char* argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    const Args args = Parse(argc, argv);
    if (args.model.empty() && !args.motd_selftest)
    {
        std::printf("usage: deep2_agentic_loop.exe --model <gguf> [--task f] [--workdir D] "
                    "[--max-steps N] [--max-new N] [--cpu] [--toktest]\n");
        return 1;
    }
    if (args.motd_selftest)
    {
        const Action motdAction = ParseAction("TOOL read_motd\n");
        const Action writeAction = ParseAction("TOOL write target.cpp @@content@@\n");
        bool ok = motdAction.valid && motdAction.tool == "read_motd" &&
                  writeAction.valid && writeAction.tool == "write";
        rawrxd::agentic::MotdAuthorization auth(args.workdir);
        const std::string session = "deep2-motd-selftest";
        std::string reason, contents, digest, error;
        ok = ok && auth.BeginTurn(session, 1);
        if (ok && auth.AuthorizeTool(writeAction.tool, session, 1, reason)) ok = false;
        ok = ok && auth.AuthorizeTool(motdAction.tool, session, 1, reason);
        ok = ok && auth.ReadMotd(session, 1, contents, digest, error);
        ok = ok && !digest.empty() && contents.find("PassiveRoleNotRoleplay") != std::string::npos;
        ok = ok && auth.AuthorizeTool(writeAction.tool, session, 1, reason);
        ok = ok && auth.BeginTurn(session, 2);
        ok = ok && !auth.AuthorizeTool(writeAction.tool, session, 2, reason);
        Logf_("MOTD_LOOP_SELFTEST %s\n", ok ? "PASS" : "FAIL");
        Logf_("POLICY_SHA256 %s\n", digest.c_str());
        if (!error.empty()) Logf_("MOTD_ERROR %s\n", error.c_str());
        return ok ? 0 : 1;
    }
    if (args.toktest)
        return TokTest(args);
    if (args.parity)
        return ParityRun(args);
    // FIRST-TOKEN PARITY (P0): plain prompt, no tool protocol, EOS rank
    // reported explicitly so "the model refuses" can be told apart from "the
    // logits are wrong". Checked before the parity harness needs an ids file.
    if (!args.plain_prompt.empty())
        return PlainPromptRun(args);

    // ============================================================================
    // CLOUD PROVIDER MODE (--provider kilo | openrouter)
    // Routes inference through a free cloud model instead of local Deep2.
    // Used for autonomous self-development while Deep2 is being repaired.
    // ============================================================================
    if (args.provider == "kilo" || args.provider == "openrouter")
    {
        // Resolve API key from env if not provided via --api-key
        std::string api_key = args.api_key;
        if (api_key.empty())
        {
            if (args.provider == "kilo")
            {
                const char* ek = std::getenv("KILO_API_KEY");
                if (ek) api_key = ek;
            }
            else if (args.provider == "openrouter")
            {
                const char* ek = std::getenv("OPENROUTER_API_KEY");
                if (ek) api_key = ek;
            }
        }

        ModelConfig cfg;
        cfg.backend = (args.provider == "kilo") ? ModelBackend::KILO_GATEWAY : ModelBackend::OPENROUTER;
        cfg.model_id = args.model.empty() ? (args.provider == "kilo" ? "kilo-auto/free" : "openrouter/free")
                                          : args.model;
        cfg.parameters["max_tokens"] = std::to_string(args.max_new);
        cfg.parameters["temperature"] = std::to_string(args.temperature);
        if (args.provider == "openrouter")
        {
            cfg.parameters["http_referer"] = "https://rawrxd.local/self-repair";
            cfg.parameters["x_title"] = "RawrXD Self-Repair Agent";
        }

        CloudApiClient cloud;
        std::string prompt = args.task.empty() ? "You are a helpful coding assistant." : args.task;

        Logf_("[cloud] provider=%s model=%s temperature=%.2f max_tokens=%d task_length=%zu\n",
              args.provider.c_str(), cfg.model_id.c_str(), args.temperature, args.max_new,
              prompt.size());
        Logf_("[cloud] task: %s\n", prompt.c_str());

        std::string result = cloud.generate(prompt, cfg);
        if (result.empty())
        {
            Logf_("[cloud] ERROR: cloud generation failed\n");
            return 1;
        }

        Logf_("[cloud] response:\n%s\n", result.c_str());
        Logf_("[cloud] COMPLETE\n");
        return 0;
    }

    // Each invocation handles one user-originated task. Continuation model
    // turns share this authorization, while the next process/task starts fresh.
    rawrxd::agentic::MotdAuthorization motdAuthorization(args.workdir);
    const auto motdNonce = std::chrono::steady_clock::now().time_since_epoch().count();
#ifdef _WIN32
    const std::string motdSession = "deep2-agent-" + std::to_string(GetCurrentProcessId()) + "-" +
                                    std::to_string(motdNonce);
#else
    const std::string motdSession = "deep2-agent-" + std::to_string(motdNonce);
#endif
    constexpr uint64_t motdTurn = 1;
    if (!motdAuthorization.BeginTurn(motdSession, motdTurn))
    {
        Logf_("MOTD_STATUS BLOCKED: could not initialize turn authorization\n");
        return 3;
    }
    Logf_("MOTD_STATUS TURN_START session=%s turn=%llu\n", motdSession.c_str(),
          static_cast<unsigned long long>(motdTurn));

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
    Logf_("[stage] ingest done in %.1f ms: arch=%s blocks=%llu vocab=%zu bos=%d eos=%d\n",
          std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_load0).count(),
          rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count, enc.tokens.size(),
          (int)GetTokenizer().bos_id, (int)GetTokenizer().eos_id);
    if (!GetTokenizer().chat_template.empty())
        Logf_("[stage] model ships a chat template (%zu bytes):\n%s\n",
              GetTokenizer().chat_template.size(), GetTokenizer().chat_template.c_str());
    else
        Logf_("[stage] model ships NO chat template; using plain prompt\n");

    // Tokenizer self-check: decode(encode(x)) == x on the prompt. A wrong
    // tokenizer silently corrupts every position, and no amount of correct
    // inference can compensate for it.
    bool rt_ok = false;
    {
        std::vector<int32_t> rt;
        enc.Encode("TOOL read_motd\nTOOL read calc.cpp\nint add(int a, int b) { return a + b; }", rt);
        std::string back;
        for (int32_t id : rt)
            back += enc.Piece((uint32_t)id);
        rt_ok = back.find("TOOL read_motd") != std::string::npos &&
                back.find("TOOL read calc.cpp") != std::string::npos;
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

    // ============================================================================
    // SNAP Process Guard: lifecycle integration (H02/H03)
    // ============================================================================
    // 1. Create Job Object for automatic child cleanup (kill-on-job-close)
    snap::process::JobObject agent_job;
    if (!agent_job.create(L"RawrXD_Agent_Job"))
    {
        Logf_("[snap] WARNING: Failed to create Job Object, child cleanup disabled\n");
    }
    else
    {
        if (agent_job.assign_self())
        {
            Logf_("[snap] Job Object created and self-assigned; children will inherit\n");
        }
        else
        {
            Logf_("[snap] WARNING: Failed to assign self to Job Object\n");
        }
    }

    // 2. Preflight scan for stale Deep2 agent processes
    std::wstring agent_exe_w = std::wstring(args.model.begin(), args.model.end()); // will be replaced with actual executable path
    // Use the actual agent executable path
    char self_exe[MAX_PATH];
    GetModuleFileNameA(nullptr, self_exe, MAX_PATH);
    std::string agent_exe = self_exe;
    std::wstring agent_exe_wide(agent_exe.begin(), agent_exe.end());

    snap::process::StaleProcessScanner::Config scan_cfg;
    scan_cfg.target_exe = agent_exe_wide;
    scan_cfg.ram_warning_mb = 2048;  // 2GB warning threshold
    scan_cfg.check_job_membership = true;
    scan_cfg.emit_esp_events = true;

    snap::process::StaleProcessScanner scanner(scan_cfg);
    auto preflight_report = scanner.scan();

    if (preflight_report.contention_detected)
    {
        Logf_("[snap] Preflight: CONTENTION DETECTED - %zu candidates, %zu warnings\n",
              preflight_report.candidates.size(), preflight_report.warnings.size());
        for (const auto& w : preflight_report.warnings)
        {
            // Convert wstring to string for logging
            std::string w_str(w.begin(), w.end());
            Logf_("[snap]   %s\n", w_str.c_str());
        }

        // Attempt authorized recovery of verified stale processes
        snap::process::ProcessVerifier verifier(snap::process::VerificationPolicy{
            .require_accessible = true,
            .require_path_match = true,
            .allow_self = false,
            .expected_exe = agent_exe_wide
        });

        for (const auto& candidate : preflight_report.candidates)
        {
            if (candidate.is_self) continue;

            auto verify_result = verifier.verify(candidate.pid);
            if (verify_result.verified)
            {
                Logf_("[snap] Authorized recovery: terminating verified stale PID %u\n", candidate.pid);
                snap::process::ProcessTerminator terminator(snap::process::TerminationPolicy{
                    .require_confirmation = false,  // pre-authorized by host policy
                    .use_graceful_first = true,
                    .graceful_timeout_ms = 3000,
                    .allow_self = false
                });
                auto term_result = terminator.terminate(candidate.pid, true);
                if (term_result.success)
                {
                    Logf_("[snap] Successfully terminated stale PID %u\n", candidate.pid);
                }
                else
                {
                    Logf_("[snap] FAILED to terminate stale PID %u: %S\n", candidate.pid, term_result.reason.c_str());
                }
            }
        }
    }
    else
    {
        Logf_("[snap] Preflight clean: no contention detected\n");
    }
    // ============================================================================
    // End SNAP Process Guard integration
    // ============================================================================

    // ============================================================================
    // Deep2 Flight Recorder: instrument the REAL inference path.
    //
    // The Executor owns the actual token/layer loop, so the recorder is handed
    // to it (EnableFlightRecorder) rather than wrapping host-side phases only.
    // The previous host-side-only recorder emitted no events at all, which made
    // every long operation look like a deadlock to the watchdog.
    // ============================================================================
    std::wstring exec_flight_path = std::wstring(args.workdir.begin(), args.workdir.end()) + L"\\deep2_flight.jsonl";
    ex.EnableFlightRecorder(exec_flight_path);
    if (ex.IsFlightRecorderEnabled())
    {
        Logf_("[flight] Executor flight recorder active: %s\n", args.workdir.c_str());
    }
    else
    {
        Logf_("[flight] WARNING: Executor flight recorder not active\n");
    }
    // ============================================================================
    // End Flight Recorder initialization
    // ============================================================================

    // Chat markers from the model's own template (plain-text fallback).
    const ChatMarkers markers = ParseChatMarkers(GetTokenizer().chat_template);
    Logf_("[stage] chat markers: %s user='%s' asst='%s' gen='%s' bos_in_template=%d\n",
          markers.has_template ? "template" : "plain", markers.user_pre.c_str(),
          markers.asst_pre.c_str(), markers.gen_prompt.c_str(),
          markers.bos_in_template ? 1 : 0);

    // MSVC environment. Discovering cl here (rather than trusting PATH) is what
    // separates "the model's patch was wrong" from "there was no compiler".
    const MsvcEnv msvc = InitMsvcEnv();
    Logf_("[env] compiler: %s\n", msvc.detail.c_str());
    if (!msvc.initialized)
        Logf_("[env] WARNING: no verified MSVC toolchain; builds will fail with the toolchain's own error\n");

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
// ---- H02/SNAP state -------------------------------------------------------
    PerfProfiler profiler;
    RetryState retry_state;
    retry_state.max_attempts = args.max_retries;
    retry_state.max_tokens = args.max_total_tokens;
    retry_state.max_wall_time_sec = args.max_wall_time_sec;
    retry_state.start_time = std::chrono::steady_clock::now();

    PatchManager patch_mgr(args.workdir);
    ExecutionLedger ledger(args.workdir);
    patch_mgr.snapshot(args.target_file);
    const std::string initial_hash = SHA256_Hash(ReadFile(args.workdir + "/" + args.target_file));

    // Agent ESP telemetry with metrics
    rawrxd::esp::Bus esp(16384);
    std::string esp_log_path = args.workdir + "/agentic_live.jsonl";
    rawrxd::esp::ConsoleView cli_view;
    rawrxd::esp::Recorder esp_log(esp, esp_log_path, [&](const rawrxd::esp::Event& e){ cli_view(e); });
    if (!esp_log.start())
    {
        Logf_("[ESP] Failed to start recorder at %s\n", esp_log_path.c_str());
    }
    const uint64_t request_id = 1;
    const uint64_t agent_id = 0;
    rawrxd::esp::RuntimeESP esp_rt(esp, request_id, agent_id);

    // SNAP cancellation: Ctrl+C / console close sets the flag; it is polled at
    // every token and every prefill step (the safe dispatch boundaries).
    g_cancel_flag.store(false, std::memory_order_relaxed);
#ifdef _WIN32
    SetConsoleCtrlHandler(Deep2ConsoleCtrlHandler, TRUE);
#endif

    deep2::agent::StopController stop;
    stop.max_tokens = (uint32_t)args.max_new;

    // SNAP limits; a fresh Controller is built for each assistant turn.
    deep2::snap::Limits snap_ctl_limits;
    snap_ctl_limits.max_tokens = (size_t)args.max_new;
    snap_ctl_limits.max_output_bytes = 4 * 1024 * 1024;
    snap_ctl_limits.deadline = retry_state.start_time + std::chrono::seconds(args.max_wall_time_sec);

    // Conversation state (token-exact, template-faithful).
    //
    // The prompt is built from MESSAGES rendered with the model's own chat
    // template. Rendering is a pure function of the message list, so the token
    // stream has a stable prefix; each turn feeds only the tokens after
    // `fed.size()`. The model's generated tokens are executed as produced, so
    // they are already part of the next render's prefix and are NEVER
    // recomputed.
    //
    // `fed` is the authority for "the executor has consumed this many tokens",
    // so it must NEVER contain a token that was not actually executed. The old
    // pre-seed pushed BOS here while nothing executed it, so the loop then
    // called ExecuteToken(rendered[1], 1) with zero committed KV rows: position 1
    // attended to a never-written row and produced garbage that looked like
    // output. RenderChatTokens emits the BOS itself, so the seed stays empty and
    // every token in `fed` corresponds to a real forward pass.
    std::vector<uint32_t> fed;

    std::vector<ChatMessage> msgs;
    msgs.push_back({"system",
        "You are a file-repair agent operating a tool protocol.\n"
        "Reply with EXACTLY ONE command per turn. Never add explanations,\n"
        "apologies, quotes, or code fences.\n"
        "Before any other tool, read the workspace policy exactly once with:\n"
        "  TOOL read_motd\n"
        "Then continue with the requested task. The host blocks all other tools\n"
        "until read_motd succeeds.\n"
        "Commands:\n"
        "  TOOL read_motd\n"
        "  TOOL read <filename>\n"
        "  TOOL write <filename> @@<complete file content>@@\n"
        "  TOOL bash <command>\n"
        "  TOOL finish\n"});
    msgs.push_back({"user",
        "Read the workspace policy first. Then read the C++ file, fix its off-by-one bug, build it, and run it.\n"
        "File: " + args.target_file + "\n"
        "Reply with: TOOL read_motd"});

    bool finished = false, built = false, ran_pass = false;
    bool source_patched = false;
    deep2::agent::StopReason final_stop_reason = deep2::agent::StopReason::None;

    std::chrono::steady_clock::time_point last_token_time{};
    double last_transition_ms = -1.0;
    std::vector<uint32_t> incremental_stream = fed;

    // ---- Test A diagnostic: one static turn, no loop, no retry -----------------
    // Correctness before optimization.
    std::string gen;
    if (args.single_turn)
    {
        Logf_("[diag] TEST A: static prompt, single turn, %s\n",
              args.full_prefill ? "full-prefill baseline" : "incremental feed");
        const std::vector<uint32_t> prompt_tokens =
            RenderChatTokens(markers, msgs, true, enc, GetTokenizer().bos_id, GetTokenizer().eos_id);
        const size_t start = args.full_prefill ? 0 : fed.size();
        profiler.start_phase("prefill", prompt_tokens.size() - start);
        
        esp_rt.model_load(args.model);
        esp_rt.tokenizer(rt_ok);
        esp_rt.prefill_start(prompt_tokens.size() - start, fed.size());
        
        for (size_t i = start; i < prompt_tokens.size(); ++i)
        {
            if (!ex.ExecuteToken(prompt_tokens[i], fed.size()))
            {
                Logf_("[diag] EXEC_FAIL prefill pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                return 1;
            }
            fed.push_back(prompt_tokens[i]);
            incremental_stream.push_back(prompt_tokens[i]);
            // RAWRXD_DEEP2_PREFILL_PROGRESS_001: per-token telemetry during
            // prefill, so a long prefill reports ctx/gpu counters as it
            // advances instead of ctx=0 for the entire pass.
            esp_rt.set_context(fed.size());
            esp_rt.sync_kernel_counters(ex.Stats().gpu_calls, ex.Stats().cpu_calls);
            if ((i % 8) == 0) esp_rt.tick();
        }
        profiler.end_phase();
        esp_rt.prefill_end();
        esp_rt.set_context(fed.size());
        esp_rt.sync_kernel_counters(ex.Stats().gpu_calls, ex.Stats().cpu_calls);
        esp_rt.tick();
        Logf_("[diag] prefilled %zu tokens (%zu new; ctx=%zu)\n", prompt_tokens.size(),
              prompt_tokens.size() - start, fed.size());

        stop.reset();
        uint32_t next = 0;
        const auto t_gen = std::chrono::steady_clock::now();
        profiler.start_phase("generation", 0);
        esp_rt.decode_start();
        for (int t = 0; t < args.max_new; ++t)
        {
            if (g_cancel_flag.load(std::memory_order_relaxed))
            {
                final_stop_reason = deep2::agent::StopReason::Cancelled;
                break;
            }
            if (ex.NonFiniteLogits() != 0)
            {
                final_stop_reason = deep2::agent::StopReason::NonFinite;
                Logf_("[diag] non-finite logits (%zu); failing closed\n", ex.NonFiniteLogits());
                break;
        }
            const std::vector<float>& lg = ex.Logits();
            uint32_t next = 0;
            // Sampling with configurable temperature; temperature <= 0 means greedy
            if (args.temperature <= 0.0f)
            {
                next = 0;
                for (uint32_t i = 1; i < lg.size(); ++i)
                    if (lg[i] > lg[next]) next = i;
            }
            else
            {
                // Temperature-scaled softmax sampling
                const float inv_t = 1.0f / args.temperature;
                float max_logit = lg[0];
                for (uint32_t i = 1; i < lg.size(); ++i)
                    if (lg[i] > max_logit) max_logit = lg[i];
                float sum = 0.0f;
                static thread_local std::vector<float> probs;
                probs.resize(lg.size());
                for (uint32_t i = 0; i < lg.size(); ++i)
                {
                    probs[i] = std::exp((lg[i] - max_logit) * inv_t);
                    sum += probs[i];
                }
                float r = static_cast<float>(rand()) / static_cast<float>(RAND_MAX) * sum;
                float acc = 0.0f;
                next = lg.size() - 1;
                for (uint32_t i = 0; i < lg.size(); ++i)
                {
                    acc += probs[i];
                    if (r <= acc) { next = i; break; }
                }
            }

            const Action probe = ParseAction(gen);
            const deep2::agent::StopReason reason =
                stop.inspect(next, (uint32_t)GetTokenizer().eos_id, probe.valid && !probe.finish,
                             probe.valid && probe.finish, false);
            profiler.add_tokens(1);  // every token counted exactly once
            if (reason != deep2::agent::StopReason::None)
            {
                final_stop_reason = reason;
                if (reason == deep2::agent::StopReason::EOS) gen += '\n';
                Logf_("[diag] SNAP STOP: %s after %u tokens\n", deep2::agent::StopReasonName(reason),
                      stop.generated);
                break;
            }
            gen += enc.Piece(next);
            if (!ex.ExecuteToken(next, fed.size()))
            {
                Logf_("[diag] EXEC_FAIL gen pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                break;
            }
            fed.push_back(next);
            esp_rt.token(next, enc.Piece(next));
            // RAWRXD_DEEP2_GPU_TELEMETRY_001: publish the engine's real dispatch
            // counters so ESP gpu_dispatches/cpu_fallbacks are host-derived
            // facts, not always-zero placeholders.
            esp_rt.sync_kernel_counters(ex.Stats().gpu_calls, ex.Stats().cpu_calls);
            if (t % 5 == 0) esp_rt.tick();
            if (!args.quiet)
                Logf_("[diag] tok %3d/%d: %s\n", t, args.max_new, Trim(gen).c_str());
        }
        profiler.end_phase();
        const double gen_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t_gen).count();
        profiler.report();

        Logf_("\n=== TEST A RESULT ===\n");
        Logf_("STOP_REASON      %s\n", deep2::agent::StopReasonName(final_stop_reason));
        Logf_("GENERATED_TOKENS %u\n", stop.generated);
        Logf_("GEN_TIME_MS      %.1f\n", gen_ms);
        Logf_("DECODE_TPS       %.3f\n",
              stop.generated > 0 && gen_ms > 0 ? stop.generated / (gen_ms / 1000.0) : 0.0);
        const Action act = ParseAction(gen);
        Logf_("VALID_TOOL_CALL  %s\n", act.valid ? "yes" : "no");
        bool authorizationPassed = false;
        if (act.valid)
        {
            Logf_("TOOL             %s\n", act.tool.c_str());
            Logf_("TARGET           %s\n", act.arg1.c_str());
            std::string authorizationError;
            const bool authorized = motdAuthorization.AuthorizeTool(
                act.tool, motdSession, motdTurn, authorizationError);
            if (!authorized)
            {
                Logf_("MOTD_TOOL_VERDICT DENIED (%s)\n", authorizationError.c_str());
            }
            else if (act.tool == "read_motd")
            {
                std::string policy, hash, readError;
                const bool readOk = motdAuthorization.ReadMotd(
                    motdSession, motdTurn, policy, hash, readError);
                Logf_("MOTD_TOOL_VERDICT %s\n", readOk ? "ACKNOWLEDGED" : readError.c_str());
                if (readOk) Logf_("MOTD_SHA256 %s\n", hash.c_str());
                authorizationPassed = readOk;
            }
            else if (act.tool == "read")
            {
                const auto t_gen_b = std::chrono::steady_clock::now();
                const auto t_dispatch = std::chrono::steady_clock::now();
                const std::string content = ReadFile(args.workdir + "/" + act.arg1);
                Logf_("SNAP_TRANSITION_MS %.4f\n",
                      std::chrono::duration<double, std::milli>(t_dispatch - t_gen_b).count());
                Logf_("READ_BYTES       %zu\n", content.size());
                Logf_("READ_PREVIEW     %s\n", content.substr(0, 200).c_str());
                authorizationPassed = true;
            }
        }
        Logf_("RAW_OUTPUT       >>>%s<<<\n", Trim(gen).c_str());
        const bool testPass = act.valid && authorizationPassed;
        Logf_("TEST_A_VERDICT   %s\n", testPass ? "PASS" : "FAIL");
        ledger.log_verification(testPass, "single-turn static prompt + MOTD authorization diagnostic");
        esp_rt.finish(testPass);
        esp_log.stop();
        return testPass ? 0 : 1;
    }

    // ============================================================================
    // TEST B: TRUE single-turn repair -- one tool command, execute, verify, exit
    // ============================================================================
    if (args.single_turn_repair)
    {
        Logf_("\n=== TEST B: single-turn repair ===\n");
        const auto t_gen_b = std::chrono::steady_clock::now();
        const Action act = ParseAction(gen);
        if (!act.valid)
        {
            Logf_("TEST_B_VERDICT   FAIL (no valid tool command generated)\n");
            ledger.log_verification(false, "single-turn repair: invalid tool command");
            esp_rt.finish(false);
            esp_log.stop();
            return 1;
        }
        Logf_("TOOL             %s\n", act.tool.c_str());
        Logf_("TARGET           %s\n", act.arg1.c_str());

        bool step_ok = false;
        std::string authorizationError;
        const bool authorized = motdAuthorization.AuthorizeTool(
            act.tool, motdSession, motdTurn, authorizationError);
        if (!authorized)
        {
            Logf_("MOTD_TOOL_VERDICT DENIED (%s)\n", authorizationError.c_str());
        }
        else if (act.tool == "read_motd")
        {
            std::string policy, hash, readError;
            step_ok = motdAuthorization.ReadMotd(motdSession, motdTurn, policy, hash, readError);
            Logf_("MOTD_TOOL_VERDICT %s\n", step_ok ? "ACKNOWLEDGED" : readError.c_str());
            if (step_ok) Logf_("MOTD_SHA256 %s\n", hash.c_str());
            // This diagnostic mode certifies only one call, so the read proves
            // the gate itself but never claims a complete repair.
            step_ok = false;
        }
        else if (act.tool == "read")
        {
            const auto t_dispatch = std::chrono::steady_clock::now();
            const std::string content = ReadFile(args.workdir + "/" + act.arg1);
            const double snap_ms = std::chrono::duration<double, std::milli>(
                t_dispatch - t_gen_b).count();
            Logf_("SNAP_TRANSITION_MS %.4f\n", snap_ms);
            Logf_("READ_BYTES       %zu\n", content.size());
            Logf_("READ_PREVIEW     %s\n", content.substr(0, 200).c_str());
            step_ok = true;
        }
        else if (act.tool == "write")
        {
            const auto t_dispatch = std::chrono::steady_clock::now();
            const std::string target = args.workdir + "/" + act.arg1;
            if (WriteFile(target, act.arg2))
            {
                const double snap_ms = std::chrono::duration<double, std::milli>(
                    t_dispatch - t_gen_b).count();
                Logf_("SNAP_TRANSITION_MS %.4f\n", snap_ms);
                Logf_("WRITE_BYTES      %zu\n", act.arg2.size());
                Logf_("WRITE_PREVIEW    %s\n", act.arg2.substr(0, 200).c_str());

                // Compile
                Logf_("[build] %s\n", build_cmd);
                int code = 0;
                std::string build_out = RunCmd("cd /d \"" + args.workdir + "\" && " + build_cmd + " 2>&1", &code);
                Logf_("BUILD_EXIT       %d\n", code);
                if (code == 0)
                {
                    // Run test
                    Logf_("[run] %s\n", run_cmd);
                    int run_code = 0;
                    std::string run_out = RunCmd("cd /d \"" + args.workdir + "\" && " + run_cmd + " 2>&1", &run_code);
                    Logf_("RUN_EXIT         %d\n", run_code);
                    if (run_code == 0 && run_out.find(args.expected_output) != std::string::npos)
                    {
                        step_ok = true;
                        Logf_("TEST_PASSED      YES\n");
                    }
                    else
                    {
                        Logf_("TEST_FAILED      NO (exit=%d, output_missing_marker=%s)\n",
                              run_code,
                              run_out.find(args.expected_output) == std::string::npos ? "true" : "false");
                    }
                }
                else
                {
                    Logf_("BUILD_FAILED     %s\n", build_out.substr(0, 500).c_str());
                }
            }
            else
            {
                Logf_("WRITE_FAILED\n");
            }
        }
        else if (act.tool == "bash")
        {
            const auto t_dispatch = std::chrono::steady_clock::now();
            int code = 0;
            std::string out = RunCmd("cd /d \"" + args.workdir + "\" && " + act.arg1 + " 2>&1", &code);
            const double snap_ms = std::chrono::duration<double, std::milli>(
                t_dispatch - t_gen_b).count();
            Logf_("SNAP_TRANSITION_MS %.4f\n", snap_ms);
            Logf_("BASH_EXIT        %d\n", code);
            Logf_("BASH_OUTPUT      %s\n", out.substr(0, 200).c_str());
            step_ok = (code == 0);
        }
        else if (act.tool == "finish")
        {
            Logf_("FINISH called; no further action\n");
            step_ok = true;
        }
        else
        {
            Logf_("UNKNOWN_TOOL     %s\n", act.tool.c_str());
        }

        std::string gen;
        Logf_("RAW_OUTPUT       >>>%s<<<\n", Trim(gen).c_str());
        Logf_("TEST_B_VERDICT   %s\n", step_ok ? "PASS" : "FAIL");
        ledger.log_verification(step_ok, "single-turn repair");
        esp_rt.finish(step_ok);
        esp_log.stop();
        return step_ok ? 0 : 1;
    }

    // ESP: Start tracking the full agentic task
    esp_rt.model_load(args.model);
    esp_rt.tokenizer(rt_ok);
    esp_rt.prefill_start(0, 0); // Will update with actual counts per step

    for (int step = 1; step <= args.max_steps && !finished; ++step)
    {
        // ---- Budget gate: hard limits are host-owned, never model-declared -----
        if (!retry_state.can_retry())
        {
            Logf_("\n=== RETRY BUDGET EXHAUSTED ===\n");
            Logf_("Attempts: %d/%d, Tokens: %d/%d, Time: %llds/%ds, Stalled: %s\n",
                  retry_state.attempt, retry_state.max_attempts, retry_state.tokens_used,
                  retry_state.max_tokens,
                  std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::steady_clock::now() - retry_state.start_time).count(),
                  retry_state.max_wall_time_sec, retry_state.stalled ? "YES" : "NO");
            ledger.log_retry(retry_state.attempt, "budget exhausted", false);
            final_stop_reason = deep2::agent::StopReason::TokenLimit;
            break;
        }
        if (g_cancel_flag.load(std::memory_order_relaxed))
        {
            Logf_("\n[step %d] CANCELLED by user (Ctrl+C) before inference\n", step);
            ledger.log_retry(retry_state.attempt, "cancelled by user", false);
            final_stop_reason = deep2::agent::StopReason::Cancelled;
            break;
        }

        // ---- FEED only the not-yet-fed tokens (template-faithful render) -------
        const std::vector<uint32_t> rendered =
            RenderChatTokens(markers, msgs, true, enc, GetTokenizer().bos_id, GetTokenizer().eos_id);
        const size_t pending_count = rendered.size() > fed.size() ? rendered.size() - fed.size() : 0;
        if (pending_count == 0)
        {
            // Real defect: no new tokens, so the KV state is not what we believe.
            // Fail closed instead of generating against an unknown context.
            Logf_("[step %d] FATAL: rendered token stream has no new tokens (fed=%zu, rendered=%zu)\n",
                  step, fed.size(), rendered.size());
            ledger.log_retry(retry_state.attempt, "empty token delta: KV state invalid", false);
            final_stop_reason = deep2::agent::StopReason::Invalid;
            break;
        }

        {
            profiler.start_phase("prefill", pending_count);
            esp_rt.prefill_start(pending_count, fed.size());
            const auto t_step = std::chrono::steady_clock::now();
            bool pref_cancelled = false;

            // RAWRXD_DEEP2_BATCHED_PREFILL_001: use the verified batched path.
            //
            // The flight recorder established the serial cost directly: each
            // token runs 458 ops through every layer with one submission each,
            // ~1.0 s/token steady state, which is why a 135-token prompt took
            // ~138 s. PrefillBatch queues P dots per op into ONE command buffer
            // behind ONE fence, removing 458*(P-1) submissions.
            //
            // Parity is already established (evidence/GAP_AUDIT_2026-10-13/
            // gate7_tps/gate7_d2_batched_vs_serial_logits.json): 135/135
            // positions bit-identical to the serial path, worst_maxabs 0.0,
            // worst_cos 1.0. So this is a throughput change, not a numerics
            // change, and the serial path stays the reference behind
            // --batched-prefill 0.
            bool prefill_ok = false;
            if (args.batched_prefill && pending_count > 1)
            {
                std::vector<uint32_t> batch(rendered.begin() + fed.size(), rendered.end());
                prefill_ok = ex.PrefillBatch(batch, fed.size());
                if (!prefill_ok)
                {
                    Logf_("[step %d] PrefillBatch refused (%s); falling back to serial\n",
                          step, ex.LastError().c_str());
                }
            }
            else if (args.batched_prefill)
            {
                // Single new token: the batched path needs P>1 to be worth it,
                // and Executor refuses P==1 with an error, so use ExecuteToken.
                prefill_ok = false;
            }

            if (prefill_ok)
            {
                // Positions [fed.size(), rendered.size()) are now in the KV
                // cache; adopt them so the next render's prefix is unchanged.
                for (size_t i = fed.size(); i < rendered.size(); ++i)
                    incremental_stream.push_back(rendered[i]);
                fed.resize(rendered.size());
                esp_rt.set_context(fed.size());
                esp_rt.sync_kernel_counters(ex.Stats().gpu_calls, ex.Stats().cpu_calls);
                esp_rt.tick();
            }
            else
            {
                for (size_t i = fed.size(); i < rendered.size(); ++i)
                {
                    if (g_cancel_flag.load(std::memory_order_relaxed))
                    {
                        Logf_("\n[step %d] CANCELLED during prefill at %zu/%zu\n", step, i, rendered.size());
                        final_stop_reason = deep2::agent::StopReason::Cancelled;
                        pref_cancelled = true;
                        break;
                    }
                    if (!ex.ExecuteToken(rendered[i], fed.size()))
                    {
                        Logf_("EXEC_FAIL prefill pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                        return 1;
                    }
                    fed.push_back(rendered[i]);
                    incremental_stream.push_back(rendered[i]);
                    // RAWRXD_DEEP2_PREFILL_PROGRESS_001: publish per-token progress
                    // during prefill. Without it a long prefill is indistinguishable
                    // from a deadlock, and both the flight recorder watchdog and ESP
                    // report global_no_progress while the engine is actually working.
                    esp_rt.set_context(fed.size());
                    esp_rt.sync_kernel_counters(ex.Stats().gpu_calls, ex.Stats().cpu_calls);
                    if ((i % 8) == 0) esp_rt.tick();
                }
            }
            profiler.end_phase();
            esp_rt.prefill_end();
            esp_rt.set_context(fed.size());
            Logf_("[step %d] prefill +%zu tokens (ctx=%zu tokens) in %.0f ms (%s)\n", step, pending_count,
                  fed.size(),
                  std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t_step).count(),
                  prefill_ok ? "batched" : "serial");
            esp_rt.sync_kernel_counters(ex.Stats().gpu_calls, ex.Stats().cpu_calls);
            esp_rt.tick();
            if (pref_cancelled)
                break;
        }

        // ---- GENERATE under the SNAP controller (event-driven termination) ----
        deep2::snap::Controller snap_ctl{snap_ctl_limits, 4 * 1024 * 1024};
        std::string gen;
        uint32_t next = 0;
        const auto t_gen = std::chrono::steady_clock::now();
        last_token_time = t_gen;
        deep2::snap::Result snap_res;
        std::vector<uint32_t> turn_token_ids;

        profiler.start_phase("generation", 0);
        esp_rt.decode_start();
        for (int t = 0; t < args.max_new; ++t)
        {
            if (g_cancel_flag.load(std::memory_order_relaxed))
                snap_ctl.cancel();  // propagate Ctrl+C into SNAP
            auto pre = snap_ctl.before_decode();
            if (pre.reason != deep2::snap::Reason::none)
            {
                snap_res = pre;
                Logf_("[step %d] SNAP pre-decode stop: reason=%d tokens=%zu %s\n", step, (int)pre.reason,
                      pre.tokens, pre.diagnostic.c_str());
                break;
            }
            if (ex.NonFiniteLogits() != 0)
            {
                snap_res = {deep2::snap::Reason::invalid, {}, pre.tokens, "non-finite logits"};
                Logf_("\n[step %d] SNAP: NON-FINITE LOGITS (%zu); failing closed\n", step,
                      ex.NonFiniteLogits());
                ledger.log_retry(retry_state.attempt, "non-finite logits", retry_state.can_retry());
                break;
            }
            const std::vector<float>& lg = ex.Logits();
            next = 0;
            for (uint32_t i = 1; i < lg.size(); ++i)
                if (lg[i] > lg[next]) next = i;

            const bool is_eos = (next == (uint32_t)GetTokenizer().eos_id);
            const std::string piece = is_eos ? std::string() : enc.Piece(next);
            snap_res = snap_ctl.on_token(piece, is_eos);
            profiler.add_tokens(1);  // every token counted exactly once
            if (snap_res.reason != deep2::snap::Reason::none)
            {
                if (snap_res.reason == deep2::snap::Reason::eos) gen += '\n';
                esp_rt.snap(snap_res.diagnostic.empty() ? 
                    std::string("reason=") + std::to_string((int)snap_res.reason) : snap_res.diagnostic);
                Logf_("[step %d] SNAP STOP: reason=%d tokens=%zu after %u host tokens\n", step,
                      (int)snap_res.reason, snap_res.tokens, t + 1);
                // ---- Immediate-EOS diagnosis (Failure A) ----------------------
                // EOS as the FIRST token of a turn is not a model refusal, it is
                // a prompt-format defect: the model was never put in the state
                // where an assistant turn should continue. Dump the tail of what
                // was actually fed so the marker drift is visible on the same
                // line as the failure instead of requiring a separate decode.
                if (snap_res.reason == deep2::snap::Reason::eos && gen.empty() && step == 1)
                {
                    std::string tail;
                    const size_t tw = fed.size() > 24 ? fed.size() - 24 : 0;
                    for (size_t i = tw; i < fed.size(); ++i)
                        tail += enc.Piece(fed[i]);
                    Logf_("[step %d] IMMEDIATE EOS on the first generated token.\n", step);
                    Logf_("[step %d]   generated text  : >>>%s<<<\n", step, EscapeForLog(gen).c_str());
                    Logf_("[step %d]   last fed tokens: >>>%s<<<\n", step, EscapeForLog(tail).c_str());
                    Logf_("[step %d]   markers: user='%s' asst='%s' gen='%s' sys_eos=%d user_eos=%d asst_eos=%d\n",
                          step,
                          EscapeForLog(markers.user_pre).c_str(),
                          EscapeForLog(markers.asst_pre).c_str(),
                          EscapeForLog(markers.gen_prompt).c_str(),
                          (int)markers.system_eos_suffix,
                          (int)markers.user_eos_suffix,
                          (int)markers.eos_in_asst_suffix);
                    Logf_("[step %d]   eos_id=%d bos_id=%d prompt_ids=%zu\n",
                          step, GetTokenizer().eos_id, GetTokenizer().bos_id, fed.size());
                    ledger.log_retry(retry_state.attempt, "immediate EOS: prompt format mismatch", false);
                }
                break;
            }
            gen += piece;
            turn_token_ids.push_back(next);
            esp_rt.token(next, piece);
            // RAWRXD_DEEP2_GPU_TELEMETRY_001: mirror the engine's real kernel
            // counters into ESP each token so the heartbeat reports what the
            // backend actually dispatched instead of always-zero.
            esp_rt.sync_kernel_counters(ex.Stats().gpu_calls, ex.Stats().cpu_calls);
            if (t % 5 == 0) esp_rt.tick();
            if (!ex.ExecuteToken(next, fed.size()))
            {
                Logf_("EXEC_FAIL gen pos=%zu err=%s\n", fed.size(), ex.LastError().c_str());
                snap_res = {deep2::snap::Reason::invalid, {}, pre.tokens, ex.LastError()};
                break;
            }
            fed.push_back(next);
            // The generated token is PART of the token stream the executor has
            // consumed. incremental_stream mirrors `fed`, so it must be extended
            // here too: omitting decode tokens made the stream end at the
            // generation prompt, and the next turn's render then diverged at that
            // point (fresh contained the assistant turn's own content + EOS).
            incremental_stream.push_back(next);
            last_token_time = std::chrono::steady_clock::now();
            if (!args.quiet && t % 10 == 0)
                Logf_("[step %d] tok %d/%d: %s\n", step, t, args.max_new, Trim(gen).c_str());
        }
        profiler.end_phase();
        esp_rt.tick();

        const double gen_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t_gen).count();
        const size_t gen_tokens = snap_res.tokens;
        Logf_("[step %d] generated %zu tokens / %zu chars in %.0f ms (%.3f tok/s) snap=%d\n",
              step, gen_tokens, gen.size(), gen_ms,
              gen_tokens > 0 && gen_ms > 0 ? gen_tokens / (gen_ms / 1000.0) : 0.0,
              (int)snap_res.reason);
        dump_snap_output("SNAP OUT", gen, (int)GetTokenizer().eos_id, &turn_token_ids);

        retry_state.tokens_used += (int)gen_tokens;
        msgs.push_back({"assistant", gen});  // the model's own words, template-faithful

        // ---- Resolve the command: strict SNAP framing first, then legacy -------
        Action act;
        bool used_strict_protocol = false;
        if (snap_res.command)
        {
            const auto& cmd = *snap_res.command;
            act.tool = cmd.verb;
            act.arg1 = cmd.payload;
            act.arg2 = cmd.payload;
            act.valid = true;
            act.finish = (cmd.verb == "finish");
            act.raw = "TOOL " + cmd.verb + " " + std::to_string(cmd.payload.size()) + "\n" +
                      cmd.payload + "\nEND_TOOL";
            used_strict_protocol = true;
        }
        else
        {
            // Legacy grammar. The strict parser failed, so the line has ended
            // without its terminator: append one. ParseAction still requires an
            // explicit closing @@ for writes, so an incomplete multi-line patch
            // can never dispatch.
            act = ParseAction(gen + "\n");
        }
        if (used_strict_protocol)
            Logf_("[step %d] strict SNAP protocol command: verb=%s payload=%zu bytes\n", step,
                  act.tool.c_str(), act.arg1.size());

        if (!act.valid)
        {
            Logf_("[step %d] INVALID OUTPUT (snap reason=%d %s); no complete command\n", step,
                  (int)snap_res.reason, snap_res.diagnostic.c_str());
            dump_snap_output("SNAP REJECT", gen, (int)GetTokenizer().eos_id, &turn_token_ids);
            retry_state.record_failure("invalid_tool_format");
            // RAWRXD_DEEP2_FAILURE_TRUTH_001: a model-output failure is a failure.
            // The old heartbeat reported failures=0 through a run that produced
            // two invalid model outputs and then failed, because only build/test
            // exit codes ever incremented the counter. A receipt whose failure
            // count stays at zero while the verdict is FAIL is not evidence of
            // anything except a broken counter.
            esp_rt.model_output_failure();
            ledger.log_retry(retry_state.attempt, "invalid_tool_format", retry_state.can_retry());
            retry_state.attempt++;
            msgs.push_back({"user",
                "That reply was not one complete command. Reply with EXACTLY one command.\n"
                "e.g. TOOL read " + args.target_file});
            continue;
        }

        last_transition_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - last_token_time).count();
        if (act.finish)
        {
            finished = true;
            Logf_("[step %d] TOOL finish requested - host verification required\n", step);
            break;
        }

        // ---- dispatch -----------------------------------------------------------
        std::string result;
        int bash_exit_code = 0;
        bool tool_rejected = false;
        std::string authorizationError;
        const bool toolAuthorized = motdAuthorization.AuthorizeTool(
            act.tool, motdSession, motdTurn, authorizationError);
        const bool writeSnapshotReady = !toolAuthorized || act.tool != "write" ||
                                        patch_mgr.snapshot(act.arg1);
        if (!toolAuthorized)
        {
            tool_rejected = true;
            bash_exit_code = -1;
            result = "MOTD_REQUIRED: " + authorizationError;
            Logf_("[step %d] MOTD_TOOL_VERDICT DENIED (%s)\n", step, authorizationError.c_str());
        }
        else if (!writeSnapshotReady)
        {
            tool_rejected = true;
            bash_exit_code = -1;
            result = "[exit -1]\nERROR: failed to snapshot target before write\n";
            Logf_("[step %d] ERROR: Failed to snapshot %s before write\n", step, act.arg1.c_str());
        }
        else if (act.tool == "read_motd")
        {
            std::string policy, hash, readError;
            if (motdAuthorization.ReadMotd(motdSession, motdTurn, policy, hash, readError))
            {
                result = "MOTD_ACK=1\nMOTD_SHA256=" + hash + "\n" + policy;
                Logf_("[step %d] MOTD_STATUS ACKNOWLEDGED sha256=%s\n", step, hash.c_str());
            }
            else
            {
                tool_rejected = true;
                bash_exit_code = -1;
                result = "MOTD_READ_FAILED: " + readError;
                Logf_("[step %d] MOTD_STATUS BLOCKED (%s)\n", step, readError.c_str());
            }
        }
        else if (act.tool == "read")
        {
            result = ReadFile(args.workdir + "/" + act.arg1);
            if (result.empty()) result = "(file not found)";
        }
        else if (act.tool == "write")
        {
            const std::string path = args.workdir + "/" + act.arg1;
            const bool ok = WriteFile(path, act.arg2);
            source_patched = true;
            result = ok ? ("wrote " + act.arg1 + " (" + std::to_string(act.arg2.size()) + " bytes)")
                        : "write failed";
            ledger.log_patch(step, act.arg1, initial_hash, SHA256_Hash(act.arg2), false, false);
        }
        else if (act.tool == "build" || act.tool == "test")
        {
            // Security boundary: the parser validates syntax, never authorization.
            // These verbs map to PREDETERMINED host commands, never model shell.
            const std::string& cmd = (act.tool == "build") ? build_cmd : run_cmd;
            if (!cmd.empty())
            {
                int code = 0;
                result = RunCmd("cd /d \"" + args.workdir + "\" && " + WithMsvcEnv(msvc, cmd) + " 2>&1", &code);
                bash_exit_code = code;
                if (act.tool == "build" && code == 0) built = true;
                char hdr[48];
                std::snprintf(hdr, sizeof(hdr), "[exit %d]\n", code);
                result = hdr + result;
            }
            else
            {
                tool_rejected = true;
                result = "[exit -1]\nERROR: no host-authorised command configured for this verb\n";
                bash_exit_code = -1;
            }
        }
        else if (act.tool == "bash")
        {
            if (act.arg1.find("TOOL ") != std::string::npos ||
                act.arg1.find("$(") != std::string::npos ||
                act.arg1.find("`") != std::string::npos ||
                (act.arg1.find("&&") != std::string::npos && act.arg1.find("cl ") == std::string::npos))
            {
                tool_rejected = true;
                result = "[exit -1]\nERROR: malformed bash command rejected\n";
                bash_exit_code = -1;
                Logf_("[step %d] TOOL bash REJECTED: %s\n", step, act.arg1.c_str());
            }
            else
            {
                int code = 0;
                // A model-issued build command needs the same MSVC environment
                // the host's own build verb uses.
                const std::string wrapped = (act.arg1.rfind("cl", 0) == 0 || act.arg1.find(" cl ") != std::string::npos)
                    ? WithMsvcEnv(msvc, act.arg1) : act.arg1;
                result = RunCmd("cd /d \"" + args.workdir + "\" && " + wrapped + " 2>&1", &code);
                bash_exit_code = code;
                char hdr[48];
                std::snprintf(hdr, sizeof(hdr), "[exit %d]\n", code);
                result = hdr + result;
            }
        }
        else
        {
            result = "unsupported tool";
            tool_rejected = true;
        }

        if (toolAuthorized && act.tool != "read_motd")
            motdAuthorization.NoteExecution(motdSession, motdTurn);

        if (result.size() > 2500 && act.tool != "read_motd")
            result = result.substr(0, 1200) + "\n...[truncated]...\n" + result.substr(result.size() - 800);

        // ESP: Tool events
        esp_rt.tool_start(act.tool + " " + act.arg1);
        if (act.tool == "read" || act.tool == "write") {
            esp_rt.tool_result(act.tool + " " + act.arg1 + " bytes=" + std::to_string(result.size()), bash_exit_code);
        } else if (act.tool == "build") {
            esp_rt.build_start(build_cmd);
            esp_rt.build_result(bash_exit_code);
        } else if (act.tool == "test") {
            esp_rt.test_start(run_cmd);
            esp_rt.test_result(bash_exit_code);
        } else if (act.tool == "bash") {
            esp_rt.tool_result("bash " + act.arg1 + " exit=" + std::to_string(bash_exit_code), bash_exit_code);
        }

        ToolCallReceipt receipt;
        receipt.step = step;
        receipt.tool = act.tool;
        receipt.target = act.arg1;
        receipt.raw_command = act.raw;
        receipt.observation = result;
        receipt.observation_bytes = (int)result.size();
        receipt.bash_exit_code = bash_exit_code;
        receipt.tool_valid = !tool_rejected;
        receipt.timestamp = std::chrono::steady_clock::now();
        retry_state.record_tool_call(receipt);
        ledger.log_tool_call(step, act.tool, act.arg1, result, bash_exit_code, !tool_rejected);
        Logf_("[step %d] TOOL %s -> %s ; observation %zu bytes; SNAP dispatch transition %.4f ms\n",
              step, act.tool.c_str(), act.arg1.c_str(), result.size(), last_transition_ms);
        Logf_("%s\n", result.c_str());

        esp_rt.tick();

        // ---- Write patch: the HOST decides commit or rollback -------------------
        if (act.tool == "write" && source_patched)
        {
            if (patch_mgr.verify(build_cmd, run_cmd, args.expected_output, args.workdir))
            {
                patch_mgr.commit(act.arg1);
                ledger.log_patch(step, act.arg1, initial_hash,
                                 SHA256_Hash(ReadFile(args.workdir + "/" + act.arg1)), true, false);
                Logf_("[step %d] PATCH COMMITTED and verified by host\n", step);
                built = true;
                ran_pass = true;
                finished = true;
                break;
            }
            patch_mgr.rollback(act.arg1);
            ledger.log_patch(step, act.arg1, initial_hash,
                             SHA256_Hash(ReadFile(args.workdir + "/" + act.arg1)), false, true);
            retry_state.record_failure("patch_verification_failed");
            ledger.log_retry(retry_state.attempt,
                             "patch_verification_failed: " + patch_mgr.last()->last_error,
                             retry_state.can_retry());
            retry_state.attempt++;
            result = "\nRESULT: Patch failed verification - " + patch_mgr.last()->last_error +
                     "\nRollback performed. Retry " + std::to_string(retry_state.attempt) + "/" +
                     std::to_string(retry_state.max_attempts) + "\n";
            Logf_("[step %d] PATCH ROLLED BACK: %s\n", step, patch_mgr.last()->last_error.c_str());
        }

        // ---- Feed the observation back as the next user turn -------------------
        msgs.push_back({"user", "Result of your command:\n" + result});
    }

    // ---- Token-stream equivalence: incremental KV vs fresh render -------------
    //
    // The incremental path feeds only tokens after `fed.size()` and assumes the
    // rendered prefix is stable. If the two streams diverge, the KV cache holds
    // a prefix that is NOT the prompt the model is currently answering, so every
    // later step is conditioned on fabricated context.
    //
    // The correct contract is PREFIX, not equality: turn N's stream ends with
    // turn N's generation prompt, and that prompt is a token prefix of turn N+1's
    // assistant marker (e.g. gen prompt ">\" is the first tokens of the
    // assistant marker ">\n"). The KV state created while conditioning on the
    // generation prompt is therefore still valid, which is exactly why the
    // incremental path can reuse it instead of re-running the whole prompt.
    //
    // Fail closed: report the FIRST divergence (position + both token ids + the
    // decoded text on each side) and record it as a verification failure. A
    // mismatch must never be downgraded to a warning.
    bool kv_consistent = true;
    {
        const std::vector<uint32_t> fresh =
            RenderChatTokens(markers, msgs, true, enc, GetTokenizer().bos_id, GetTokenizer().eos_id);

        // Longest common prefix length.
        size_t common = 0;
        while (common < incremental_stream.size() && common < fresh.size() &&
               incremental_stream[common] == fresh[common])
            ++common;
        const bool is_prefix = (common == incremental_stream.size());
        kv_consistent = is_prefix;

        Logf_("[kv] committed KV stream %s the current render (%zu of %zu ids common; incremental=%zu fresh=%zu)\n",
              is_prefix ? "IS A VALID PREFIX OF" : "DIVERGES FROM",
              common, fresh.size(), incremental_stream.size(), fresh.size());
        if (!is_prefix)
        {
            const size_t d = common;
            Logf_("[kv] FIRST DIVERGENCE at position %zu: incremental=%u ('%s') fresh=%u ('%s')\n",
                  d,
                  d < incremental_stream.size() ? incremental_stream[d] : 0u,
                  d < incremental_stream.size() ? enc.Piece(incremental_stream[d]).c_str() : "<eof>",
                  d < fresh.size() ? fresh[d] : 0u,
                  d < fresh.size() ? enc.Piece(fresh[d]).c_str() : "<eof>");
            // Dump the surrounding window on both sides so the cause (BOS/EOS
            // placement, role delimiter, template drift) is visible directly.
            const size_t win = d > 4 ? d - 4 : 0;
            const size_t wend = std::min(d + 5, std::max(incremental_stream.size(), fresh.size()));
            std::string inc_txt, fresh_txt;
            for (size_t i = win; i < wend; ++i)
            {
                if (i < incremental_stream.size())
                    inc_txt += enc.Piece(incremental_stream[i]);
                if (i < fresh.size())
                    fresh_txt += enc.Piece(fresh[i]);
            }
            Logf_("[kv] window [%zu..%zu): incremental='%s'\n", win, wend, EscapeForLog(inc_txt).c_str());
            Logf_("[kv] window [%zu..%zu): fresh     ='%s'\n", win, wend, EscapeForLog(fresh_txt).c_str());
            // KV ADMISSION GUARD: the cache holds a context that is not a prefix
            // of the prompt now being asked. Decoding from here would condition
            // on tokens the conversation never contained, so the run must stop
            // rather than produce a confidently wrong answer.
            Logf_("[kv] ADMISSION GUARD: committed KV is not a prefix of the current prompt; refusing to decode\n");
            ledger.log_retry(args.max_steps, "kv_prefix_mismatch@" + std::to_string(d), false);
        }
    }

    // ---- INDEPENDENT verification (the model's word is not evidence) ----------
    const std::string src = ReadFile(args.workdir + "/" + args.target_file);
    const bool src_fixed = src.find("a + b") != std::string::npos || src.find("a+b") != std::string::npos;
    
    // Execute the build command if not already done
    if (!built)
    {
        Logf_("[verification] running build command: %s\n", build_cmd.c_str());
        int code = 0;
        std::string build_out = RunCmd("cd /d \"" + args.workdir + "\" && " + WithMsvcEnv(msvc, build_cmd) + " 2>&1", &code);
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
        run_out = RunCmd("cd /d \"" + args.workdir + "\" && " + WithMsvcEnv(msvc, run_cmd) + " 2>&1", &exit_now);
    }
    const bool exe_ok = exit_now == 0 && run_out.find(args.expected_output) != std::string::npos;

    Logf_("\n=== verification (harness-run, independent of the model) ===\n");
    Logf_("MODEL_SAID_FINISH      %s\n", finished ? "yes" : "no");
    Logf_("SOURCE_PATCHED         %s (%s contains %s)\n", src_fixed ? "PASS" : "FAIL", args.target_file.c_str(),
          src_fixed ? "a + b" : "no fix");
    Logf_("BUILD_ARTIFACT         %s (%s)\n", built ? "attempted" : "not observed",
          msvc.initialized ? msvc.detail.c_str() : "NO VERIFIED TOOLCHAIN");
    Logf_("TEST_EXECUTION         %s (%s exit=%d out=%s)\n", exe_ok ? "PASS" : "FAIL", args.target_file.c_str(), exit_now, run_out.c_str());
    Logf_("TOOL_RESULT_FEEDBACK   %d steps completed\n", args.max_steps);
    Logf_("KV_PREFIX_CONSISTENT   %s\n", kv_consistent ? "PASS" : "FAIL");
    // A model that never asked for a tool did not do the repair, no matter what
    // the file on disk says. The harness's own pass/fail is reported separately
    // and must not be conflated with the agent's.
    const bool model_drove_repair = finished && retry_state.tool_calls > 0;
    Logf_("MODEL_REQUESTED_TOOL   %s (tool_calls=%u)\n", model_drove_repair ? "yes" : "NO", retry_state.tool_calls);
    Logf_("FINAL_VERDICT          %s\n",
          (model_drove_repair && src_fixed && exe_ok && kv_consistent) ? "PASS" : "FAIL");

    // ESP: Finish with host verification result
    const bool final_pass = model_drove_repair && src_fixed && exe_ok && kv_consistent;
    esp_rt.finish(final_pass);
    esp_log.stop();
    
    return final_pass ? 0 : 1;
}
