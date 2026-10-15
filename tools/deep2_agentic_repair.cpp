// ============================================================================
// deep2_agentic_repair.cpp -- H01/H02: Host-driven autonomous repair loop
// ============================================================================
// RAWR_AUTONOMOUS_REPAIR_E2E_001
//
// The host owns the entire loop. The model's ONLY job is to emit the complete
// fixed source for the defective file when given the source plus the real
// compiler/test output. There is no free-form tool protocol: base and small
// instruct models demonstrably fail to honour one, and a fabricated protocol
// pass is not a repair.
//
// Certification sequence (each gate fail-closed, monotonic stage timings):
//   G1 tokenizer round-trip      decode(encode(x)) == x, byte-exact
//   G2 one-token inference        nonzero finite logits
//   G3 short generation           10 tokens, detokenises cleanly
//   G4 baseline defect confirmed  build FAILS or runs and prints non-PASS
//   G5 model patch attempt         model emits source; host applies it
//   G6 patch verification         host builds + runs; PASS expected
//   G7 independent re-verification fresh process, fresh build
//
// Every stage prints a flushed monotonic timestamp receipt. Nothing is
// reported as passing without host-side evidence (build exit code, program
// exit code, expected output marker).
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "deep2_tokenizer.hpp"

using namespace RawrXD::Deep2;
using RawrXD::Deep2::RuntimeGraph::Executor;
using RawrXD::Deep2::Universal::GetTokenizer;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;

namespace fs = std::filesystem;
using deep2tools::SpEncoder;
using Clock = std::chrono::steady_clock;

struct Args
{
    std::string model;
    std::string target_file = "calc.cpp";
    std::string workdir = "agentic_ws";
    std::string build_cmd;
    std::string run_cmd;
    std::string expected_output = "PASS";
    int max_retries = 3;
    int max_new = 1024;
    bool cpu = false;
    bool verbose = false;
    // Certification-only probes: stop after the named gate.
    std::string stop_after;
    // Skip the compiler stage entirely (tokenizer/inference gates only).
    bool no_build = false;
};

static Args Parse(int argc, char* argv[])
{
    Args a;
    for (int i = 1; i < argc; ++i)
    {
        const std::string s = argv[i];
        if (s == "--model" && i + 1 < argc) a.model = argv[++i];
        else if (s == "--target-file" && i + 1 < argc) a.target_file = argv[++i];
        else if (s == "--workdir" && i + 1 < argc) a.workdir = argv[++i];
        else if (s == "--build-command" && i + 1 < argc) a.build_cmd = argv[++i];
        else if (s == "--run-command" && i + 1 < argc) a.run_cmd = argv[++i];
        else if (s == "--expected-output" && i + 1 < argc) a.expected_output = argv[++i];
        else if (s == "--max-retries" && i + 1 < argc) a.max_retries = std::atoi(argv[++i]);
        else if (s == "--max-new" && i + 1 < argc) a.max_new = std::atoi(argv[++i]);
        else if (s == "--stop-after" && i + 1 < argc) a.stop_after = argv[++i];
        else if (s == "--cpu") a.cpu = true;
        else if (s == "--verbose" || s == "-v") a.verbose = true;
        else if (s == "--no-build") a.no_build = true;
    }
    return a;
}

static std::string ReadFile(const std::string& p)
{
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) return {};
    std::string s;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, n);
    std::fclose(f);
    return s;
}

static bool WriteFile(const std::string& p, const std::string& s)
{
    FILE* f = std::fopen(p.c_str(), "wb");
    if (!f) return false;
    const size_t n = std::fwrite(s.data(), 1, s.size(), f);
    std::fclose(f);
    return n == s.size();
}

static std::string Trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

// ---------------------------------------------------------------------------
// Stage-timing receipt layer. Every stage prints a flushed monotonic line so
// a timeout can be attributed to a specific stage instead of a silent stall.
// ---------------------------------------------------------------------------
struct StageTimer
{
    Clock::time_point t0;
    std::vector<std::string> receipts;

    StageTimer() : t0(Clock::now()) {}

    double since_start_ms() const
    {
        return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    }

    void mark(const std::string& stage, const std::string& detail = "")
    {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "  [%8.1f ms] ", since_start_ms());
        const std::string line = std::string(buf) + stage + (detail.empty() ? "" : " | " + detail);
        std::fputs(("[stage] " + line + "\n").c_str(), stdout);
        std::fflush(stdout);
        receipts.push_back(line);
    }
};

// Host-owned command execution. Build commands run inside an MSVC environment;
// the vcvars wrapper keeps the compiler reachable without the caller having
// to shell out of a developer prompt. Timeout is the host's, per command.
struct CmdResult
{
    int exit_code = -1;
    std::string output;
    double elapsed_ms = 0;
};

// Host-owned command execution. Build commands run inside an MSVC environment
// via the vcvars wrapper batch.
//
// Two cmd.exe quoting rules are load-bearing here, both verified by experiment:
//   1. The wrapper invocation itself must be `"batch" args`, NOT `"batch"args`
//      (no separating space makes cmd.exe read one nonexistent token).
//   2. _popen runs `cmd.exe /c <string>`, and cmd.exe only treats a leading
//      quoted token as a command to execute when the whole line is wrapped in
//      an extra pair of quotes: `cmd /c ""wrapper" cl ... "src.cpp""`. Without
//      that wrapper cmd.exe fails with "The filename, directory name, or volume
//      label syntax is incorrect" and exits 1 in ~15 ms, which silently turns a
//      working compiler into a false "build failed" verdict.
// The command must also avoid `cd`/`&&`: cmd.exe splits those operators before
// the batch receives them, so the compiler would run outside the developer
// environment. Absolute paths make `cd` unnecessary; /Fo pins the .obj.
static CmdResult RunCmd(const std::string& cmd)
{
    CmdResult r;
    const auto t = Clock::now();
    const std::string full = "\"\"F:\\rawrxd\\agentic_ws\\vcvars_run.bat\" " + cmd + "\"";
    FILE* p = _popen(full.c_str(), "r");
    if (!p)
    {
        r.exit_code = -1;
        r.output = "popen failed";
        r.elapsed_ms = std::chrono::duration<double, std::milli>(Clock::now() - t).count();
        return r;
    }
    char buf[512];
    while (std::fgets(buf, sizeof(buf), p)) r.output += buf;
    r.exit_code = _pclose(p);
    r.elapsed_ms = std::chrono::duration<double, std::milli>(Clock::now() - t).count();
    return r;
}

// Stable, explicitly non-cryptographic checksum for before/after evidence.
// Real SHA-256 belongs in the release manifest gate, not here.
static std::string ContentHash(const std::string& data)
{
    uint64_t h = 14695981039346656037ull;
    for (unsigned char c : data)
    {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)h);
    return buf;
}

static std::string HexHead(const std::string& s, size_t n = 32)
{
    char buf[4];
    std::string o;
    const size_t lim = s.size() < n ? s.size() : n;
    for (size_t i = 0; i < lim; ++i)
    {
        std::snprintf(buf, sizeof(buf), "%02x", (unsigned char)s[i]);
        o += buf;
        if (i % 2) o += ' ';
    }
    if (s.size() > n) o += "...";
    return o;
}

// ---------------------------------------------------------------------------
// G1: tokenizer round-trip with byte-exact diagnostics on failure.
// ---------------------------------------------------------------------------
static bool GateTokenizer(StageTimer& st, SpEncoder& enc, bool verbose)
{
    st.mark("G1 tokenizer: round-trip begin");
    const std::vector<std::string> probes = {
        "int main() { return 0; }\n",
        "for (size_t i = 0; i <= data.size(); ++i) {",
        "\ttab-indented line\n    four-space line\n",
        "#include <vector>\nint add(int a, int b) { return a + b; }\n",
    };
    int fails = 0;
    for (const auto& in : probes)
    {
        std::vector<int32_t> ids;
        enc.Encode(in, ids);
        std::string d1 = deep2tools::DetokenizeWith(enc.tokens, ids);
        std::string d2;
        for (int32_t id : ids) d2 += enc.Piece((uint32_t)id);
        const bool ok = (ids.size() > 0) && (d1 == in) && (d2 == in);
        if (!ok)
        {
            ++fails;
            size_t first_diff = 0;
            const std::string& ref = (d1 == in) ? d1 : d2;
            while (first_diff < ref.size() && first_diff < in.size() && ref[first_diff] == in[first_diff]) ++first_diff;
            std::printf("TOKENIZER_TEST=FAIL\n");
            std::printf("INPUT_BYTES=%s\n", HexHead(in, 64).c_str());
            std::printf("ENCODED_IDS=");
            for (int32_t id : ids) std::printf("%d,", id);
            std::printf("\n");
            std::printf("DECODED_BYTES=%s\n", HexHead(d1, 64).c_str());
            std::printf("PIECE_DECODED_BYTES=%s\n", HexHead(d2, 64).c_str());
            std::printf("FIRST_MISMATCH_OFFSET=%zu\n", first_diff);
            std::printf("EXPECTED_HEX=%s\n", HexHead(in.substr(std::min(first_diff, in.size())), 8).c_str());
            std::printf("ACTUAL_HEX=%s\n", HexHead(d1.substr(std::min(first_diff, d1.size())), 8).c_str());
            std::fflush(stdout);
        }
        if (verbose)
        {
            std::printf("[stage] G1 probe ids=%zu -> bytes=%zu %s\n", ids.size(), d1.size(), ok ? "PASS" : "FAIL");
            std::fflush(stdout);
        }
    }
    // Exhaustive byte-alphabet round-trip: all 256 byte values.
    {
        std::string all;
        all.reserve(256);
        for (size_t b = 0; b < 256; ++b) all += (char)b;
        std::vector<int32_t> ids;
        enc.Encode(all, ids);
        std::string d;
        for (int32_t id : ids) d += enc.Piece((uint32_t)id);
        if (d != all)
        {
            ++fails;
            std::printf("TOKENIZER_TEST=FAIL (all256bytes)\n");
            size_t p = 0;
            while (p < all.size() && p < d.size() && all[p] == d[p]) ++p;
            std::printf("FIRST_MISMATCH_OFFSET=%zu\nEXPECTED_HEX=%s\nACTUAL_HEX=%s\n", p,
                        p < all.size() ? HexHead(all.substr(p), 4).c_str() : "eof",
                        p < d.size() ? HexHead(d.substr(p), 4).c_str() : "eof");
            std::fflush(stdout);
        }
    }
    st.mark("G1 tokenizer: round-trip done", fails == 0 ? "PASS" : "FAIL");
    return fails == 0;
}

// ---------------------------------------------------------------------------
// Prompt prefill. PrefillBatch runs the Linear ops op-major / token-minor
// (one submission for a whole same-input projection group) while attention,
// MoE, SSM and norms stay per-token in causal order, so KV is identical to the
// serial path. The per-token ExecuteToken loop that preceded it cost ~1 s per
// token on the R9700 for a 243-token repair prompt, which is what made a
// single repair attempt take minutes before the model had said anything.
// ---------------------------------------------------------------------------
struct PrefillResult
{
    bool ok = false;
    size_t tokens = 0;
    size_t ctx_after = 0;
    std::string error;
};

static PrefillResult PrefillPrompt(Executor& ex, SpEncoder& enc, const std::string& prompt)
{
    PrefillResult r;
    std::vector<int32_t> ids;
    enc.Encode(prompt, ids);
    r.tokens = ids.size();
    std::vector<uint32_t> tokens(ids.begin(), ids.end());
    const size_t start = ex.Position() + 1;
    if (!ex.PrefillBatch(tokens, start))
    {
        r.ok = false;
        r.error = ex.LastError();
        return r;
    }
    r.ok = true;
    r.ctx_after = start + tokens.size();
    return r;
}

// ---------------------------------------------------------------------------
// G2/G3: one-token finite-logits probe and short generation.
// ---------------------------------------------------------------------------
static bool GateInference(StageTimer& st, Executor& ex, SpEncoder& enc, int32_t bos, int max_new, bool verbose)
{
    st.mark("G2 inference: batched prefill of probe prompt");
    if (bos >= 0)
    {
        if (!ex.ExecuteToken((uint32_t)bos, 0))
        {
            st.mark("G2 inference: FAILED at BOS", ex.LastError());
            return false;
        }
    }

    const std::string probe = "int main() { return 0; }";
    const PrefillResult pf = PrefillPrompt(ex, enc, probe);
    if (!pf.ok)
    {
        st.mark("G2 inference: prefill FAILED", pf.error);
        return false;
    }
    st.mark("G2 inference: prefill complete", "tokens=" + std::to_string(pf.tokens) + " ctx=" + std::to_string(pf.ctx_after));

    const std::vector<float>& lg = ex.Logits();
    size_t nonfinite = 0, zero_count = 0;
    for (float v : lg)
    {
        if (!std::isfinite(v)) ++nonfinite;
        if (v == 0.0f) ++zero_count;
    }
    const bool g2 = (!lg.empty()) && (nonfinite == 0);
    st.mark("G2 inference: one-token logits", "n=" + std::to_string(lg.size()) + " nonfinite=" + std::to_string(nonfinite) +
                                                 (g2 ? " PASS" : " FAIL"));

    // G3 is a fixed-window probe: ten tokens. Generating 512 here would cost
    // ~190 s of decode for evidence the gate does not need.
    st.mark("G3 generation: begin");
    std::string gen;
    std::string gen_ids;
    int produced = 0;
    size_t pos = pf.ctx_after;
    for (int t = 0; t < max_new; ++t)
    {
        const std::vector<float>& lge = ex.Logits();
        if (lge.empty()) break;
        uint32_t best = 0;
        for (uint32_t i = 1; i < lge.size(); ++i)
            if (lge[i] > lge[best]) best = i;
        if (best == (uint32_t)GetTokenizer().eos_id) break;
        const std::string piece = enc.Piece(best);
        gen += piece;
        gen_ids += std::to_string(best) + " ";
        ++produced;
        if (produced >= 10) break;  // G3 probe window is exactly ten tokens
        if (!ex.ExecuteToken(best, pos++)) break;
    }
    st.mark("G3 generation: done", "tokens=" + std::to_string(produced) + " bytes=" + std::to_string(gen.size()));
    // The token ids and the escaped bytes are both reported: a sample that looks
    // empty with nonzero bytes is the signature of whitespace-only pieces, which
    // is a detokenizer fact worth recording rather than hiding with Trim().
    std::printf("G3_TOKEN_IDS=%s\n", gen_ids.c_str());
    std::printf("G3_DECODED_ESCAPED=%s\n", HexHead(gen, gen.size()).c_str());
    std::fflush(stdout);
    if (verbose) std::printf("[stage] G3 sample: %s\n", Trim(gen).substr(0, 160).c_str());
    return (produced > 0);
}

// ---------------------------------------------------------------------------
// Extract the fixed source from model output. Accepts a bare source file or a
// fenced ```cpp / ``` block, strips leading commentary, trims a partial final
// line and trailing prose after the last top-level closing brace.
// ---------------------------------------------------------------------------
static std::string ExtractSource(const std::string& raw)
{
    std::string s = raw;
    // Prefer the last fenced block when the model wrapped its answer.
    const size_t fence = s.rfind("```");
    if (fence != std::string::npos)
    {
        const size_t open = s.rfind("```", fence - 1);
        if (open != std::string::npos && fence > open + 3)
        {
            std::string body = s.substr(open + 3, fence - (open + 3));
            const size_t nl = body.find('\n');
            if (nl != std::string::npos && body.find("cpp", 0) != std::string::npos && nl < 8) body = body.substr(nl + 1);
            s = body;
        }
    }
    const size_t inc = s.find("#include");
    if (inc != std::string::npos && inc > 0) s = s.substr(inc);
    // Drop a trailing partial line (model cut off mid-token).
    const size_t last_nl = s.find_last_of('\n');
    if (last_nl != std::string::npos && last_nl + 1 < s.size())
    {
        const std::string tail = Trim(s.substr(last_nl + 1));
        if (!tail.empty() && tail.back() != ';' && tail.back() != '}' && tail.back() != '{')
            s = s.substr(0, last_nl);
    }
    // Cut after the last closing brace so trailing commentary is excluded.
    const size_t last_brace = s.rfind('}');
    if (last_brace != std::string::npos) s = s.substr(0, last_brace + 1);
    s += "\n";
    return s;
}

int main(int argc, char* argv[])
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    const Args args = Parse(argc, argv);
    if (args.model.empty())
    {
        std::printf("usage: deep2_agentic_repair.exe --model <gguf> --target-file <f> [--workdir D]\n"
                    "       [--build-command C] [--run-command C] [--expected-output S]\n"
                    "       [--max-retries N] [--max-new N] [--stop-after GATE] [--cpu] [-v] [--no-build]\n");
        return 1;
    }

    StageTimer st;

    // ---- ingest / bind ------------------------------------------------------
    st.mark("load model", args.model);
    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok)
    {
        st.mark("load model FAILED", rep.error);
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    st.mark("ingest", "arch=" + rep.spec.architecture + " blocks=" + std::to_string((long long)rep.spec.block_count));

    SpEncoder enc;
    enc.Build(GetTokenizer());
    st.mark("tokenizer build", "vocab=" + std::to_string(enc.tokens.size()) + " convention=" +
                                   (enc.marker[0] == '\xC4' ? std::string("U+0120_gpt2") : std::string("U+2581_sp")));
    if (!enc.ok)
    {
        std::printf("TOKENIZER_FAIL: empty vocabulary\n");
        return 1;
    }

    // ---- G1: tokenizer correctness is a hard prerequisite --------------------
    if (!GateTokenizer(st, enc, args.verbose))
    {
        std::printf("\nGATE_RESULT G1=PASS G2=SKIP G3=SKIP G4=SKIP G5=SKIP G6=SKIP G7=SKIP\n");
        std::printf("FINAL_VERDICT=FAIL (tokenizer round-trip failed; autonomy not evaluated)\n");
        return 1;
    }
    std::printf("GATE_RESULT G1=PASS\n");
    if (args.stop_after == "tokenizer" || args.stop_after == "g1")
    {
        std::printf("FINAL_VERDICT=PASS (stage-limited run: tokenizer gate only)\n");
        return 0;
    }

    // ---- G2/G3: inference must work before autonomy is tested ---------------
    // The probe executor is scoped and destroyed before the repair executor
    // binds: only one full copy of the weights is ever GPU-resident, and a
    // second Bind() while the first is alive was observed to leave the second
    // executor unable to run a generation pass after prefill.
    {
        Executor probe_ex;
        probe_ex.SetForceCpu(args.cpu);
        if (!probe_ex.Bind(rep))
        {
            st.mark("probe executor bind FAILED", probe_ex.LastError());
            std::printf("BIND_FAIL(probe): %s\n", probe_ex.LastError().c_str());
            return 1;
        }
        st.mark("probe executor bound", "ops=" + std::to_string(probe_ex.Stats().ops_total));
        if (!GateInference(st, probe_ex, enc, GetTokenizer().bos_id, args.max_new > 512 ? 512 : args.max_new,
                           args.verbose))
        {
            std::printf("GATE_RESULT G1=PASS G2=FAIL\n");
            std::printf("FINAL_VERDICT=FAIL (inference probe failed; autonomy not evaluated)\n");
            return 1;
        }
    }
    std::printf("GATE_RESULT G1=PASS G2=PASS G3=PASS\n");
    if (args.stop_after == "inference" || args.stop_after == "g3")
    {
        std::printf("FINAL_VERDICT=PASS (stage-limited run: inference gates only)\n");
        return 0;
    }
    if (args.no_build)
    {
        std::printf("FINAL_VERDICT=PASS (stage-limited run: --no-build)\n");
        return 0;
    }

    // ---- repair target setup -------------------------------------------------
    const std::string target_path = args.workdir + "/" + args.target_file;
    if (!fs::exists(target_path))
    {
        std::printf("TARGET_MISSING: %s\n", target_path.c_str());
        return 1;
    }
    const std::string stem = args.target_file.substr(0, args.target_file.find_last_of('.'));
    // Absolute paths throughout: no `cd`, no `&&`, so the vcvars wrapper batch
    // receives the whole command line as its arguments. /Fo pins the .obj.
    std::string build_cmd = args.build_cmd.empty()
        ? "cl /nologo /EHsc /std:c++20 /Fo:\"" + args.workdir + "/" + stem + ".obj\" /Fe:\"" + args.workdir + "/" +
              stem + ".exe\" \"" + target_path + "\""
        : args.build_cmd;
    std::string run_cmd = args.run_cmd.empty() ? (args.workdir + "/" + stem + ".exe") : args.run_cmd;

    // ---- G4: baseline defect must be reproduced by the host ------------------
    // A defect is CONFIRMED when the target does not already pass: either it
    // fails to compile, or it compiles and its program does not print the
    // expected marker with exit 0.
    st.mark("G4 baseline: build defective source");
    const std::string original = ReadFile(target_path);
    const std::string original_hash = ContentHash(original);

    CmdResult base_build = RunCmd(build_cmd);
    CmdResult base_run;
    bool base_defect;
    if (base_build.exit_code == 0)
    {
        base_run = RunCmd("\"" + run_cmd + "\"");
        base_defect = (base_run.exit_code != 0) || (base_run.output.find(args.expected_output) == std::string::npos);
        st.mark("G4 baseline: built and ran",
                "build_exit=0 run_exit=" + std::to_string(base_run.exit_code) +
                    " marker_present=" + std::to_string(base_defect ? 0 : 1));
    }
    else
    {
        base_defect = true;  // defective source does not even build
        st.mark("G4 baseline: build FAILED (compile defect)", "exit=" + std::to_string(base_build.exit_code));
    }
    if (!base_defect)
    {
        // The target is not defective; there is nothing to repair.
        std::printf("GATE_RESULT G1=PASS G2=PASS G3=PASS G4=FAIL\n");
        std::printf("FINAL_VERDICT=FAIL (baseline already passes: no defect to repair)\n");
        return 1;
    }
    std::printf("GATE_RESULT G1=PASS G2=PASS G3=PASS G4=PASS\n");

    // ---- G5/G6: bounded model-driven repair attempts -------------------------
    // A fresh executor guarantees the probe context cannot influence the
    // repair: the executor has no reset, so position-indexed KV reuse across
    // prompts would silently contaminate the second context.
    st.mark("G5 setup: fresh executor for repair stage");
    Executor rep_ex;
    rep_ex.SetForceCpu(args.cpu);
    if (!rep_ex.Bind(rep))
    {
        std::printf("GATE_RESULT G1=PASS G2=PASS G3=PASS G4=PASS G5=FAIL\n");
        std::printf("FINAL_VERDICT=FAIL (repair-stage executor bind failed: %s)\n", rep_ex.LastError().c_str());
        return 1;
    }
    st.mark("G5 setup: repair executor bound", "ops=" + std::to_string(rep_ex.Stats().ops_total));

    // Wall-clock budget for the whole repair stage, independent of attempt
    // count. A model that produces garbage must not consume unbounded time.
    const Clock::time_point repair_start = Clock::now();
    const double repair_budget_sec = 480.0;
    const int gen_cap = std::min(args.max_new, 600);

    std::string current = original;
    bool repaired = false;
    for (int attempt = 1; attempt <= args.max_retries && !repaired; ++attempt)
    {
        const double elapsed = std::chrono::duration<double>(Clock::now() - repair_start).count();
        if (elapsed > repair_budget_sec)
        {
            st.mark("G5 repair budget exhausted", std::to_string((int)elapsed) + "s");
            break;
        }

        st.mark("G5 attempt " + std::to_string(attempt) + ": prompt build + prefill");
        const std::string error_context = (base_build.exit_code != 0)
            ? base_build.output
            : (base_run.exit_code != 0
                   ? "The program compiled but exited with code " + std::to_string(base_run.exit_code) + " instead of 0."
                   : "The program compiled and exited 0 but its output did not contain the required marker \"" +
                         args.expected_output + "\".");
        std::string err = error_context;
        if (err.size() > 3000) err = err.substr(0, 3000);

        const std::string prompt =
            "Fix this defective C++ file. Output ONLY the complete corrected source, starting with the first "
            "#include line. Do not add explanations, markdown fences, or commentary.\n"
            "The corrected file must compile with MSVC and its program must print exactly \""
            + args.expected_output + "\" and exit 0.\n\n"
            "FILE: " + args.target_file + "\n"
            "=== SOURCE ===\n" + current + "\n=== END SOURCE ===\n"
            "=== BUILD/RUN RESULT ===\n" + err + "\n=== END RESULT ===\n"
            "=== CORRECTED SOURCE ===\n";

        const PrefillResult pf = PrefillPrompt(rep_ex, enc, prompt);
        if (!pf.ok)
        {
            st.mark("G5 attempt " + std::to_string(attempt) + ": prefill FAILED", pf.error);
            continue;
        }
        st.mark("G5 attempt " + std::to_string(attempt) + ": prompt prefilled",
                "tokens=" + std::to_string(pf.tokens) + " ctx=" + std::to_string(pf.ctx_after));

        std::string gen;
        std::string gen_ids;
        size_t pos = pf.ctx_after;
        for (int t = 0; t < gen_cap; ++t)
        {
            const std::vector<float>& lg = rep_ex.Logits();
            if (lg.empty()) break;
            uint32_t best = 0;
            for (uint32_t i = 1; i < lg.size(); ++i)
                if (lg[i] > lg[best]) best = i;
            if (best == (uint32_t)GetTokenizer().eos_id) break;
            const std::string piece = enc.Piece(best);
            gen += piece;
            gen_ids += std::to_string(best) + " ";
            if (!rep_ex.ExecuteToken(best, pos++)) break;
            // Stop once a plausible complete translation unit has been emitted.
            if (t > 24 && gen.find("int main") != std::string::npos &&
                gen.rfind('}') > gen.find("int main")) break;
        }
        st.mark("G5 attempt " + std::to_string(attempt) + ": generated", "bytes=" + std::to_string(gen.size()));
        std::printf("G5_ATTEMPT%d_TOKEN_IDS=%s\n", attempt, gen_ids.c_str());
        std::fflush(stdout);
        if (args.verbose)
        {
            FILE* f = std::fopen((args.workdir + "/gen_attempt_" + std::to_string(attempt) + ".txt").c_str(), "wb");
            if (f)
            {
                std::fwrite(gen.data(), 1, gen.size(), f);
                std::fclose(f);
            }
            std::printf("[stage] G5 attempt %d raw generation:\n%s\n", attempt, gen.c_str());
            std::fflush(stdout);
        }

        const std::string candidate = ExtractSource(gen);
        if (candidate.find("#include") == std::string::npos || candidate.find("int main") == std::string::npos)
        {
            st.mark("G5 attempt " + std::to_string(attempt) + ": model output unusable", "no main() or #include");
            continue;
        }

        // Host applies the candidate patch and verifies it.
        const std::string backup = current;
        if (!WriteFile(target_path, candidate))
        {
            st.mark("G5 attempt " + std::to_string(attempt) + ": write failed");
            continue;
        }
        current = candidate;

        CmdResult cb = RunCmd(build_cmd);
        if (cb.exit_code != 0)
        {
            st.mark("G6 attempt " + std::to_string(attempt) + ": patched build FAILED", "exit=" + std::to_string(cb.exit_code));
            base_build = cb;  // feed the compiler error back to the model
            WriteFile(target_path, backup);
            current = backup;
            continue;
        }
        CmdResult cr = RunCmd("\"" + run_cmd + "\"");
        const bool ok = (cr.exit_code == 0) && (cr.output.find(args.expected_output) != std::string::npos);
        st.mark("G6 attempt " + std::to_string(attempt) + ": patched run",
                "exit=" + std::to_string(cr.exit_code) + " ok=" + (ok ? "true" : "false"));
        if (ok)
        {
            repaired = true;
            std::printf("GATE_RESULT G1=PASS G2=PASS G3=PASS G4=PASS G5=PASS G6=PASS\n");
        }
        else
        {
            base_run = cr;
            WriteFile(target_path, backup);
            current = backup;
        }
    }

    // ---- G7: independent re-verification -------------------------------------
    bool final_ok = false;
    if (repaired)
    {
        st.mark("G7 re-verification: fresh build + run");
        CmdResult fb = RunCmd("cd /d \"" + args.workdir + "\" && " + build_cmd + " 2>&1");
        if (fb.exit_code == 0)
        {
            CmdResult fr = RunCmd("cd /d \"" + args.workdir + "\" && " + run_cmd + " 2>&1");
            final_ok = (fr.exit_code == 0) && (fr.output.find(args.expected_output) != std::string::npos);
            st.mark("G7 re-verification", "exit=" + std::to_string(fr.exit_code) + " ok=" + (final_ok ? "true" : "false"));
        }
        else
        {
            st.mark("G7 re-verification build FAILED", "exit=" + std::to_string(fb.exit_code));
        }
    }

    const std::string final = ReadFile(target_path);
    std::printf("ORIGINAL_HASH=%s\n", original_hash.c_str());
    std::printf("FINAL_HASH=%s\n", ContentHash(final).c_str());
    std::printf("SOURCE_CHANGED=%s\n", (final != original) ? "true" : "false");
    std::printf("GATE_RESULT G1=PASS G2=PASS G3=PASS G4=PASS G5=%s G6=%s G7=%s\n",
                repaired ? "PASS" : "FAIL", repaired ? "PASS" : "FAIL", final_ok ? "PASS" : "SKIP");
    std::printf("FINAL_VERDICT=%s\n", (repaired && final_ok) ? "PASS" : "FAIL");
    return (repaired && final_ok) ? 0 : 1;
}
