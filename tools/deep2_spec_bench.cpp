// ============================================================================
// deep2_spec_bench.cpp  --  RAWRXD_DEEP2_SPEC_VERIFY_001 benchmark + gates
// ----------------------------------------------------------------------------
// Measures Deep2 native batched speculative verification against the serial
// greedy decode path on a REAL GGUF, with the acceptance rate reported
// SEPARATELY for code and prose workloads (the EXL3/RDNA4 reference reports
// very different per-workload rates, so an averaged number proves nothing).
//
// Gates (fail-closed, NOT_RUN when a gate cannot apply):
//   [G1] PARITY      the speculative token stream must be IDENTICAL, token
//                    for token, to the serial greedy stream. Greedy
//                    speculative decoding is a deterministic function of the
//                    verifier's own argmax at every position, so any
//                    divergence is a real defect (bad KV repair, numeric
//                    drift), not noise.
//   [G2] FINITE      no non-finite logits on either arm.
//   [G3] ACCEPTANCE  per-workload draft acceptance, tokens per round, bonus
//                    and replacement counts - reported, not gated.
//   [G4] THROUGHPUT  serial TPS vs speculative TPS, wall-clock, decode loop
//                    only (prefill excluded from both). Reported, not gated:
//                    this benchmark's job is the honest number, and the
//                    parity gate above is what makes the number trustworthy.
//
// Under --force-cpu the batched verify pass refuses by design (the serial CPU
// path is the reference), so the speculative arm and every gate that depends
// on it report NOT_RUN; nothing is claimed that was not measured.
//
// Usage:
//   deep2_spec_bench.exe --model <gguf> [--workload code|prose|both]
//                         [--tokens N] [--gamma N] [--ngram N]
//                         [--draft prompt|repeat] [--prompt "..."]
//                         [--force-cpu] [--no-bos] [--evidence dir]
// ============================================================================

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "deep2_speculative.hpp"
#include "quant_dot_dispatch.hpp"
#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "sp_encoder.hpp"

namespace RG = RawrXD::Deep2::RuntimeGraph;
namespace UG = RawrXD::Deep2::Universal;

namespace {

// ---------------------------------------------------------------------------
// Engine symbols this binary links against but that belong to subsystems it
// does not drive (the residency trace C interface, and the MASM FP16 GEMV
// that QuantKernelRegistry references at link time). Same definitions as
// deep2_pipeline.cpp, so both binaries behave identically. The FP16 GEMV is a
// real scalar host implementation, used only when an FP16 tensor is
// dispatched; it is never reported as the MASM kernel.
// ---------------------------------------------------------------------------
extern "C" {
    struct ResidencyEvent { uint32_t dummy; };
    int TraceInit(const char*) { return 1; }
    void TraceShutdown(void) {}
    ResidencyEvent* TraceBegin(uint32_t, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t) {
        return nullptr;
    }
    void TraceSetDestination(ResidencyEvent*, uint32_t, uint64_t, uint64_t, uint64_t,
                             uint32_t, uint32_t) {}
    void TraceComplete(ResidencyEvent*, uint64_t, uint64_t, int) {}
    void TraceFlush(void) {}

    // IEEE-754 half -> float, so the host fallback is numerically correct.
    inline float HalfToFloat(uint16_t h) {
        const uint32_t sign = static_cast<uint32_t>(h & 0x8000u) << 16;
        uint32_t exp = (h >> 10) & 0x1Fu;
        uint32_t man = h & 0x3FFu;
        uint32_t bits;
        if (exp == 0) {
            if (man == 0) { bits = sign; }
            else {
                exp = 127 - 15 + 1;
                while ((man & 0x400u) == 0) { man <<= 1; --exp; }
                man &= 0x3FF;
                bits = sign | (exp << 23) | (man << 13);
            }
        } else if (exp == 0x1F) {
            bits = sign | 0x7F800000u | (man << 13);
        } else {
            bits = sign | ((exp + 127 - 15) << 23) | (man << 13);
        }
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        return f;
    }

    // weights: rows x cols of IEEE half; y[i] = sum_j w[i*cols+j] * x[j].
    void Deep2_FP16_GEMV(const void* weights, const float* input, float* output,
                         unsigned int rows, unsigned int cols) {
        if (!weights || !input || !output) return;
        const uint16_t* w = static_cast<const uint16_t*>(weights);
        for (unsigned int i = 0; i < rows; ++i) {
            float acc = 0.0f;
            const uint16_t* row = w + static_cast<size_t>(i) * cols;
            for (unsigned int j = 0; j < cols; ++j) acc += HalfToFloat(row[j]) * input[j];
            output[i] = acc;
        }
    }
}

int g_pass = 0, g_fail = 0, g_na = 0;
std::vector<std::string> g_receipt;

void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) ++g_pass; else ++g_fail;
    g_receipt.push_back(std::string(ok ? "PASS  " : "FAIL  ") + what);
}
void Skip(const char* what, const char* why) {
    std::printf("  [N/A] %s -- %s\n", what, why);
    ++g_na;
    g_receipt.push_back(std::string("N/A   ") + what + " -- " + why);
}
void Info(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    std::printf("      %s\n", buf);
    g_receipt.push_back(std::string("      ") + buf);
}
void Section(const char* s) {
    std::printf("\n--- %s ---\n", s);
    g_receipt.push_back(std::string("== ") + s);
}
void Section(const std::string& s) { Section(s.c_str()); }

uint32_t ArgmaxOf(const std::vector<float>& lg) {
    uint32_t a = 0;
    for (size_t i = 1; i < lg.size(); ++i)
        if (lg[i] > lg[a]) a = (uint32_t)i;
    return a;
}

// ---------------------------------------------------------------------------
// Workload prompts. Both are deliberately repetitive: prompt-lookup drafting
// only proposes tokens that followed an earlier occurrence of the same
// n-gram, so the prompt decides how much drafting can do at all. The code
// prompt mirrors the reference's code-generation case; the prose prompt is
// ordinary English.
// ---------------------------------------------------------------------------
const char* kCodePrompt =
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "def sub(a, b):\n"
    "    return a - b\n"
    "\n"
    "def mul(a, b):\n"
    "    return a * b\n"
    "\n"
    "def div(a, b):\n"
    "    return a / b\n"
    "\n"
    "def mod(a, b):\n";

const char* kProsePrompt =
    "The morning was quiet and the streets were empty. The shop on the corner "
    "was still closed, and the lights in the houses were off one by one. The "
    "city woke slowly: the buses came first, then the cars, then the people. "
    "The morning was quiet and the streets were empty, and the day began the "
    "way the day before had begun, the way the next day would begin again. ";

struct Options {
    std::string model;
    std::string workload = "both";
    int tokens = 40;
    size_t gamma = 4;
    size_t ngram = 3;
    std::string draft = "prompt";
    std::string prompt;
    bool force_cpu = false;
    bool no_bos = false;
    std::string evidence = "evidence/deep2_spec_verify";
};

bool ParseArgs(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if (a == "--model") o.model = next();
        else if (a == "--workload") o.workload = next();
        else if (a == "--tokens") o.tokens = std::atoi(next().c_str());
        else if (a == "--gamma") o.gamma = (size_t)std::strtoull(next().c_str(), nullptr, 10);
        else if (a == "--ngram") o.ngram = (size_t)std::strtoull(next().c_str(), nullptr, 10);
        else if (a == "--draft") o.draft = next();
        else if (a == "--prompt") o.prompt = next();
        else if (a == "--force-cpu") o.force_cpu = true;
        else if (a == "--no-bos") o.no_bos = true;
        else if (a == "--evidence") o.evidence = next();
        else if (a == "--help" || a == "-h") {
            std::printf("usage: deep2_spec_bench.exe --model <gguf> [--workload code|prose|both]\n"
                        "   [--tokens N] [--gamma N] [--ngram N] [--draft prompt|repeat]\n"
                        "   [--prompt \"...\"] [--force-cpu] [--no-bos] [--evidence dir]\n");
            return false;
        } else {
            std::printf("unknown argument: %s\n", a.c_str());
            return false;
        }
    }
    if (o.model.empty()) { std::printf("--model is required\n"); return false; }
    if (o.tokens < 1) o.tokens = 1;
    if (o.workload != "code" && o.workload != "prose" && o.workload != "both") {
        std::printf("--workload must be code, prose, or both\n");
        return false;
    }
    if (!o.prompt.empty() && o.workload == "both") {
        std::printf("--prompt with --workload both is ambiguous; pick one workload\n");
        return false;
    }
    return true;
}

// Encode the prompt with the model's own tokenizer, optionally with BOS.
bool EncodePrompt(const UG::Tokenizer& tk, deep2tools::SpEncoder& enc,
                  const std::string& prompt, bool no_bos,
                  std::vector<uint32_t>& out, std::string& err) {
    std::vector<int32_t> ids;
    if (!enc.Encode(prompt, ids)) { err = "prompt encode failed"; return false; }
    out.clear();
    if (!no_bos && tk.bos_id >= 0) out.push_back((uint32_t)tk.bos_id);
    for (int32_t id : ids) out.push_back((uint32_t)id);
    if (out.empty()) { err = "prompt encoded to zero tokens"; return false; }
    return true;
}

struct ArmResult {
    bool ran = false;
    std::string not_run_reason;
    std::vector<uint32_t> stream;
    double decode_ms = 0.0;
    double prefill_ms = 0.0;
    size_t nonfinite = 0;
    uint64_t gpu_calls = 0, cpu_calls = 0;
    Deep2::WorkloadStats spec_stats;   // spec arm only
};

// Serial greedy decode arm. Consumes every token except the last emitted one
// (its forward pass would produce a token nobody reads), which is the minimum
// work the serial path needs to produce N tokens.
bool RunSerialArm(RG::Executor& exe, const std::vector<uint32_t>& prompt_toks,
                  int n, ArmResult& out, std::string& err) {
    out.ran = true;
    auto t0 = std::chrono::steady_clock::now();
    if (!exe.PrefillBatch(prompt_toks, 0)) {
        err = "serial prefill failed: " + exe.LastError();
        return false;
    }
    out.prefill_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    size_t pos = prompt_toks.size();
    auto t1 = std::chrono::steady_clock::now();
    for (int i = 0; i < n; ++i) {
        const std::vector<float>& lg = exe.Logits();
        if (lg.empty()) { err = "serial decode: empty logits"; return false; }
        const uint32_t t = ArgmaxOf(lg);
        out.stream.push_back(t);
        if (i + 1 < n) {
            if (!exe.ExecuteToken(t, pos)) {
                err = "serial decode: ExecuteToken failed: " + exe.LastError();
                return false;
            }
            ++pos;
        }
    }
    out.decode_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t1).count();
    out.nonfinite = exe.NonFiniteLogits();
    const RG::BindStats& st = exe.Stats();
    out.gpu_calls = st.gpu_calls;
    out.cpu_calls = st.cpu_calls;
    return true;
}

// Speculative arm. Identical prefill, then the verifier loop. The kernel of
// the loop is Deep2::SpeculativeVerifier::Step; the harness owns the token
// stream so the parity gate can compare it against the serial arm.
bool RunSpecArm(RG::Executor& exe, const std::vector<uint32_t>& prompt_toks,
                int n, const Deep2::SpeculativeConfig& cfg, ArmResult& out,
                std::string& err) {
    out.ran = true;
    auto t0 = std::chrono::steady_clock::now();
    if (!exe.PrefillBatch(prompt_toks, 0)) {
        err = "spec prefill failed: " + exe.LastError();
        return false;
    }
    out.prefill_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t0).count();

    Deep2::SpeculativeVerifier verifier(exe, cfg);
    std::vector<uint32_t> ctx = prompt_toks;
    auto t1 = std::chrono::steady_clock::now();
    while ((int)out.stream.size() < n) {
        std::vector<uint32_t> emitted;
        bool speculated = false;
        std::string serr;
        if (!verifier.Step(ctx, emitted, speculated, serr)) {
            err = "spec step failed at stream position " +
                  std::to_string(out.stream.size()) + ": " + serr;
            return false;
        }
        for (uint32_t t : emitted) {
            if ((int)out.stream.size() >= n) break;
            out.stream.push_back(t);
        }
        for (uint32_t t : emitted) ctx.push_back(t);
    }
    out.decode_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - t1).count();
    out.nonfinite = exe.NonFiniteLogits();
    const RG::BindStats& st = exe.Stats();
    out.gpu_calls = st.gpu_calls;
    out.cpu_calls = st.cpu_calls;
    out.spec_stats = verifier.Stats().Get(cfg.workload);
    return true;
}

void WriteJsonReceipt(const std::string& path, const std::string& model,
                      const std::string& sha, const Options& o,
                      const std::vector<std::string>& lines) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return;
    std::fprintf(f, "{\n");
    std::fprintf(f, "  \"tool\": \"deep2_spec_bench\",\n");
    std::fprintf(f, "  \"tag\": \"RAWRXD_DEEP2_SPEC_VERIFY_001\",\n");
    std::fprintf(f, "  \"model\": \"%s\",\n", model.c_str());
    std::fprintf(f, "  \"model_sha256\": \"%s\",\n", sha.c_str());
    std::fprintf(f, "  \"gamma\": %zu,\n", o.gamma);
    std::fprintf(f, "  \"ngram\": %zu,\n", o.ngram);
    std::fprintf(f, "  \"draft_policy\": \"%s\",\n", o.draft.c_str());
    std::fprintf(f, "  \"tokens\": %d,\n", o.tokens);
    std::fprintf(f, "  \"force_cpu\": %s,\n", o.force_cpu ? "true" : "false");
    std::fprintf(f, "  \"lines\": [\n");
    for (size_t i = 0; i < lines.size(); ++i) {
        std::string esc = lines[i];
        for (size_t p = 0; (p = esc.find('"', p)) != std::string::npos; p += 2)
            esc.replace(p, 1, "\\\"");
        std::fprintf(f, "    \"%s\"%s\n", esc.c_str(), (i + 1 < lines.size()) ? "," : "");
    }
    std::fprintf(f, "  ]\n}\n");
    std::fclose(f);
}

} // namespace

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    Options opt;
    if (!ParseArgs(argc, argv, opt)) return 2;

#ifdef _WIN32
    CreateDirectoryA(opt.evidence.c_str(), nullptr);
#endif

    std::printf("=================================================================\n");
    std::printf(" Deep2 SPECULATIVE VERIFICATION BENCH  (RAWRXD_DEEP2_SPEC_VERIFY_001)\n");
    std::printf(" serial greedy vs batched verify, code/prose acceptance split\n");
    std::printf("=================================================================\n");
    Info("model=%s", opt.model.c_str());

    // -----------------------------------------------------------------------
    // Real model, real provenance.
    // -----------------------------------------------------------------------
    Section("[P] REAL MODEL (universal GGUF ingest)");
    const UG::IngestReport& rep = UG::Ingest(opt.model, /*want_weights=*/false);
    if (!rep.ok) {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    const UG::Provenance& prov = UG::GetProvenance();
    const UG::Tokenizer& tk = UG::GetTokenizer();
    Info("arch=%s name=%s sha256=%s", rep.spec.architecture.c_str(),
         rep.spec.model_name.c_str(), prov.sha256.c_str());
    Info("layers=%llu embd=%llu heads=%llu vocab=%llu ctx=%llu",
         (unsigned long long)rep.spec.block_count, (unsigned long long)rep.spec.embd,
         (unsigned long long)rep.spec.heads, (unsigned long long)rep.spec.vocab,
         (unsigned long long)rep.spec.context_length);
    if (!tk.ok) {
        std::printf("TOKENIZER_FAIL: model ships no usable tokenizer\n");
        return 1;
    }
    deep2tools::SpEncoder enc;
    enc.Build(tk.tokens, tk.merges);
    if (!enc.ok) {
        std::printf("TOKENIZER_FAIL: encoder build failed\n");
        return 1;
    }

    if (opt.force_cpu) {
        RawrXD::Deep2::QuantDot::SetForceCpu(true);
        Info("force-cpu: serial CPU path is the reference; batched verify will refuse");
    }

    std::vector<Deep2::WorkloadKind> workloads;
    if (opt.workload == "code" || opt.workload == "both")
        workloads.push_back(Deep2::WorkloadKind::Code);
    if (opt.workload == "prose" || opt.workload == "both")
        workloads.push_back(Deep2::WorkloadKind::Prose);

    bool any_spec_ran = false;

    for (Deep2::WorkloadKind wl : workloads) {
        const char* wl_name = Deep2::WorkloadName(wl);
        Section(std::string("[") + wl_name + "] workload");

        const std::string prompt = opt.prompt.empty()
            ? std::string(wl == Deep2::WorkloadKind::Code ? kCodePrompt : kProsePrompt)
            : opt.prompt;
        std::vector<uint32_t> prompt_toks;
        std::string perr;
        if (!EncodePrompt(tk, enc, prompt, opt.no_bos, prompt_toks, perr)) {
            std::printf("PROMPT_FAIL: %s\n", perr.c_str());
            return 1;
        }
        Info("prompt: %zu tokens, generate=%d, gamma=%zu, ngram=%zu, draft=%s",
             prompt_toks.size(), opt.tokens, opt.gamma, opt.ngram, opt.draft.c_str());

        // ---- serial arm -----------------------------------------------------
        ArmResult serial;
        {
            RG::Executor exe;
            if (opt.force_cpu) exe.SetForceCpu(true);
            if (!exe.Bind(rep)) {
                std::printf("SERIAL_ARM_BIND_FAIL: %s\n", exe.LastError().c_str());
                return 1;
            }
            if (exe.HasSsm())
                Info("graph contains recurrent (SSM) blocks: serial arm unaffected");
            std::string err;
            // Under force-cpu the batched prefill refuses; drive the prompt
            // through the same serial ExecuteToken the decode loop uses.
            if (opt.force_cpu) {
                auto t0 = std::chrono::steady_clock::now();
                for (size_t i = 0; i < prompt_toks.size(); ++i) {
                    if (!exe.ExecuteToken(prompt_toks[i], i)) {
                        std::printf("SERIAL_ARM_PREFILL_FAIL: %s\n", exe.LastError().c_str());
                        return 1;
                    }
                }
                serial.prefill_ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t0).count();
                serial.ran = true;
                size_t pos = prompt_toks.size();
                auto t1 = std::chrono::steady_clock::now();
                for (int i = 0; i < opt.tokens; ++i) {
                    const std::vector<float>& lg = exe.Logits();
                    if (lg.empty()) { std::printf("SERIAL_ARM_FAIL: empty logits\n"); return 1; }
                    const uint32_t t = ArgmaxOf(lg);
                    serial.stream.push_back(t);
                    if (i + 1 < opt.tokens) {
                        if (!exe.ExecuteToken(t, pos)) {
                            std::printf("SERIAL_ARM_FAIL: %s\n", exe.LastError().c_str());
                            return 1;
                        }
                        ++pos;
                    }
                }
                serial.decode_ms = std::chrono::duration<double, std::milli>(
                    std::chrono::steady_clock::now() - t1).count();
                serial.nonfinite = exe.NonFiniteLogits();
                const RG::BindStats& st = exe.Stats();
                serial.gpu_calls = st.gpu_calls;
                serial.cpu_calls = st.cpu_calls;
            } else {
                std::string err;
                if (!RunSerialArm(exe, prompt_toks, opt.tokens, serial, err)) {
                    std::printf("SERIAL_ARM_FAIL: %s\n", err.c_str());
                    return 1;
                }
            }
            Info("serial: prefill=%.1f ms decode=%.1f ms gpu_calls=%llu cpu_calls=%llu",
                 serial.prefill_ms, serial.decode_ms,
                 (unsigned long long)serial.gpu_calls,
                 (unsigned long long)serial.cpu_calls);
        }

        // ---- speculative arm -------------------------------------------------
        ArmResult spec;
        Deep2::SpeculativeConfig cfg;
        cfg.gamma = opt.gamma;
        cfg.workload = wl;
        cfg.ngram = opt.ngram;
        cfg.policy = (opt.draft == "repeat") ? Deep2::DraftPolicy::RepeatLast
                                             : Deep2::DraftPolicy::PromptLookup;
        {
            RG::Executor exe;
            if (opt.force_cpu) exe.SetForceCpu(true);
            if (!exe.Bind(rep)) {
                std::printf("SPEC_ARM_BIND_FAIL: %s\n", exe.LastError().c_str());
                return 1;
            }
            if (exe.HasSsm()) {
                Skip("spec arm (recurrent graph)",
                     "SSM state cannot be rolled back after a rejected draft");
                spec.not_run_reason = "recurrent (SSM) graph";
            } else if (opt.force_cpu) {
                Skip("spec arm (force-cpu)",
                     "batched verify refuses under force-cpu; serial path is the reference");
                spec.not_run_reason = "force-cpu";
            } else {
                std::string err;
                if (!RunSpecArm(exe, prompt_toks, opt.tokens, cfg, spec, err)) {
                    std::printf("SPEC_ARM_FAIL: %s\n", err.c_str());
                    Check(false, "spec arm executed without failure");
                    g_receipt.push_back("SPEC_ARM_FAIL: " + err);
                    continue;
                }
                any_spec_ran = true;
            }
        }

        // ---- gates -----------------------------------------------------------
        if (spec.ran) {
            Info("spec: prefill=%.1f ms decode=%.1f ms gpu_calls=%llu cpu_calls=%llu",
                 spec.prefill_ms, spec.decode_ms,
                 (unsigned long long)spec.gpu_calls,
                 (unsigned long long)spec.cpu_calls);
            const Deep2::WorkloadStats& ws = spec.spec_stats;
            const double serial_tps =
                serial.decode_ms > 0 ? (serial.stream.size() / (serial.decode_ms * 1e-3)) : 0.0;
            const double spec_tps =
                spec.decode_ms > 0 ? (spec.stream.size() / (spec.decode_ms * 1e-3)) : 0.0;
            Info("serial TPS=%.2f  spec TPS=%.2f  speedup=%.2fx",
                 serial_tps, spec_tps, serial_tps > 0 ? spec_tps / serial_tps : 0.0);
            Info("acceptance[%s]: rounds=%llu proposed=%llu accepted=%llu rate=%.1f%% "
                 "tokens/round=%.2f bonus=%llu replacements=%llu zero_accept=%llu serial_steps=%llu "
                 "verify_batches=%llu verify_positions=%llu repairs=%llu serial_fallbacks=%llu adaptive_disabled=%d",
                 wl_name,
                 (unsigned long long)ws.rounds, (unsigned long long)ws.proposed,
                 (unsigned long long)ws.accepted, 100.0 * ws.acceptance_rate(),
                 ws.tokens_per_round(), (unsigned long long)ws.bonus,
                 (unsigned long long)ws.replacements,
                 (unsigned long long)ws.zero_accept_rounds,
                 (unsigned long long)ws.serial_steps,
                 (unsigned long long)ws.verify_batches,
                 (unsigned long long)ws.verify_positions,
                 (unsigned long long)ws.repair_steps,
                 (unsigned long long)ws.serial_fallbacks,
                 ws.adaptive_disabled ? 1 : 0);

            // G1: token-for-token equivalence.
            bool parity = serial.stream.size() == spec.stream.size();
            size_t first_diff = 0;
            if (parity) {
                for (size_t i = 0; i < serial.stream.size(); ++i) {
                    if (serial.stream[i] != spec.stream[i]) {
                        parity = false;
                        first_diff = i;
                        break;
                    }
                }
            } else {
                first_diff = std::min(serial.stream.size(), spec.stream.size());
            }
            if (!parity) {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                              "spec stream diverges from serial at index %zu (serial=%u spec=%u)",
                              first_diff,
                              first_diff < serial.stream.size() ? serial.stream[first_diff] : 0u,
                              first_diff < spec.stream.size() ? spec.stream[first_diff] : 0u);
                Check(false, buf);
            } else {
                Check(true, "spec stream identical to serial greedy stream (greedy equivalence)");
            }
            Check(spec.nonfinite == 0, "no non-finite logits on the spec arm");
        } else {
            Skip("spec stream == serial stream", spec.not_run_reason.c_str());
            Skip("no non-finite logits on the spec arm", spec.not_run_reason.c_str());
        }
        Check(serial.nonfinite == 0, "no non-finite logits on the serial arm");
    }

    // -----------------------------------------------------------------------
    // Receipt.
    // -----------------------------------------------------------------------
    Section("VERDICT");
    const char* verdict = (g_fail == 0) ? "PASS" : "FAIL";
    Info("pass=%d fail=%d na=%d spec_ran=%d", g_pass, g_fail, g_na, (int)any_spec_ran);
    std::printf("\nVERDICT=%s\n", verdict);

    const std::string txt = opt.evidence + "/SPEC_BENCH_RECEIPT.txt";
    FILE* f = std::fopen(txt.c_str(), "wb");
    if (f) {
        for (const std::string& l : g_receipt) std::fprintf(f, "%s\n", l.c_str());
        std::fprintf(f, "VERDICT=%s\n", verdict);
        std::fclose(f);
        std::printf("receipt: %s\n", txt.c_str());
    }
    WriteJsonReceipt(opt.evidence + "/spec_bench.json", opt.model, prov.sha256, opt, g_receipt);
    return g_fail == 0 ? 0 : 1;
}
