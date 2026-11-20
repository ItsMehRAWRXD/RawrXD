// deep2_strata_chat.cpp -- RAWRXD_DEEP2_STRATA_S11
//
// Headless, request-scoped Strata chat harness.
//
// Proves that the same RuntimeGraphExecutor used by deep2_strata_bench can serve
// an actual text-generation request: real GGUF ingestion, real text tokenization
// (CanonicalTokenizer), Strata expert-residency tracking, prompt prefill,
// autoregressive decode with streaming output, bounded cancellation and a
// machine-readable receipt.
//
// Request-scoped by design: token positions, generation limit, cancellation and
// completion status are local to one invocation, so a GUI adapter can call the
// same sequence per request.
//
// Usage:
//   deep2_strata_chat.exe --model <gguf> --prompt "text" [--max-new N]
//       [--gpu|--cpu] [--device N] [--strata|--no-strata] [--policy N]
//       [--outdir D] [--tag T] [--cancel-after N]

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "CanonicalTokenizer.hpp"
#include "StrataExpertResidency.hpp"
#include "quant_dot_dispatch.hpp"
#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include <windows.h>

using namespace RawrXD::Deep2;  // Universal / RuntimeGraph / QuantDot

namespace {

double MsSince(std::chrono::steady_clock::time_point t0)
{
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now() - t0)
        .count();
}

uint64_t ArgMax(const std::vector<float>& logits)
{
    uint64_t best = 0;
    float bestValue = logits.empty() ? 0.0f : logits[0];
    for (size_t i = 1; i < logits.size(); ++i) {
        if (logits[i] > bestValue) {
            bestValue = logits[i];
            best = i;
        }
    }
    return best;
}

bool WriteReceipt(const std::string& dir, const std::string& tag,
                  const std::string& model, const std::string& promptText,
                  const std::vector<uint32_t>& prompt,
                  const std::vector<uint32_t>& generated, bool cancelled,
                  double bindMs, double prefillMs, double decodeMs,
                  const RuntimeGraph::Executor& ex,
                  const Strata::ExpertResidencyLedger::Summary& ledger)
{
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const std::string path = (std::filesystem::path(dir) /
                              ("strata_chat_" + tag + ".json")).string();
    std::ofstream out(path, std::ios::trunc);
    if (!out)
        return false;

    const auto& b = ex.Stats();
    const size_t nonfinite = ex.NonFiniteLogits();
    const double totalS = (bindMs + prefillMs + decodeMs) / 1000.0;
    const double tps = decodeMs > 0 ? (generated.size() * 1000.0 / decodeMs) : 0.0;

    out << "{\n";
    out << "  \"tag\": \"" << tag << "\",\n";
    out << "  \"model\": \"" << model << "\",\n";
    out << "  \"prompt_text\": \"" << promptText << "\",\n";
    out << "  \"prompt_tokens\": " << prompt.size() << ",\n";
    out << "  \"prompt_ids\": [";
    for (size_t i = 0; i < prompt.size(); ++i)
        out << (i ? ", " : "") << prompt[i];
    out << "],\n";
    out << "  \"generate_tokens\": " << generated.size() << ",\n";
    out << "  \"generated_ids\": [";
    for (size_t i = 0; i < generated.size(); ++i)
        out << (i ? ", " : "") << generated[i];
    out << "],\n";
    out << "  \"cancelled\": " << (cancelled ? "true" : "false") << ",\n";
    out << "  \"bind_ms\": " << bindMs << ",\n";
    out << "  \"prefill_ms\": " << prefillMs << ",\n";
    out << "  \"decode_ms\": " << decodeMs << ",\n";
    out << "  \"total_ms\": " << (totalS * 1000.0) << ",\n";
    out << "  \"decode_tps\": " << tps << ",\n";
    out << "  \"gpu_calls\": " << b.gpu_calls << ",\n";
    out << "  \"cpu_calls\": " << b.cpu_calls << ",\n";
    out << "  \"fallback\": \""
        << (b.fallback_reason.empty() ? "<none>" : b.fallback_reason) << "\",\n";
    out << "  \"nonfinite_logits\": " << nonfinite << ",\n";
    out << "  \"expert_ledger\": {"
        << "\"observations\": " << ledger.observations << ", "
        << "\"hits\": " << ledger.hits << ", "
        << "\"misses\": " << ledger.misses << ", "
        << "\"evictions\": " << ledger.evictions << ", "
        << "\"hit_rate\": " << ledger.hit_rate << ", "
        << "\"distinct_experts\": " << ledger.distinct_experts << "},\n";
    out << "  \"cleanup\": \"ok\"\n";
    out << "}\n";
    out.close();
    std::printf("RECEIPT %s\n", path.c_str());
    return true;
}

}  // namespace

int main(int argc, char** argv)
{
    std::string model, promptText = "The capital of France is";
    std::string outdir = "strata_chat_out", tag = "run";
    int maxNew = 32;
    int cancelAfter = -1;
    int policy = 0;  // 0 = lru
    int devicePin = 0;
    bool gpu = true;
    bool strata = true;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--prompt" && i + 1 < argc) promptText = argv[++i];
        else if (a == "--max-new" && i + 1 < argc) maxNew = std::atoi(argv[++i]);
        else if (a == "--cancel-after" && i + 1 < argc) cancelAfter = std::atoi(argv[++i]);
        else if (a == "--policy" && i + 1 < argc) policy = std::atoi(argv[++i]);
        else if (a == "--device" && i + 1 < argc) devicePin = std::atoi(argv[++i]);
        else if (a == "--outdir" && i + 1 < argc) outdir = argv[++i];
        else if (a == "--tag" && i + 1 < argc) tag = argv[++i];
        else if (a == "--cpu") gpu = false;
        else if (a == "--gpu") gpu = true;
        else if (a == "--no-strata") strata = false;
        else if (a == "--strata") strata = true;
    }
    if (model.empty() || maxNew < 1) {
        std::printf("usage: deep2_strata_chat.exe --model <gguf> [--prompt TEXT] "
                    "[--max-new N] [--gpu|--cpu] [--device N] [--strata|--no-strata] "
                    "[--policy N] [--cancel-after N] [--outdir D] [--tag T]\n");
        return 2;
    }

    // ---- request scope: tokenize this request's prompt ---------------------
    auto& tok = Deep2::CanonicalTokenizer::Instance();
    if (!tok.LoadFromGGUF(model)) {
        std::printf("TOKENIZER_FAIL: %s\n", tok.LastError().c_str());
        return 1;
    }
    const std::vector<int> ids = tok.Encode(promptText);
    if (ids.empty()) {
        std::printf("TOKENIZE_EMPTY: no tokens for prompt\n");
        return 1;
    }
    std::vector<uint32_t> prompt(ids.begin(), ids.end());
    std::printf("PROMPT_TOKENS %zu\n", prompt.size());
    for (size_t i = 0; i < prompt.size(); ++i)
        std::printf("  in[%zu]=%u '%s'\n", i, prompt[i],
                    tok.Decode((int)prompt[i]).c_str());
    std::fflush(stdout);

    // ---- model + executor (same setup as deep2_strata_bench) --------------
    const auto bindT0 = std::chrono::steady_clock::now();
    const Universal::IngestReport& rep = Universal::Ingest(model, false);
    if (!rep.ok) {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    std::printf("arch=%s blocks=%llu embd=%llu experts=%llu\n",
                rep.spec.architecture.c_str(),
                (unsigned long long)rep.spec.block_count,
                (unsigned long long)rep.spec.embd,
                (unsigned long long)rep.spec.expert_count);
    std::fflush(stdout);

    RuntimeGraph::Executor ex;
    ex.SetForceCpu(!gpu);
    if (devicePin >= 0) QuantDot::SetPreferredDevice(devicePin);
    if (strata) {
        ex.SetStrataExpertTracking(true);
        ex.SetStrataCachePolicy(policy);
    }
    if (!ex.Bind(rep)) {
        std::printf("BIND_FAIL: %s\n", ex.Stats().error.c_str());
        return 1;
    }
    const double bindMs = MsSince(bindT0);
    std::printf("bound ops=%zu (%.1f ms)\n", ex.Stats().ops_total, bindMs);
    std::fflush(stdout);

    // ---- prefill ----------------------------------------------------------
    const auto preT0 = std::chrono::steady_clock::now();
    for (size_t pos = 0; pos < prompt.size(); ++pos) {
        if (!ex.ExecuteToken(prompt[pos], pos)) {
            std::printf("PREFILL_FAIL at pos=%zu\n", pos);
            return 1;
        }
    }
    const double prefillMs = MsSince(preT0);
    std::printf("prefill_done %.1f ms\n", prefillMs);
    std::fflush(stdout);

    // ---- decode: stream every token as it is produced ---------------------
    std::vector<uint32_t> generated;
    const auto decT0 = std::chrono::steady_clock::now();
    uint32_t next = prompt.back();
    bool cancelled = false;
    for (int step = 0; step < maxNew; ++step) {
        if (cancelAfter >= 0 && step >= cancelAfter) {
            std::printf("CANCELLED after %d tokens\n", step);
            cancelled = true;
            break;
        }
        const uint64_t pick = ArgMax(ex.Logits());
        if (pick == 0 && step > 0) {
            std::printf("EOS at step=%d\n", step);
            break;
        }
        generated.push_back((uint32_t)pick);
        const std::string piece = tok.Decode((int)pick);
        std::printf("[tok %d] id=%llu '%s'\n", step, (unsigned long long)pick,
                    piece.c_str());
        std::fflush(stdout);

        next = (uint32_t)pick;
        const size_t pos = prompt.size() + (size_t)step;
        if (!ex.ExecuteToken(next, pos)) {
            std::printf("DECODE_FAIL at pos=%zu\n", pos);
            break;
        }
    }
    const double decodeMs = MsSince(decT0);

    auto ledger = ex.StrataExpertSummary();
    const auto& b = ex.Stats();
    const size_t nonfinite = ex.NonFiniteLogits();
    std::printf("DISPATCH gpu_calls=%llu cpu_calls=%llu fallback=%s nonfinite_logits=%zu\n",
                (unsigned long long)b.gpu_calls, (unsigned long long)b.cpu_calls,
                b.fallback_reason.empty() ? "<none>" : b.fallback_reason.c_str(),
                nonfinite);
    std::printf("S01_EXPERT_LEDGER observations=%llu hits=%llu misses=%llu "
                "evictions=%llu hit_rate=%.4f distinct_experts=%llu\n",
                (unsigned long long)ledger.observations,
                (unsigned long long)ledger.hits,
                (unsigned long long)ledger.misses,
                (unsigned long long)ledger.evictions,
                ledger.hit_rate,
                (unsigned long long)ledger.distinct_experts);
    std::printf("CHAT_STATUS %s\n", cancelled ? "CANCELLED"
                                               : (generated.empty() ? "EMPTY" : "OK"));
    WriteReceipt(outdir, tag, model, promptText, prompt, generated, cancelled,
                 bindMs, prefillMs, decodeMs, ex, ledger);
    std::printf("Released; exiting\n");
    return 0;
}