// ============================================================================
// deep2_parity_first_divergence.cpp  --  RAWRXD_DEEP2 Sprint 9 P0-02
// ============================================================================
// Native GPU-batched versus CPU-serial prefill differential driver.
//
// Sprint 8 closed with PREFILL_PARITY_MAX_REL=21.9 / NUMERICAL_PARITY=FAIL:
// the batched prefill path and the serial reference path disagreed, but only an
// aggregate error survived -- not WHERE they first diverged. This tool turns
// that aggregate into a localisation:
//
//   * First divergent POSITION  -- per-position logits, CPU-serial vs GPU-batch.
//   * First divergent LAYER     -- per-block/per-position K and V cache rows.
//
// DESIGN (authorized Sprint 9 decision)
//   A genuinely-batched CPU prefill is NOT supported by the current runtime:
//   Executor::PrefillBatch refuses the per-executor force_cpu_ flag and its
//   BeginBatch() fails when the process-wide QuantDot CPU policy is engaged
//   (observed: "prefill-batch: BeginBatch failed"). PrefillBatch is a GPU
//   submission optimisation. The parity question is therefore:
//
//       CPU-serial reference   vs   GPU-batched candidate
//
//   Both sessions use the SAME model (one Ingest), the SAME token ids, the SAME
//   start position (0) and the SAME initial (empty) KV state.
//
//     Reference  Executor::SetForceCpu(true)   + ExecuteToken per position
//                -> require gpu_calls == 0 (proves the reference is CPU-only)
//     Candidate  Executor::SetForceCpu(false)  + PrefillBatch
//                -> require gpu_calls  > 0 (proves the candidate really batched
//                   on the GPU; a zero here means the "batched" run did not
//                   exercise the GPU path and must NOT be reported as one)
//
//   The per-executor force_cpu_ flag is independent of the process-wide
//   QuantDot switch, so the two policies coexist; the gpu_calls assertions are
//   the authority on what actually ran, not the flags. Sessions run sequentially
//   (reference fully completes before the candidate starts).
//
// This tool does NOT use the executor's OpTrace path: that path disables dot
// batching, so it cannot certify a genuinely batched execution. It measures the
// first divergent POSITION (logits) and first divergent LAYER (KV), NOT the
// first divergent OPERATION (which would require per-op tensor capture on the
// batched path -- future work, tracked separately).
//
// Usage:
//   deep2_parity_first_divergence.exe --model <gguf> [--prompt "text"]
//       [--max-tokens N] [--abs-tol A] [--rel-tol R] [--outdir D] [--tag T]
//
// Exit codes:
//   0   PARITY PASS      (GPU-batched and CPU-serial logits equivalent in tol)
//   5   PARITY FAIL      (a divergent position was found)
//   1   load / tokenize / ingest error
//   2   usage / bad tolerance
//   10  INIT_FAIL_SERIAL (reference executor did not bind)
//   11  SERIAL_FAIL / CPU_REF_DISPATCHED_GPU (reference did not run CPU-only)
//   12  INIT_FAIL_BATCH  (candidate executor did not bind)
//   13  CPU_BATCH_UNSUPPORTED (candidate refused: force_cpu pinned)
//   14  BATCH_BEGIN_FAIL (candidate BeginBatch failed)
//   15  BATCH_FAIL       (candidate prefill failed for another reason)
//   16  GPU_BATCH_NO_GPU_DISPATCH (candidate did not dispatch GPU work)
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

#include "CanonicalTokenizer.hpp"
#include "quant_dot_dispatch.hpp"
#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "deep2/ParityCapture.hpp"

namespace PC = RawrXD::Deep2::Parity;
using namespace RawrXD::Deep2;

namespace {

struct Options {
    std::string model;
    std::string promptText = "The capital of France is";
    std::string outdir = "parity_first_divergence_out";
    std::string tag = "run";
    std::size_t maxTokens = 0; // 0 = whole prompt
    double absTol = 1e-4;
    double relTol = 1e-3;
};

std::string JsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '\\': o += "\\\\"; break;
        case '"': o += "\\\""; break;
        case '\n': o += "\\n"; break;
        case '\r': o += "\\r"; break;
        case '\t': o += "\\t"; break;
        default: o += c; break;
        }
    }
    return o;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) opt.model = argv[++i];
        else if (a == "--prompt" && i + 1 < argc) opt.promptText = argv[++i];
        else if (a == "--max-tokens" && i + 1 < argc) opt.maxTokens = (std::size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--abs-tol" && i + 1 < argc) opt.absTol = std::atof(argv[++i]);
        else if (a == "--rel-tol" && i + 1 < argc) opt.relTol = std::atof(argv[++i]);
        else if (a == "--outdir" && i + 1 < argc) opt.outdir = argv[++i];
        else if (a == "--tag" && i + 1 < argc) opt.tag = argv[++i];
    }
    if (opt.model.empty()) {
        std::printf("usage: deep2_parity_first_divergence.exe --model <gguf> "
                    "[--prompt TEXT] [--max-tokens N] [--abs-tol A] [--rel-tol R] "
                    "[--outdir D] [--tag T]\n");
        return 2;
    }
    if (!PC::IsFiniteCapture(opt.absTol, opt.relTol)) {
        std::printf("BAD_TOLERANCE absTol=%g relTol=%g\n", opt.absTol, opt.relTol);
        return 2;
    }

    // ---- tokenize (single canonical tokenizer, byte-identical prompt) ------
    auto& tok = Deep2::CanonicalTokenizer::Instance();
    if (!tok.LoadFromGGUF(opt.model)) {
        std::printf("TOKENIZER_FAIL: %s\n", tok.LastError().c_str());
        return 1;
    }
    const std::vector<int> ids = tok.Encode(opt.promptText);
    if (ids.empty()) {
        std::printf("TOKENIZE_EMPTY\n");
        return 1;
    }
    const auto& special = tok.GetSpecialTokens();
    std::vector<uint32_t> prompt;
    if (special.bosId >= 0 && (ids.empty() || ids.front() != special.bosId))
        prompt.push_back(static_cast<uint32_t>(special.bosId));
    prompt.insert(prompt.end(), ids.begin(), ids.end());
    if (opt.maxTokens > 0 && prompt.size() > opt.maxTokens)
        prompt.resize(opt.maxTokens);
    if (prompt.empty()) {
        std::printf("EMPTY_PROMPT\n");
        return 1;
    }
    std::printf("PROMPT_TOKENS %zu\n", prompt.size());
    std::fflush(stdout);

    // ---- ingest once; both executors bind the same immutable report --------
    const Universal::IngestReport& rep = Universal::Ingest(opt.model, false);
    if (!rep.ok) {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    std::printf("arch=%s blocks=%llu embd=%llu\n",
                rep.spec.architecture.c_str(),
                (unsigned long long)rep.spec.block_count,
                (unsigned long long)rep.spec.embd);
    std::fflush(stdout);

    // =====================================================================
    // Session A: CPU-serial REFERENCE
    // =====================================================================
    RuntimeGraph::Executor exRef;
    exRef.SetForceCpu(true);
    if (!exRef.Bind(rep)) {
        std::printf("INIT_FAIL_SERIAL: %s\n", exRef.Stats().error.c_str());
        return 10;
    }
    std::vector<std::vector<float>> refLogits(prompt.size());
    for (std::size_t pos = 0; pos < prompt.size(); ++pos) {
        if (!exRef.ExecuteToken(prompt[pos], pos)) {
            std::printf("SERIAL_FAIL at pos=%zu: %s\n", pos, exRef.LastError().c_str());
            return 11;
        }
        refLogits[pos] = exRef.Logits();
    }
    const uint64_t refGpu = exRef.Stats().gpu_calls;
    const uint64_t refCpu = exRef.Stats().cpu_calls;
    std::printf("DISPATCH reference{gpu=%llu cpu=%llu}\n",
                (unsigned long long)refGpu, (unsigned long long)refCpu);
    std::fflush(stdout);
    if (refGpu != 0) {
        // The reference was supposed to be CPU-only. A nonzero GPU count means
        // the per-executor CPU pin leaked; do NOT trust a comparison against a
        // reference that actually ran on the GPU.
        std::printf("CPU_REF_DISPATCHED_GPU gpu=%llu -- reference is not CPU-only\n",
                    (unsigned long long)refGpu);
        std::printf("PARITY_VERDICT=NOT_CPU_REFERENCE\n");
        return 11;
    }

    // =====================================================================
    // Session B: GPU-batched CANDIDATE
    // =====================================================================
    RuntimeGraph::Executor exCand;
    exCand.SetForceCpu(false); // GPU dot batching; PrefillBatch requires this
    if (!exCand.Bind(rep)) {
        std::printf("INIT_FAIL_BATCH: %s\n", exCand.Stats().error.c_str());
        return 12;
    }
    std::vector<std::vector<float>> candLogits;
    if (!exCand.PrefillBatch(prompt, 0, &candLogits)) {
        const std::string e = exCand.LastError();
        std::printf("BATCH_FAIL: %s\n", e.c_str());
        if (e.find("force_cpu") != std::string::npos) {
            std::printf("PARITY_VERDICT=BATCH_UNSUPPORTED_CPU\n");
            return 13;
        }
        if (e.find("BeginBatch") != std::string::npos) {
            std::printf("PARITY_VERDICT=BATCH_BEGIN_FAIL\n");
            return 14;
        }
        std::printf("PARITY_VERDICT=BATCH_FAIL\n");
        return 15;
    }
    const uint64_t candGpu = exCand.Stats().gpu_calls;
    const uint64_t candCpu = exCand.Stats().cpu_calls;
    std::printf("DISPATCH candidate{gpu=%llu cpu=%llu}\n",
                (unsigned long long)candGpu, (unsigned long long)candCpu);
    std::fflush(stdout);
    if (candGpu == 0) {
        // The candidate was supposed to batch on the GPU. Zero GPU dispatches
        // means the "batched" run did not exercise the GPU path; do NOT report
        // it as a GPU-batched result.
        std::printf("GPU_BATCH_NO_GPU_DISPATCH -- candidate did not dispatch GPU work\n");
        std::printf("PARITY_VERDICT=NOT_GPU_BATCH\n");
        return 16;
    }

    const PC::Tolerance tol{opt.absTol, opt.relTol};
    const std::size_t P = prompt.size();

    // ---- per-position logits comparison (first divergent POSITION) ---------
    if (candLogits.size() != refLogits.size()) {
        std::printf("LOGIT_COUNT_MISMATCH reference=%zu candidate=%zu\n",
                    refLogits.size(), candLogits.size());
        std::printf("PARITY_VERDICT=FAIL\n");
        return 5;
    }

    bool anyLogitDiverged = false;
    std::size_t firstDivPos = std::numeric_limits<std::size_t>::max();
    PC::ParityCapture firstDivCap;
    double worstLogitRel = 0.0;
    std::size_t worstLogitPos = 0;
    std::size_t nonFinitePositions = 0;

    for (std::size_t pos = 0; pos < P; ++pos) {
        const PC::ParityCapture cap = PC::Compare(
            refLogits[pos], candLogits[pos],
            PC::kSentinelLayer, (std::uint32_t)pos, PC::kSentinelOperation, tol);
        if (!cap.valid) {
            ++nonFinitePositions;
            if (firstDivPos == std::numeric_limits<std::size_t>::max()) {
                firstDivPos = pos;
                firstDivCap = cap;
            }
            std::printf("POS %zu INVALID (%s)\n", pos, PC::Describe(cap).c_str());
            continue;
        }
        if (cap.maxRelError > worstLogitRel) {
            worstLogitRel = cap.maxRelError;
            worstLogitPos = pos;
        }
        if (cap.hasMismatch) {
            anyLogitDiverged = true;
            if (firstDivPos == std::numeric_limits<std::size_t>::max()) {
                firstDivPos = pos;
                firstDivCap = cap;
            }
        }
        std::printf("POS %zu %s\n", pos, PC::Describe(cap).c_str());
        // Alignment check: confirm reference and candidate describe the SAME
        // token position (guards against a perPosLogits off-by-one) and report
        // whether they agree on the predicted next token, plus the first 8 raw
        // logit pairs. A maxRel near 2.0 with matching argmax usually means an
        // opposite-sign / near-zero element, not a gross model error.
        if (!refLogits[pos].empty() && !candLogits[pos].empty() &&
            refLogits[pos].size() == candLogits[pos].size()) {
            auto am = [](const std::vector<float>& v) {
                size_t b = 0;
                for (size_t i = 1; i < v.size(); ++i) if (v[i] > v[b]) b = i;
                return b;
            };
            const size_t ra = am(refLogits[pos]);
            const size_t ca = am(candLogits[pos]);
            std::printf("  ALIGN ref_argmax=%zu cand_argmax=%zu %s",
                        ra, ca, ra == ca ? "AGREE" : "DISAGREE");
            const size_t n8 = std::min<size_t>(8, refLogits[pos].size());
            std::printf(" first8[");
            for (size_t i = 0; i < n8; ++i)
                std::printf("%s%.4f/%.4f", i ? "," : "", refLogits[pos][i], candLogits[pos][i]);
            std::printf("]\n");
        }
    }
    std::fflush(stdout);

    // ---- per-block/per-position KV comparison (first divergent LAYER) ------
    const size_t blocks = std::min(exRef.KvBlocks(), exCand.KvBlocks());
    bool anyKvDiverged = false;
    int firstKvLayer = -1;
    std::size_t firstKvPos = std::numeric_limits<std::size_t>::max();
    int firstKvStream = -1; // 0=K, 1=V
    PC::ParityCapture firstKvCap;
    double worstKvRel = 0.0;

    for (size_t b = 0; b < blocks; ++b) {
        const size_t rows = std::min(exRef.KvRows((int)b), exCand.KvRows((int)b));
        for (std::size_t pos = 0; pos < rows; ++pos) {
            for (int stream = 0; stream < 2; ++stream) {
                const std::vector<float> a = (stream == 0)
                    ? exRef.KvKRow((int)b, pos) : exRef.KvVRow((int)b, pos);
                const std::vector<float> c = (stream == 0)
                    ? exCand.KvKRow((int)b, pos) : exCand.KvVRow((int)b, pos);
                if (a.empty() && c.empty()) continue;
                const PC::ParityCapture cap = PC::Compare(
                    a, c, (std::uint32_t)b, (std::uint32_t)pos,
                    (std::uint32_t)stream, tol);
                if (!cap.valid) {
                    if (a.size() != c.size())
                        std::printf("KV block=%zu pos=%zu stream=%d SIZE_MISMATCH %zu vs %zu\n",
                                    b, pos, stream, a.size(), c.size());
                    continue;
                }
                if (cap.maxRelError > worstKvRel) worstKvRel = cap.maxRelError;
                if (cap.hasMismatch) {
                    anyKvDiverged = true;
                    if (firstKvLayer < 0) {
                        firstKvLayer = (int)b;
                        firstKvPos = pos;
                        firstKvStream = stream;
                        firstKvCap = cap;
                    }
                }
            }
        }
    }
    std::fflush(stdout);

    // ---- verdict -----------------------------------------------------------
    // PASS requires: CPU reference gpu_calls==0 (checked), GPU candidate
    // gpu_calls>0 (checked), and every position's logits equivalent in tol.
    const bool logitsEquivalent = !anyLogitDiverged && nonFinitePositions == 0;

    std::printf("\n===== SPRINT9 P0-02 FIRST-DIVERGENCE SUMMARY =====\n");
    std::printf("mode=GPU_BATCH_VS_CPU_SERIAL\n");
    std::printf("positions_compared=%zu\n", P);
    std::printf("reference_gpu_calls=%llu (must be 0)\n", (unsigned long long)refGpu);
    std::printf("candidate_gpu_calls=%llu (must be >0)\n", (unsigned long long)candGpu);
    std::printf("logits_diverged_positions=%s\n", anyLogitDiverged ? "YES" : "NO");
    if (anyLogitDiverged || nonFinitePositions) {
        std::printf("first_divergent_position=%zu\n", firstDivPos);
        std::printf("first_divergent_position_record=%s\n",
                    PC::Describe(firstDivCap).c_str());
    }
    std::printf("worst_logit_maxRel=%.9g at_pos=%zu\n", worstLogitRel, worstLogitPos);
    std::printf("kv_blocks_compared=%zu\n", blocks);
    std::printf("kv_diverged=%s\n", anyKvDiverged ? "YES" : "NO");
    if (anyKvDiverged) {
        std::printf("first_divergent_layer=%d pos=%zu stream=%s\n",
                    firstKvLayer, firstKvPos, firstKvStream == 0 ? "K" : "V");
        std::printf("first_divergent_layer_record=%s\n",
                    PC::Describe(firstKvCap).c_str());
    }
    std::printf("worst_kv_maxRel=%.9g\n", worstKvRel);
    std::printf("PARITY_VERDICT=%s\n", logitsEquivalent ? "PASS" : "FAIL");
    std::fflush(stdout);

    // ---- receipt -----------------------------------------------------------
    {
        std::error_code ec;
        std::filesystem::create_directories(opt.outdir, ec);
        const std::string path = (std::filesystem::path(opt.outdir) /
                                  ("parity_first_divergence_" + opt.tag + ".json")).string();
        std::ofstream out(path, std::ios::trunc);
        if (out) {
            out << "{\n";
            out << "  \"tag\": \"" << JsonEscape(opt.tag) << "\",\n";
            out << "  \"model\": \"" << JsonEscape(opt.model) << "\",\n";
            out << "  \"mode\": \"GPU_BATCH_VS_CPU_SERIAL\",\n";
            out << "  \"positions_compared\": " << P << ",\n";
            out << "  \"reference_gpu_calls\": " << refGpu << ",\n";
            out << "  \"reference_cpu_calls\": " << refCpu << ",\n";
            out << "  \"candidate_gpu_calls\": " << candGpu << ",\n";
            out << "  \"candidate_cpu_calls\": " << candCpu << ",\n";
            out << "  \"abs_tol\": " << opt.absTol << ",\n";
            out << "  \"rel_tol\": " << opt.relTol << ",\n";
            out << "  \"logits_diverged\": " << (anyLogitDiverged ? "true" : "false") << ",\n";
            out << "  \"nonfinite_positions\": " << nonFinitePositions << ",\n";
            out << "  \"first_divergent_position\": ";
            if (firstDivPos == std::numeric_limits<std::size_t>::max()) out << "null";
            else out << firstDivPos;
            out << ",\n";
            out << "  \"first_divergent_position_maxAbs\": " << firstDivCap.maxAbsError << ",\n";
            out << "  \"first_divergent_position_maxRel\": " << firstDivCap.maxRelError << ",\n";
            out << "  \"first_divergent_position_rms\": " << firstDivCap.rmsError << ",\n";
            out << "  \"first_divergent_position_firstMismatch\": " << firstDivCap.firstMismatchIndex << ",\n";
            out << "  \"worst_logit_maxRel\": " << worstLogitRel << ",\n";
            out << "  \"worst_logit_pos\": " << worstLogitPos << ",\n";
            out << "  \"kv_diverged\": " << (anyKvDiverged ? "true" : "false") << ",\n";
            out << "  \"first_divergent_layer\": ";
            if (firstKvLayer < 0) out << "null";
            else out << firstKvLayer;
            out << ",\n";
            out << "  \"first_divergent_layer_pos\": " << firstKvPos << ",\n";
            out << "  \"first_divergent_layer_stream\": \""
                << (firstKvStream == 0 ? "K" : (firstKvStream == 1 ? "V" : "none")) << "\",\n";
            out << "  \"first_divergent_layer_maxRel\": " << firstKvCap.maxRelError << ",\n";
            out << "  \"worst_kv_maxRel\": " << worstKvRel << ",\n";
            out << "  \"verdict\": \"" << (logitsEquivalent ? "PASS" : "FAIL") << "\"\n";
            out << "}\n";
            out.close();
            std::printf("RECEIPT %s\n", path.c_str());
        }
    }

    return logitsEquivalent ? 0 : 5;
}