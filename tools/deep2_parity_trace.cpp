// ============================================================================
// deep2_parity_trace.cpp -- RAWRXD_DEEP2_PROBE_PARITY
// ============================================================================
// Dumps every runtime-graph operator's output for a fixed teacher-forced token
// sequence (default: 1 185, i.e. positions 0 and 1), so each checkpoint can be
// compared against the llama.cpp reference probe dumps (probe_stepNN_*_lNN.bin).
//
// The run is CPU-pinned: the CPU path is the certification target, and the GPU
// path is afterwards required to reproduce it without fallback.
//
// Writes into <outdir>:
//   d2_logits_pos<N>.bin              full logits (raw f32) per position
//   d2_pos<N>_blk<B>_<name>.bin       every op output (raw f32) per position
//   d2_trace_pos<N>.txt               op order, sizes, first values
//
// Usage: deep2_parity_trace.exe --model <gguf> [--tokens "1 185"] [--outdir D]
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

using namespace RawrXD::Deep2;

namespace {

std::string Sanitize(const std::string& s) {
    std::string out;
    for (char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.')
            out.push_back(c);
        else
            out.push_back('_');
    }
    return out;
}

bool WriteFloats(const std::string& path, const std::vector<float>& v) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const size_t n = std::fwrite(v.data(), sizeof(float), v.size(), f);
    std::fclose(f);
    return n == v.size();
}

}  // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::string model, outdir = "parity_out", tokensArg = "1 185";
    int generate = 0;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--outdir" && i + 1 < argc) outdir = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokensArg = argv[++i];
        else if (a == "--generate" && i + 1 < argc) generate = std::atoi(argv[++i]);
        else {
            std::printf("unknown arg %s\n", a.c_str());
            return 1;
        }
    }
    if (model.empty()) {
        std::printf("usage: deep2_parity_trace.exe --model <gguf> [--tokens \"1 185\"] [--outdir D]\n");
        return 1;
    }

    std::vector<uint32_t> tokens;
    {
        const char* p = tokensArg.c_str();
        char* end = nullptr;
        for (long v = std::strtol(p, &end, 10); end != p; v = std::strtol(p, &end, 10)) {
            if (v < 0) break;
            tokens.push_back((uint32_t)v);
            p = end;
            while (*p == ' ' || *p == ',') ++p;
            if (!*p) break;
        }
    }
    if (tokens.empty()) {
        std::printf("no tokens parsed from \"%s\"\n", tokensArg.c_str());
        return 1;
    }
    std::printf("tokens: %zu:", tokens.size());
    for (uint32_t t : tokens) std::printf(" %u", t);
    std::printf("\n");

    std::printf("ingesting %s ...\n", model.c_str());
    const Universal::IngestReport& rep = Universal::Ingest(model, false);
    if (!rep.ok) {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    std::printf("arch=%s blocks=%llu embd=%llu heads=%llu kv=%llu lora=%llu kl=%llu vl=%llu "
                "experts=%llu used=%llu shared=%llu dense_lead=%llu rope_dim=%llu eps=%g\n",
                rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count,
                (unsigned long long)rep.spec.embd, (unsigned long long)rep.spec.heads,
                (unsigned long long)rep.spec.heads_kv, (unsigned long long)rep.spec.kv_lora_rank,
                (unsigned long long)rep.spec.key_length, (unsigned long long)rep.spec.value_length,
                (unsigned long long)rep.spec.expert_count, (unsigned long long)rep.spec.expert_used,
                (unsigned long long)rep.spec.expert_shared, (unsigned long long)rep.spec.leading_dense,
                (unsigned long long)rep.spec.rope_dim, rep.spec.rms_eps);

    RuntimeGraph::Executor ex;
    ex.SetForceCpu(true);  // CPU-pinned: the certification path
    if (!ex.Bind(rep)) {
        std::printf("BIND_FAIL: %s\n", ex.Stats().error.c_str());
        return 1;
    }
    std::printf("bound ops=%zu\n", ex.Stats().ops_total);

    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        ex.SetOpTrace(true, true);
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = ex.ExecuteToken(tokens[pos], pos);
        const auto t1 = std::chrono::steady_clock::now();
        if (!ok) {
            std::printf("EXEC_FAIL pos=%zu err=%s\n", pos, ex.LastError().c_str());
            return 1;
        }
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

        const std::vector<float>& logits = ex.Logits();
        if (!WriteFloats(outdir + "/d2_logits_pos" + std::to_string(pos) + ".bin", logits)) {
            std::printf("WARN: logits dump write failed pos=%zu\n", pos);
        }
        uint32_t argmax = 0;
        for (size_t i = 1; i < logits.size(); ++i)
            if (logits[i] > logits[argmax]) argmax = (uint32_t)i;
        std::printf("pos=%zu token=%u argmax=%u max_logit=%.6f (%.1f ms)\n", pos, tokens[pos],
                    argmax, logits.empty() ? 0.0 : logits[argmax], ms);

        FILE* lst = std::fopen((outdir + "/d2_trace_pos" + std::to_string(pos) + ".txt").c_str(), "w");
        if (lst) std::fprintf(lst, "pos=%zu token=%u\n", pos, tokens[pos]);
        const std::vector<RuntimeGraph::Executor::OpTrace>& tr = ex.OpTraces();
        std::printf("  op traces: %zu\n", tr.size());
        for (const auto& t : tr) {
            const std::string base = outdir + "/d2_pos" + std::to_string(pos) + "_blk" +
                                     std::to_string(t.block < 0 ? 999 : t.block) + "_pc" +
                                     std::to_string(t.pc) + "_" +
                                     Sanitize(t.name.empty() ? std::string("hidden") : t.name);
            if (!t.values.empty()) WriteFloats(base + ".bin", t.values);
            if (lst) {
                std::fprintf(lst, "blk=%d pc=%d op=%d name=%s size=%zu vals=", t.block, t.pc, t.op,
                             t.name.c_str(), t.size);
                for (int i = 0; i < 8; ++i) std::fprintf(lst, "%.7g ", (double)t.first_vals[i]);
                std::fprintf(lst, "\n");
            }
        }
        if (lst) std::fclose(lst);
        ex.SetOpTrace(false);
    }

    // ---- greedy generation (multi-token agreement with KV reuse) -----------
    // Mirrors llama_gen_ref: the argmax of the LAST seed position is gen[0],
    // then each generated token is decoded through the persistent KV cache for
    // a total of `generate` entries. Printed in the same GENSTREAM format so
    // the two engines can be compared token-for-token.
    if (generate > 0) {
        std::vector<uint32_t> gen;
        std::vector<double> genMax;
        size_t gpos = tokens.size() - 1;
        const std::vector<float>* last = &ex.Logits();
        auto argmaxOf = [](const std::vector<float>& lg) {
            uint32_t a = 0;
            for (size_t i = 1; i < lg.size(); ++i)
                if (lg[i] > lg[a]) a = (uint32_t)i;
            return a;
        };
        gen.push_back(argmaxOf(*last));
        genMax.push_back((*last)[gen.back()]);
        for (int i = 1; i < generate; ++i) {
            ++gpos;
            if (!ex.ExecuteToken((uint32_t)gen.back(), gpos)) {
                std::printf("GEN_FAIL pos=%zu err=%s\n", gpos, ex.LastError().c_str());
                return 1;
            }
            last = &ex.Logits();
            gen.push_back(argmaxOf(*last));
            genMax.push_back((*last)[gen.back()]);
        }
        std::printf("GENSTREAM:");
        for (size_t i = 0; i < gen.size(); ++i)
            std::printf(" %u %.6f", gen[i], genMax[i]);
        std::printf("\n");
    }

    const RuntimeGraph::BindStats& b = ex.Stats();
    std::printf("gpu_calls=%llu cpu_calls=%llu fallback=%s\n", (unsigned long long)b.gpu_calls,
                (unsigned long long)b.cpu_calls,
                b.fallback_reason.empty() ? "<none>" : b.fallback_reason.c_str());
    return 0;
}
