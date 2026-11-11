// ============================================================================
// deep2_d1_prefill_parity.cpp -- RAWRXD_DEEP2_D1_PREFILL_PARITY
// ============================================================================
// Independent verification of Executor::PrefillBatch (D1 batched multi-token
// prefill) against the serial ExecuteToken path on the SAME model and device.
//
// Two checks, both required by the D1 acceptance contract:
//
//  1. FULL-LOGIT PARITY: for every prefix length k (2..N) a FRESH batched
//     executor runs PrefillBatch(tokens[0..k)); its final-position logits are
//     compared bit-for-bit against the serial path's logits at position k-1.
//     A prefix sweep (not just the full length) is what actually exercises the
//     batched path's KV writes for every position: each k is a different
//     prefill length with a different chunking pattern.
//
//  2. CAUSAL KV STATE: after the longest prefill, BOTH executors continue with
//     the same next token and a short greedy decode. If the batched path's KV
//     cache or per-token hidden carriers were wrong, the continued logits and
//     the decode stream would diverge here.
//
// Any mismatch is reported with the exact position and magnitude. Exit code 0
// only when both checks are bit-exact.
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

using namespace RawrXD::Deep2;

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::string model, tokensArg = "1 185 278 20606 23808 7936 14336 28416";
    size_t max_prefix = 12;
    size_t decode_steps = 8;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokensArg = argv[++i];
        else if (a == "--max-prefix" && i + 1 < argc) max_prefix = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--decode-steps" && i + 1 < argc) decode_steps = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else { std::printf("unknown arg %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        std::printf("usage: deep2_d1_prefill_parity.exe --model <gguf> --tokens \"1 185\" "
                    "[--max-prefix N] [--decode-steps N]\n");
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
    if (tokens.size() < 2) { std::printf("NEED_2_TOKENS\n"); return 1; }
    if (max_prefix > tokens.size()) max_prefix = tokens.size();
    std::printf("D1_PARITY model=%s tokens=%zu max_prefix=%zu\n", model.c_str(), tokens.size(), max_prefix);
    for (size_t i = 0; i < tokens.size(); ++i) std::printf(" %u", tokens[i]);
    std::printf("\n");

    std::printf("ingesting %s ...\n", model.c_str());
    const Universal::IngestReport& rep = Universal::Ingest(model, false);
    if (!rep.ok) { std::printf("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }

    // ---- serial reference: one executor, per-position logits -----------------
    std::vector<std::vector<float>> serial_logits(tokens.size());
    {
        RuntimeGraph::Executor ex;
        if (!ex.Bind(rep)) { std::printf("SERIAL_BIND_FAIL: %s\n", ex.Stats().error.c_str()); return 1; }
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (!ex.ExecuteToken(tokens[i], i)) {
                std::printf("SERIAL_EXEC_FAIL pos=%zu err=%s\n", i, ex.LastError().c_str());
                return 1;
            }
            serial_logits[i] = ex.Logits();
        }
        std::printf("serial reference complete: %zu positions, %zu logits each\n",
                    serial_logits.size(), serial_logits.back().size());
    }

    // ---- check 1: prefix sweep, batched prefill vs serial per-position ------
    int mismatches = 0;
    double worst_abs = 0.0;
    size_t worst_k = 0;
    for (size_t k = 2; k <= max_prefix; ++k) {
        std::vector<uint32_t> prefix(tokens.begin(), tokens.begin() + (long)k);
        RuntimeGraph::Executor ex;
        if (!ex.Bind(rep)) { std::printf("BATCH_BIND_FAIL k=%zu: %s\n", k, ex.Stats().error.c_str()); return 1; }
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = ex.PrefillBatch(prefix, 0);
        const double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        if (!ok) {
            std::printf("PREFILL_BATCH_FAIL k=%zu: %s\n", k, ex.LastError().c_str());
            return 2;
        }
        const std::vector<float>& got = ex.Logits();
        const std::vector<float>& want = serial_logits[k - 1];
        bool same = got.size() == want.size() && std::memcmp(got.data(), want.data(),
                                                             want.size() * sizeof(float)) == 0;
        double maxabs = 0.0;
        if (!same && got.size() == want.size()) {
            for (size_t i = 0; i < want.size(); ++i)
                maxabs = std::max(maxabs, (double)std::fabs(got[i] - want[i]));
        }
        if (!same) {
            ++mismatches;
            if (maxabs > worst_abs) { worst_abs = maxabs; worst_k = k; }
        }
        std::printf("prefix k=%2zu: %s maxabs=%.6g (%.1f ms)\n", k,
                    same ? "BIT_EXACT" : "MISMATCH", maxabs, ms);
    }

    // ---- check 2: causal KV via continued decode on both paths ---------------
    RuntimeGraph::Executor ser;
    RuntimeGraph::Executor bat;
    if (!ser.Bind(rep) || !bat.Bind(rep)) { std::printf("CONT_BIND_FAIL\n"); return 1; }
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (!ser.ExecuteToken(tokens[i], i)) { std::printf("CONT_SERIAL_FAIL\n"); return 1; }
    }
    if (!bat.PrefillBatch(tokens, 0)) { std::printf("CONT_PREFILL_FAIL: %s\n", bat.LastError().c_str()); return 2; }
    // The batched prefill's final logits must equal the serial's final logits.
    {
        const std::vector<float>& a = bat.Logits();
        const std::vector<float>& b = serial_logits[tokens.size() - 1];
        const bool same = a.size() == b.size() && std::memcmp(a.data(), b.data(), b.size() * sizeof(float)) == 0;
        double maxabs = 0.0;
        if (!same && a.size() == b.size())
            for (size_t i = 0; i < b.size(); ++i)
                maxabs = std::max(maxabs, (double)std::fabs(a[i] - b[i]));
        std::printf("full-sequence final logits: %s maxabs=%.6g\n", same ? "BIT_EXACT" : "MISMATCH", maxabs);
        if (!same) ++mismatches, worst_abs = std::max(worst_abs, maxabs);
    }
    // Continue both with the argmax of the serial final logits, then decode.
    uint32_t next = 0;
    {
        const std::vector<float>& b = serial_logits[tokens.size() - 1];
        for (size_t i = 1; i < b.size(); ++i) if (b[i] > b[next]) next = (uint32_t)i;
    }
    std::string ser_stream, bat_stream;
    for (size_t d = 0; d < decode_steps; ++d) {
        const size_t pos = tokens.size() + d;
        if (!ser.ExecuteToken(next, pos) || !bat.ExecuteToken(next, pos)) {
            std::printf("CONT_DECODE_FAIL step=%zu\n", d);
            return 1;
        }
        const std::vector<float>& a = bat.Logits();
        const std::vector<float>& b = ser.Logits();
        const bool same = a.size() == b.size() && std::memcmp(a.data(), b.data(), b.size() * sizeof(float)) == 0;
        double maxabs = 0.0;
        if (!same && a.size() == b.size())
            for (size_t i = 0; i < b.size(); ++i)
                maxabs = std::max(maxabs, (double)std::fabs(a[i] - b[i]));
        uint32_t na = 0, nb = 0;
        for (size_t i = 1; i < a.size(); ++i) if (a[i] > a[na]) na = (uint32_t)i;
        for (size_t i = 1; i < b.size(); ++i) if (b[i] > b[nb]) nb = (uint32_t)i;
        char sb[32]; std::snprintf(sb, sizeof(sb), " %u", nb);
        ser_stream += sb;
        char bb[32]; std::snprintf(bb, sizeof(bb), " %u", na);
        bat_stream += bb;
        std::printf("decode step=%zu: logits %s maxabs=%.6g (serial argmax=%u, batched argmax=%u)\n",
                    d, same ? "BIT_EXACT" : "MISMATCH", maxabs, nb, na);
        if (!same) { ++mismatches; worst_abs = std::max(worst_abs, maxabs); }
        next = nb;
    }
    std::printf("serial stream:%s\nbatched stream:%s\n", ser_stream.c_str(), bat_stream.c_str());
    if (ser_stream != bat_stream) { ++mismatches; }

    std::printf("D1_PARITY mismatches=%d worst_maxabs=%.6g (worst prefix k=%zu)\n",
                mismatches, worst_abs, worst_k);
    std::printf("D1_PARITY_VERDICT=%s\n", mismatches == 0 ? "PASS" : "FAIL");
    return mismatches == 0 ? 0 : 3;
}
