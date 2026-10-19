// ============================================================================
// d1_prefill_verify.cpp — RAWRXD_DEEP2_D1 batched-prefill parity certification
// ============================================================================
// Certifies the batched multi-token prefill entry (Executor::ExecuteTokens)
// against the serial per-token loop at batch lengths 1, 2, 8, 32, and 128:
//
//   1. full-logit parity    : every position's complete logits must match the
//                             serial loop bit-for-bit (the batch changes no
//                             arithmetic, so anything else is a defect).
//   2. causal-KV equivalence: the KV footprint after the batch must equal the
//                             serial run's, and positions must not observe
//                             future tokens.
//   3. continuation          : prefill(K/2) + prefill(rest) must give the same
//                             final logits as one prefill(K) — the property a
//                             streaming/agentic caller depends on.
//
// Usage: d1_prefill_verify --model M.gguf --tokens "1 185 13 ..." [--gpu]
// Exit 0 iff every length passes. Machine-readable receipt on stdout; the
// JSON verdict is written to --json when given.
// ============================================================================
#include "universal_gguf.hpp"
#include "deep2/runtime_graph_executor.hpp"

#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using RawrXD::Deep2::RuntimeGraph::Executor;

namespace {

struct Cmp {
    bool bitexact = true;
    double max_diff = 0.0;
    size_t first_diff = (size_t)-1;
    size_t nonfinite = 0;
};

Cmp CompareLogits(const std::vector<float>& a, const std::vector<float>& b) {
    Cmp c;
    if (a.size() != b.size()) { c.bitexact = false; c.max_diff = 1e30; c.first_diff = 0; return c; }
    for (size_t i = 0; i < a.size(); ++i) {
        const float x = a[i], y = b[i];
        if (!std::isfinite(y)) ++c.nonfinite;
        if (x != y) {
            c.bitexact = false;
            if (c.first_diff == (size_t)-1) c.first_diff = i;
        }
        const double d = std::fabs((double)x - (double)y);
        if (d > c.max_diff) c.max_diff = d;
    }
    return c;
}

std::string G(float v) { char b[64]; std::snprintf(b, sizeof(b), "%.9g", v); return b; }

} // namespace

int main(int argc, char** argv) {
    std::string model, tokens_arg, json_out;
    bool gpu = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokens_arg = argv[++i];
        else if (a == "--gpu") gpu = true;
        else if (a == "--json" && i + 1 < argc) json_out = argv[++i];
        else if (a == "--help") {
            std::printf("usage: d1_prefill_verify --model M.gguf --tokens \"...\" [--gpu] [--json out.json]\n");
            return 0;
        }
    }
    if (model.empty() || tokens_arg.empty()) {
        std::printf("usage: d1_prefill_verify --model M.gguf --tokens \"...\" [--gpu]\n");
        return 2;
    }
    std::vector<uint32_t> tokens;
    {
        size_t p = 0;
        while (p < tokens_arg.size()) {
            while (p < tokens_arg.size() && std::isspace((unsigned char)tokens_arg[p])) ++p;
            if (p >= tokens_arg.size()) break;
            size_t q = p;
            while (q < tokens_arg.size() && !std::isspace((unsigned char)tokens_arg[q])) ++q;
            tokens.push_back((uint32_t)std::strtoul(tokens_arg.substr(p, q - p).c_str(), nullptr, 10));
            p = q;
        }
    }
    if (tokens.size() < 128) {
        std::printf("FAIL: need at least 128 tokens for the length ladder (got %zu)\n", tokens.size());
        return 2;
    }

    std::printf("=== D1 batched-prefill parity certification (%s) ===\n", gpu ? "gpu-native" : "cpu");
    std::printf("tokens=%zu model=%s\n", tokens.size(), model.c_str());

    const RawrXD::Deep2::Universal::IngestReport& rep =
        RawrXD::Deep2::Universal::Ingest(model, false);
    if (!rep.ok) { std::printf("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }
    std::printf("ingest ok: arch=%s blocks=%llu embd=%llu\n", rep.spec.architecture.c_str(),
                (unsigned long long)rep.spec.block_count, (unsigned long long)rep.spec.embd);

    const size_t lengths[] = {1, 2, 8, 32, 128};
    int failures = 0;
    std::string json_rows;
    for (size_t li = 0; li < sizeof(lengths) / sizeof(lengths[0]); ++li) {
        const size_t L = lengths[li];

        // ---- serial reference ------------------------------------------------
        Executor serial;
        serial.SetForceCpu(!gpu);
        if (!serial.Bind(rep)) { std::printf("BIND_FAIL(serial): %s\n", serial.Stats().error.c_str()); return 1; }
        std::vector<std::vector<float>> serial_logits(L);
        for (size_t p = 0; p < L; ++p) {
            if (!serial.ExecuteToken(tokens[p], p)) {
                std::printf("EXEC_FAIL serial pos=%zu: %s\n", p, serial.LastError().c_str());
                return 1;
            }
            serial_logits[p] = serial.Logits();
        }
        size_t serial_kv = 0;
        for (const auto& k : serial.kv_k_debug()) serial_kv += k.size();

        // ---- batched path ----------------------------------------------------
        Executor batch;
        batch.SetForceCpu(!gpu);
        if (!batch.Bind(rep)) { std::printf("BIND_FAIL(batch): %s\n", batch.Stats().error.c_str()); return 1; }
        const auto tb0 = std::chrono::steady_clock::now();
        if (!batch.ExecuteTokens(tokens.data(), L, 0, /*capture=*/true)) {
            std::printf("EXEC_FAIL batched L=%zu: %s\n", L, batch.LastError().c_str());
            return 1;
        }
        const double batch_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - tb0).count();
        const auto& ps = batch.LastPrefill();
        size_t batch_kv = 0;
        for (const auto& k : batch.kv_k_debug()) batch_kv += k.size();

        // ---- continuation: split prefill must equal whole prefill -------------
        Executor cont;
        cont.SetForceCpu(!gpu);
        if (!cont.Bind(rep)) { std::printf("BIND_FAIL(cont): %s\n", cont.Stats().error.c_str()); return 1; }
        const size_t split = L / 2;
        bool cont_ok = true;
        std::string cont_err;
        if (!cont.ExecuteTokens(tokens.data(), split, 0, false)) {
            cont_ok = false; cont_err = cont.LastError();
        } else if (!cont.ExecuteTokens(tokens.data() + split, L - split, split, false)) {
            cont_ok = false; cont_err = cont.LastError();
        }
        Cmp cont_cmp;
        if (cont_ok) cont_cmp = CompareLogits(serial_logits[L - 1], cont.Logits());

        // ---- comparisons ------------------------------------------------------
        Cmp worst;
        int pos_match = 0;
        for (size_t p = 0; p < L; ++p) {
            const Cmp c = CompareLogits(serial_logits[p], batch.PrefillLogits()[p]);
            if (c.max_diff > worst.max_diff) worst = c;
            if (!c.bitexact) ++failures;
            if (batch.PrefillLogits()[p] == serial_logits[p]) ++pos_match;
        }
        const bool kv_equal = (serial_kv == batch_kv);
        const bool length_pass = worst.bitexact && kv_equal && cont_ok && cont_cmp.bitexact;
        if (!length_pass) ++failures;

        std::printf("L=%-4zu positions_bit_equal=%d/%zu kv_bytes serial=%zu batch=%zu(%s) "
                    "cont=%s(maxdiff=%s) max_diff=%s first_diff=%zu nonfinite=%zu :: %s\n",
                    L, pos_match, L, serial_kv, batch_kv, kv_equal ? "equal" : "DIFFER",
                    cont_ok ? (cont_cmp.bitexact ? "bit-equal" : "DIFFERS") : "FAILED",
                    cont_ok ? G(cont_cmp.max_diff).c_str() : cont_err.c_str(),
                    G(worst.max_diff).c_str(), worst.first_diff, worst.nonfinite,
                    length_pass ? "PASS" : "FAIL");
        std::printf("      timing: total=%.1fms first=%.1fms steady_mean=%.1fms\n",
                    batch_ms, ps.first_token_ms, ps.steady_token_ms);

        if (!json_rows.empty()) json_rows += ",";
        json_rows += "{\"length\":" + std::to_string(L) +
                     ",\"bit_exact\":" + (worst.bitexact ? "true" : "false") +
                     ",\"kv_equal\":" + (kv_equal ? "true" : "false") +
                     ",\"continuation_bit_equal\":" + ((cont_ok && cont_cmp.bitexact) ? "true" : "false") +
                     ",\"max_diff\":" + G(worst.max_diff) +
                     ",\"total_ms\":" + G(batch_ms) +
                     ",\"first_token_ms\":" + G(ps.first_token_ms) +
                     ",\"steady_token_ms\":" + G(ps.steady_token_ms) +
                     ",\"verdict\":\"" + (length_pass ? "PASS" : "FAIL") + "\"}";
    }

    const bool all_pass = failures == 0;
    std::printf(all_pass ? "D1_RESULT: PASS\n" : "D1_RESULT: FAIL (%d failing position comparisons)\n", failures);
    if (!json_out.empty()) {
        FILE* f = std::fopen(json_out.c_str(), "w");
        if (f) {
            std::fprintf(f, "{\"tool\":\"d1_prefill_verify\",\"model\":\"%s\",\"gpu\":%s,"
                            "\"lengths\":[%s],\"result\":\"%s\"}\n",
                         model.c_str(), gpu ? "true" : "false", json_rows.c_str(),
                         all_pass ? "PASS" : "FAIL");
            std::fclose(f);
            std::printf("json written: %s\n", json_out.c_str());
        }
    }
    return all_pass ? 0 : 1;
}
