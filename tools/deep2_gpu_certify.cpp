// ============================================================================
// deep2_gpu_certify.cpp -- RAWRXD_DEEP2_GPU_QUANT_DOT_003
// ============================================================================
// Certifies the NATIVE GPU quant-dot path end to end on real GGUF weights:
//   * runs the full transformer forward with the GPU path enabled (no CPU pin)
//   * reports gpu_calls / cpu_calls / the exact fallback reason, if any
//   * re-runs the identical sequence CPU-pinned and compares the full logit
//     vectors of both executions (cosine, max_abs, argmax agreement)
//   * requires finite logits over the whole vocabulary
//
// With --reference-dir, certification requires zero CPU fallback, finite
// full-vocabulary logits, and argmax/cosine/max-error agreement with the
// independent reference at every tested position. The CPU-pinned executor is
// retained as a diagnostic comparison and is not the absolute oracle.
//
// Usage: deep2_gpu_certify.exe --model <gguf> [--tokens "1 185" ]
//        [--reference-dir <independent logits directory>] [--dump <dir>]
// ============================================================================
#include <chrono>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"

using namespace RawrXD::Deep2;

namespace {

bool WriteLogits(const std::string& path, const std::vector<float>& v) {
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const size_t n = std::fwrite(v.data(), sizeof(float), v.size(), f);
    std::fclose(f);
    return n == v.size();
}

size_t FiniteCount(const std::vector<float>& v) {
    size_t n = 0;
    for (float x : v) if (std::isfinite(x)) ++n;
    return n;
}

std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 16);
    for (const unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

struct CertificationReceipt {
    std::string model;
    std::string status = "NOT_STARTED";
    std::string execution_status = "NOT_RUN";
    std::string certification_status = "NOT_CERTIFIED";
    std::string reason;
    std::string architecture;
    std::string provenance_sha256;
    std::string reference_dir;
    uint64_t elapsed_ms = 0;
    uint64_t mapped_bytes = 0;
    uint32_t shard_count = 0;
    size_t tensor_count = 0;
    size_t resolved_tensors = 0;
    size_t unmapped_tensors = 0;
    size_t unsupported_ops = 0;
    size_t token_count = 0;
    uint64_t gpu_calls = 0;
    uint64_t cpu_calls = 0;
    size_t nonfinite_logits = 0;
    bool gpu_cpu_internal_parity = false;
    bool independent_reference_parity = false;
    size_t reference_positions = 0;
    size_t reference_failures = 0;
    double reference_min_cosine = 0.0;
    double reference_max_abs = 0.0;
};

bool WriteReceipt(const std::string& dump, const CertificationReceipt& r) {
    std::error_code ec;
    std::filesystem::create_directories(dump, ec);
    if (ec) return false;
    std::ofstream out(std::filesystem::path(dump) / "full_model_receipt.json",
                      std::ios::binary | std::ios::trunc);
    if (!out) return false;
    out << "{\n"
        << "  \"model\":\"" << JsonEscape(r.model) << "\",\n"
        << "  \"status\":\"" << JsonEscape(r.status) << "\",\n"
        << "  \"execution_status\":\"" << JsonEscape(r.execution_status) << "\",\n"
        << "  \"certification_status\":\"" << JsonEscape(r.certification_status) << "\",\n"
        << "  \"reason\":\"" << JsonEscape(r.reason) << "\",\n"
        << "  \"architecture\":\"" << JsonEscape(r.architecture) << "\",\n"
        << "  \"provenance_sha256\":\"" << JsonEscape(r.provenance_sha256) << "\",\n"
        << "  \"reference_dir\":\"" << JsonEscape(r.reference_dir) << "\",\n"
        << "  \"elapsed_ms\":" << r.elapsed_ms << ",\n"
        << "  \"mapped_bytes\":" << r.mapped_bytes << ",\n"
        << "  \"shard_count\":" << r.shard_count << ",\n"
        << "  \"tensor_count\":" << r.tensor_count << ",\n"
        << "  \"resolved_tensors\":" << r.resolved_tensors << ",\n"
        << "  \"unmapped_tensors\":" << r.unmapped_tensors << ",\n"
        << "  \"unsupported_ops\":" << r.unsupported_ops << ",\n"
        << "  \"token_count\":" << r.token_count << ",\n"
        << "  \"gpu_calls\":" << r.gpu_calls << ",\n"
        << "  \"cpu_calls\":" << r.cpu_calls << ",\n"
        << "  \"nonfinite_logits\":" << r.nonfinite_logits << ",\n"
        << "  \"gpu_cpu_internal_parity\":" << (r.gpu_cpu_internal_parity ? "true" : "false") << ",\n"
        << "  \"independent_reference_parity\":" << (r.independent_reference_parity ? "true" : "false") << ",\n"
        << "  \"reference_positions\":" << r.reference_positions << ",\n"
        << "  \"reference_failures\":" << r.reference_failures << ",\n"
        << "  \"reference_min_cosine\":" << std::setprecision(10) << r.reference_min_cosine << ",\n"
        << "  \"reference_max_abs\":" << std::setprecision(10) << r.reference_max_abs << "\n"
        << "}\n";
    return static_cast<bool>(out);
}

bool ReadLogits(const std::string& path, std::vector<float>& values) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) return false;
    const std::streamoff bytes = in.tellg();
    if (bytes < 0 || bytes % static_cast<std::streamoff>(sizeof(float)) != 0) return false;
    values.resize(static_cast<size_t>(bytes / static_cast<std::streamoff>(sizeof(float))));
    in.seekg(0, std::ios::beg);
    return values.empty() || static_cast<bool>(in.read(reinterpret_cast<char*>(values.data()), bytes));
}

}  // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    const auto started = std::chrono::steady_clock::now();
    std::string model, tokensArg = "1 185", dump = "gpu_certify", reference;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokensArg = argv[++i];
        else if (a == "--dump" && i + 1 < argc) dump = argv[++i];
        else if (a == "--reference-dir" && i + 1 < argc) reference = argv[++i];
        else { std::printf("unknown arg %s\n", a.c_str()); return 1; }
    }
    CertificationReceipt receipt;
    receipt.model = model;
    receipt.reference_dir = reference;
    std::error_code mkdir_error;
    std::filesystem::create_directories(dump, mkdir_error);
    auto finish = [&](int code, const char* status, const std::string& reason) {
        receipt.status = status;
        receipt.reason = reason;
        receipt.elapsed_ms = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
        WriteReceipt(dump, receipt);
        std::printf("CERT_STATUS=%s\nCERTIFICATION_STATUS=%s\nRECEIPT=%s/full_model_receipt.json\n",
                    receipt.status.c_str(), receipt.certification_status.c_str(), dump.c_str());
        return code;
    };
    if (mkdir_error) {
        return finish(1, "FAIL_RECEIPT_PATH", "cannot create dump directory: " + mkdir_error.message());
    }
    if (model.empty()) {
        std::printf("usage: deep2_gpu_certify.exe --model <gguf> [--tokens \"1 185\"] [--dump DIR]\n");
        return finish(1, "FAIL_ARGUMENTS", "--model is required");
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
    if (tokens.empty()) { std::printf("no tokens\n"); return finish(1, "FAIL_ARGUMENTS", "no valid token ids"); }
    receipt.token_count = tokens.size();
    std::printf("tokens:");
    for (auto t : tokens) std::printf(" %u", t);
    std::printf("\n");

    const Universal::IngestReport& rep = Universal::Ingest(model, false);
    if (!rep.ok) {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return finish(1, "BLOCKED_INGEST", rep.error);
    }
    const Universal::Provenance& provenance = Universal::GetProvenance();
    receipt.architecture = rep.spec.architecture;
    receipt.provenance_sha256 = provenance.sha256;
    receipt.mapped_bytes = rep.mapped_bytes ? rep.mapped_bytes : provenance.file_bytes;
    receipt.shard_count = rep.shard_count;
    receipt.tensor_count = rep.tensors.size();
    receipt.resolved_tensors = rep.resolved;
    for (const auto& tensor : rep.tensors) {
        if (!tensor.data || tensor.bytes == 0 || tensor.dims.empty()) ++receipt.unmapped_tensors;
    }
    receipt.unsupported_ops = rep.graph.unsupported;
    if (receipt.unmapped_tensors != 0 || receipt.resolved_tensors != receipt.tensor_count) {
        const std::string reason = "full tensor map incomplete: mapped=" +
            std::to_string(receipt.tensor_count - receipt.unmapped_tensors) +
            " total=" + std::to_string(receipt.tensor_count);
        return finish(2, "BLOCKED_INCOMPLETE_MODEL", reason);
    }
    if (receipt.unsupported_ops != 0) {
        std::string reason = "native graph contains " + std::to_string(receipt.unsupported_ops) + " unsupported operator(s)";
        bool first = true;
        for (const auto& op : rep.graph.ops) {
            const bool qwen4exp_blocker =
                op.op == Universal::Op::Qsa || op.op == Universal::Op::Gdn ||
                op.op == Universal::Op::Ple ||
                op.op == Universal::Op::Hyperconnection ||
                op.op == Universal::Op::SparseMoE;
            if ((!qwen4exp_blocker && op.op != Universal::Op::Unsupported) ||
                op.detail.empty()) continue;
            reason += first ? ": " : "; ";
            reason += op.detail;
            first = false;
        }
        return finish(2, "BLOCKED_NATIVE_GRAPH", reason);
    }
    std::printf("arch=%s blocks=%llu embd=%llu vocab=%llu experts=%llu used=%llu\n",
                rep.spec.architecture.c_str(), (unsigned long long)rep.spec.block_count,
                (unsigned long long)rep.spec.embd, (unsigned long long)rep.spec.vocab,
                (unsigned long long)rep.spec.expert_count,
                (unsigned long long)rep.spec.expert_used);

    // ---- GPU path (no CPU pin) --------------------------------------------
    std::vector<std::vector<float>> gpuLogits;
    {
        RuntimeGraph::Executor ex;
        if (!ex.Bind(rep)) {
            std::printf("BIND_FAIL(gpu): %s\n", ex.Stats().error.c_str());
            return finish(2, "BLOCKED_GPU_BIND", ex.Stats().error);
        }
        std::printf("[gpu] bound ops=%zu\n", ex.Stats().ops_total);
        for (size_t pos = 0; pos < tokens.size(); ++pos) {
            const auto t0 = std::chrono::steady_clock::now();
            const bool ok = ex.ExecuteToken(tokens[pos], pos);
            const auto t1 = std::chrono::steady_clock::now();
            if (!ok) {
                std::printf("EXEC_FAIL(gpu) pos=%zu err=%s\n", pos, ex.LastError().c_str());
                receipt.gpu_calls = ex.Stats().gpu_calls;
                receipt.cpu_calls = ex.Stats().cpu_calls;
                return finish(1, "FAIL_GPU_EXECUTION", ex.LastError());
            }
            gpuLogits.push_back(ex.Logits());
            std::printf("[gpu] pos=%zu token=%u %.1f ms ops=%zu\n", pos, tokens[pos],
                        std::chrono::duration<double, std::milli>(t1 - t0).count(),
                        ex.Stats().ops_total);
        }
        std::printf("[gpu] gpu_calls=%llu cpu_calls=%llu fallback=%s\n",
                    (unsigned long long)ex.Stats().gpu_calls,
                    (unsigned long long)ex.Stats().cpu_calls,
                    ex.Stats().fallback_reason.empty() ? "<none>" : ex.Stats().fallback_reason.c_str());
        receipt.gpu_calls = ex.Stats().gpu_calls;
        receipt.cpu_calls = ex.Stats().cpu_calls;
        if (receipt.gpu_calls == 0 || receipt.cpu_calls != 0) {
            return finish(2, "BLOCKED_GPU_FALLBACK", "GPU execution did not remain GPU-only");
        }
    }

    // ---- CPU-pinned reference (fresh executor, identical sequence) --------
    std::vector<std::vector<float>> cpuLogits;
    {
        RuntimeGraph::Executor ex;
        ex.SetForceCpu(true);
        if (!ex.Bind(rep)) {
            std::printf("BIND_FAIL(cpu): %s\n", ex.Stats().error.c_str());
            return finish(1, "FAIL_CPU_REFERENCE", ex.Stats().error);
        }
        for (size_t pos = 0; pos < tokens.size(); ++pos) {
            if (!ex.ExecuteToken(tokens[pos], pos)) {
                std::printf("EXEC_FAIL(cpu) pos=%zu err=%s\n", pos, ex.LastError().c_str());
                return finish(1, "FAIL_CPU_REFERENCE", ex.LastError());
            }
            cpuLogits.push_back(ex.Logits());
        }
        std::printf("[cpu] cpu_calls=%llu\n", (unsigned long long)ex.Stats().cpu_calls);
    }

    // ---- comparison -------------------------------------------------------
    bool internal_pass = true;
    bool reference_pass = !reference.empty();
    double reference_min_cosine = 1.0;
    double reference_max_abs = 0.0;
    size_t reference_positions = 0;
    size_t reference_failures = 0;
    size_t nonfinite_total = 0;
    for (size_t pos = 0; pos < tokens.size(); ++pos) {
        const std::vector<float>& g = gpuLogits[pos];
        const std::vector<float>& c = cpuLogits[pos];
        if (g.empty() || c.empty() || g.size() != c.size()) {
            std::printf("pos=%zu: invalid logits gpu=%zu cpu=%zu\n", pos, g.size(), c.size());
            internal_pass = false;
            continue;
        }
        const size_t n = std::min(g.size(), c.size());
        uint32_t ag = 0, ac = 0;
        double dot = 0, ng = 0, nc = 0, mx = 0;
        size_t finite = 0;
        for (size_t i = 0; i < n; ++i) {
            if (g[i] > g[ag]) ag = (uint32_t)i;
            if (c[i] > c[ac]) ac = (uint32_t)i;
            dot += double(g[i]) * double(c[i]);
            ng += double(g[i]) * double(g[i]);
            nc += double(c[i]) * double(c[i]);
            const double d = std::fabs(double(g[i]) - double(c[i]));
            if (d > mx) mx = d;
            if (std::isfinite(g[i])) ++finite;
        }
        const double cos = ng > 0 && nc > 0 ? dot / (std::sqrt(ng) * std::sqrt(nc)) : 0.0;
        nonfinite_total += g.size() - finite;
        const bool ok = (finite == g.size()) && ag == ac && cos >= 0.999 && mx < 5.0;
        std::printf("pos=%zu vocab=%zu finite=%zu gpu_argmax=%u cpu_argmax=%u cos=%.7f max_abs=%.4g %s\n",
                    pos, g.size(), finite, ag, ac, cos, mx, ok ? "PASS" : "FAIL");
        if (!ok) internal_pass = false;
        char p1[512], p2[512];
        std::snprintf(p1, sizeof(p1), "%s/gpu_logits_pos%zu.bin", dump.c_str(), pos);
        std::snprintf(p2, sizeof(p2), "%s/cpu_logits_pos%zu.bin", dump.c_str(), pos);
        WriteLogits(p1, g);
        WriteLogits(p2, c);

        if (!reference.empty()) {
            std::vector<float> ref;
            char rp[512];
            std::snprintf(rp, sizeof(rp), "%s/ref_logits_pos%zu.bin", reference.c_str(), pos);
            bool loaded = ReadLogits(rp, ref);
            if (!loaded) {
                std::snprintf(rp, sizeof(rp), "%s/reference_logits_pos%zu.bin", reference.c_str(), pos);
                loaded = ReadLogits(rp, ref);
            }
            bool ref_ok = loaded && ref.size() == g.size();
            uint32_t ar = 0;
            double ref_dot = 0.0, ref_ng = 0.0, ref_nr = 0.0, ref_max = 0.0;
            if (ref_ok) {
                for (size_t i = 0; i < g.size(); ++i) {
                    if (!std::isfinite(ref[i])) { ref_ok = false; break; }
                    if (ref[i] > ref[ar]) ar = static_cast<uint32_t>(i);
                    ref_dot += double(g[i]) * double(ref[i]);
                    ref_ng += double(g[i]) * double(g[i]);
                    ref_nr += double(ref[i]) * double(ref[i]);
                    ref_max = std::max(ref_max, std::fabs(double(g[i]) - double(ref[i])));
                }
            }
            const double ref_cos = ref_ng > 0.0 && ref_nr > 0.0
                ? ref_dot / (std::sqrt(ref_ng) * std::sqrt(ref_nr)) : 0.0;
            ref_ok = ref_ok && std::isfinite(ref_cos) && ar == ag &&
                     ref_cos >= 0.99 && ref_max < 2.0;
            ++reference_positions;
            reference_min_cosine = std::min(reference_min_cosine, ref_cos);
            reference_max_abs = std::max(reference_max_abs, ref_max);
            if (!ref_ok) ++reference_failures;
            std::printf("pos=%zu independent_reference=%s cos=%.7f max_abs=%.4g %s\n",
                        pos, loaded ? "loaded" : "missing", ref_cos, ref_max,
                        ref_ok ? "PASS" : "FAIL");
        }
    }
    receipt.nonfinite_logits = nonfinite_total;
    receipt.gpu_cpu_internal_parity = internal_pass;
    receipt.reference_positions = reference_positions;
    receipt.reference_failures = reference_failures;
    receipt.reference_min_cosine = reference_positions ? reference_min_cosine : 0.0;
    receipt.reference_max_abs = reference_max_abs;
    receipt.independent_reference_parity = reference_positions != 0 && reference_failures == 0;
    reference_pass = receipt.independent_reference_parity;
    if (!reference.empty() && !reference_pass) {
        receipt.execution_status = "FAIL";
        return finish(1, "FAIL_REFERENCE_PARITY", "GPU output failed independent reference parity");
    }
    receipt.execution_status = internal_pass ? "PASS" : "PASS_WITH_INTERNAL_DIAGNOSTIC";
    if (reference.empty()) {
        receipt.certification_status = "BLOCKED_NO_INDEPENDENT_REFERENCE";
        std::printf("VERDICT=PASS_INTERNAL_ONLY\n");
        return finish(2, "EXECUTION_PASS_NOT_CERTIFIED",
                      "GPU/CPU comparison passed, but no independent reference logits were supplied");
    }
    receipt.certification_status = "FULL_MODEL_CERTIFIED";
    std::printf("VERDICT=PASS_FULL_MODEL\n");
    return finish(0, "PASS_FULL_MODEL", "full model executed with GPU-only path and independent reference parity");
}
