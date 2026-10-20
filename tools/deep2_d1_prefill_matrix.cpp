// D1 native multi-token prefill matrix. This invokes Executor::PrefillBatch
// directly and compares every position's complete vocabulary logits, actual
// FP32 K/V payloads, executor position/token state, and incremental continuation.
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "quant_dot_dispatch.hpp"

using RawrXD::Deep2::RuntimeGraph::Executor;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;
using RawrXD::Deep2::QuantDot::BackendCounters;

namespace {
struct Diff {
    bool same = true;
    size_t elements = 0;
    double max_abs = 0.0;
};

Diff Compare(const std::vector<float>& a, const std::vector<float>& b) {
    Diff d;
    d.elements = a.size();
    if (a.size() != b.size()) {
        d.same = false;
        d.max_abs = INFINITY;
        return d;
    }
    if (!a.empty() && std::memcmp(a.data(), b.data(), a.size() * sizeof(float)) == 0)
        return d;
    d.same = false;
    for (size_t i = 0; i < a.size(); ++i)
        d.max_abs = std::max(d.max_abs, std::fabs(double(a[i]) - double(b[i])));
    return d;
}

uint64_t Delta(uint64_t after, uint64_t before) {
    return after >= before ? after - before : 0;
}

std::vector<uint32_t> MakeTokens(size_t count, size_t vocab) {
    std::vector<uint32_t> out;
    out.reserve(count);
    if (vocab < 2) return out;
    for (size_t i = 0; i < count; ++i)
        out.push_back(static_cast<uint32_t>(1 + ((i * 37u + 13u) % (vocab - 1))));
    return out;
}

bool CompareKv(const Executor& serial, const Executor& batch, size_t positions,
               size_t& compared_floats, double& max_abs) {
    bool same = true;
    compared_floats = 0;
    max_abs = 0.0;
    if (serial.KvBlocks() != batch.KvBlocks()) return false;
    for (size_t b = 0; b < serial.KvBlocks(); ++b) {
        const size_t sk = serial.KvRowWidthK(static_cast<int>(b));
        const size_t sv = serial.KvRowWidthV(static_cast<int>(b));
        const size_t bk = batch.KvRowWidthK(static_cast<int>(b));
        const size_t bv = batch.KvRowWidthV(static_cast<int>(b));
        if (sk != bk || sv != bv || serial.KvRows(static_cast<int>(b)) < positions ||
            batch.KvRows(static_cast<int>(b)) < positions || sk == 0 || sv == 0) {
            same = false;
            continue;
        }
        for (size_t p = 0; p < positions; ++p) {
            const auto skrow = serial.KvKRow(static_cast<int>(b), p);
            const auto bkrow = batch.KvKRow(static_cast<int>(b), p);
            const auto svrow = serial.KvVRow(static_cast<int>(b), p);
            const auto bvrow = batch.KvVRow(static_cast<int>(b), p);
            const Diff kd = Compare(skrow, bkrow);
            const Diff vd = Compare(svrow, bvrow);
            compared_floats += kd.elements + vd.elements;
            max_abs = std::max(max_abs, std::max(kd.max_abs, vd.max_abs));
            same = same && kd.same && vd.same;
        }
    }
    return same;
}

bool CompareKvPosition(const Executor& serial, const Executor& batch, size_t position,
                       size_t& compared_floats, double& max_abs) {
    bool same = serial.KvBlocks() == batch.KvBlocks();
    compared_floats = 0;
    max_abs = 0.0;
    if (!same) return false;
    for (size_t b = 0; b < serial.KvBlocks(); ++b) {
        if (serial.KvRowWidthK(static_cast<int>(b)) != batch.KvRowWidthK(static_cast<int>(b)) ||
            serial.KvRowWidthV(static_cast<int>(b)) != batch.KvRowWidthV(static_cast<int>(b)) ||
            serial.KvRows(static_cast<int>(b)) <= position ||
            batch.KvRows(static_cast<int>(b)) <= position) {
            same = false;
            continue;
        }
        const Diff kd = Compare(serial.KvKRow(static_cast<int>(b), position),
                                batch.KvKRow(static_cast<int>(b), position));
        const Diff vd = Compare(serial.KvVRow(static_cast<int>(b), position),
                                batch.KvVRow(static_cast<int>(b), position));
        compared_floats += kd.elements + vd.elements;
        max_abs = std::max(max_abs, std::max(kd.max_abs, vd.max_abs));
        same = same && kd.same && vd.same;
    }
    return same;
}
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::string model;
    size_t count = 129; // positions 0..127 plus one incremental continuation token
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--model" && i + 1 < argc) model = argv[++i];
        else if (arg == "--count" && i + 1 < argc)
            count = static_cast<size_t>(std::strtoull(argv[++i], nullptr, 10));
        else {
            std::printf("usage: deep2_d1_prefill_matrix.exe --model <gguf> [--count 129]\n");
            return 2;
        }
    }
    if (model.empty() || count < 129) {
        std::printf("D1_ARGUMENT_FAIL model_required_and_count_must_cover_128_plus_continuation\n");
        return 2;
    }

    std::error_code size_error;
    const uintmax_t model_bytes = std::filesystem::file_size(model, size_error);
    if (size_error) {
        std::printf("D1_MODEL_STAT_FAIL %s\n", size_error.message().c_str());
        return 3;
    }
    std::printf("D1_MODEL path=%s bytes=%llu\n", model.c_str(),
                static_cast<unsigned long long>(model_bytes));
    const std::string model_sha = RawrXD::Deep2::Universal::Sha256File(model);
    std::printf("D1_MODEL_SHA256 %s\n", model_sha.c_str());
    const IngestReport& report = Ingest(model, false);
    if (!report.ok) {
        std::printf("D1_INGEST_FAIL %s\n", report.error.c_str());
        return 3;
    }
    std::printf("D1_MODEL_SPEC arch=%s vocab=%llu blocks=%llu embd=%llu gpu_quant_capable=%zu\n",
                report.spec.architecture.c_str(),
                static_cast<unsigned long long>(report.spec.vocab),
                static_cast<unsigned long long>(report.spec.block_count),
                static_cast<unsigned long long>(report.spec.embd), report.gpu_quant_capable);
    for (const auto& tensor : report.tensors) {
        if (tensor.name == "output.weight" || tensor.name == "lm_head.weight" ||
            tensor.name == "token_embd.weight") {
            std::printf("D1_RELEVANT_TENSOR name=%s type=%u dims0=%llu dims1=%llu bytes=%zu\n",
                        tensor.name.c_str(), static_cast<unsigned>(tensor.ggml_type),
                        static_cast<unsigned long long>(tensor.dims.empty() ? 0 : tensor.dims[0]),
                        static_cast<unsigned long long>(tensor.dims.size() > 1 ? tensor.dims[1] : 0),
                        tensor.bytes);
        }
    }
    const std::vector<uint32_t> tokens = MakeTokens(count, static_cast<size_t>(report.spec.vocab));
    if (tokens.size() != count) {
        std::printf("D1_TOKEN_GENERATION_FAIL vocab=%llu\n",
                    static_cast<unsigned long long>(report.spec.vocab));
        return 3;
    }
    std::printf("D1_INPUT_TOKEN_IDS");
    for (uint32_t token : tokens) std::printf(" %u", token);
    std::printf("\n");

    // Serial GPU reference supplies every position's full vocabulary logits
    // and the authoritative KV payload for all required prefixes.
    Executor serial;
    if (!serial.Bind(report)) {
        std::printf("D1_SERIAL_BIND_FAIL %s\n", serial.Stats().error.c_str());
        return 4;
    }
    std::vector<std::vector<float>> serial_logits(count);
    const auto serial_start = std::chrono::steady_clock::now();
    for (size_t p = 0; p < count; ++p) {
        if (!serial.ExecuteToken(tokens[p], p)) {
            std::printf("D1_SERIAL_EXEC_FAIL pos=%zu error=%s\n", p, serial.LastError().c_str());
            return 4;
        }
        serial_logits[p] = serial.Logits();
    }
    const double serial_ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - serial_start).count();
    bool serial_full_vocab = true;
    for (const auto& row : serial_logits)
        serial_full_vocab = serial_full_vocab && row.size() == report.spec.vocab;
    std::printf("D1_SERIAL_DONE tokens=%zu logits_per_position=%zu full_vocab=%s gpu_calls=%llu cpu_fallback_calls=%llu elapsed_ms=%.3f\n",
                count, serial_logits.back().size(), serial_full_vocab ? "YES" : "NO",
                static_cast<unsigned long long>(serial.Stats().gpu_calls),
                static_cast<unsigned long long>(serial.Stats().cpu_calls), serial_ms);
    if (!serial_full_vocab || serial.Stats().cpu_calls != 0) {
        std::printf("D1_SERIAL_GPU_ONLY_FAIL cpu_calls=%llu fallback=%s\n",
                    static_cast<unsigned long long>(serial.Stats().cpu_calls),
                    serial.Stats().fallback_reason.c_str());
        return 4;
    }

    const size_t required[] = {1, 2, 8, 32, 128};
    size_t total_logit_floats = 0;
    size_t total_kv_floats = 0;
    size_t total_batch_submissions = 0;
    size_t total_batch_dots = 0;
    int failures = 0;
    for (size_t k : required) {
        std::vector<uint32_t> prefix(tokens.begin(), tokens.begin() + static_cast<ptrdiff_t>(k));
        Executor batch;
        if (!batch.Bind(report)) {
            std::printf("D1_BATCH_BIND_FAIL length=%zu error=%s\n", k, batch.Stats().error.c_str());
            return 5;
        }
        std::vector<std::vector<float>> batch_logits;
        const auto backend_before = BackendCounters();
        const auto t0 = std::chrono::steady_clock::now();
        if (!batch.PrefillBatch(prefix, 0, &batch_logits)) {
            std::printf("D1_BATCH_EXEC_FAIL length=%zu error=%s cpu_calls=%llu fallback=%s\n",
                        k, batch.LastError().c_str(),
                        static_cast<unsigned long long>(batch.Stats().cpu_calls),
                        batch.Stats().fallback_reason.c_str());
            return 6;
        }
        const double batch_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        const auto backend_after = BackendCounters();

        bool full_vocab = batch_logits.size() == k && serial_full_vocab;
        for (const auto& row : batch_logits)
            full_vocab = full_vocab && row.size() == report.spec.vocab;
        bool logits_same = full_vocab;
        size_t logits_floats = 0;
        double logits_max_abs = 0.0;
        for (size_t p = 0; p < std::min(k, batch_logits.size()); ++p) {
            const Diff d = Compare(batch_logits[p], serial_logits[p]);
            logits_floats += d.elements;
            logits_max_abs = std::max(logits_max_abs, d.max_abs);
            logits_same = logits_same && d.same;
        }
        const Diff last_d = Compare(batch.Logits(), serial_logits[k - 1]);
        logits_same = logits_same && last_d.same;

        size_t kv_floats = 0;
        double kv_max_abs = 0.0;
        const bool kv_same = CompareKv(serial, batch, k, kv_floats, kv_max_abs);
        const bool state_same = batch.Position() == k - 1 && batch.LastToken() == tokens[k - 1] &&
                                batch.CommittedKvTokens() == k;
        const uint64_t batch_submissions = batch.GpuBatchSubmissions();
        const uint64_t batch_dots = batch.GpuBatchDots();
        const uint64_t vk_submits = Delta(backend_after.submits, backend_before.submits);
        const uint64_t vk_waits = Delta(backend_after.waits, backend_before.waits);
        const uint64_t lmhead_batches = batch.GpuLmHeadBatchSubmissions();
        const uint64_t lmhead_positions = batch.GpuLmHeadBatchPositions();
        const bool gpu_only = batch.Stats().cpu_calls == 0 && batch_submissions > 0 &&
                              batch_dots > 0 && batch.Stats().gpu_calls > 0 &&
                              vk_submits > 0 && vk_waits > 0;
        const bool grouped_work = vk_submits < batch_dots && vk_waits < batch_dots;
        const bool pass = logits_same && kv_same && state_same && gpu_only && grouped_work;
        total_logit_floats += logits_floats;
        total_kv_floats += kv_floats;
        total_batch_submissions += static_cast<size_t>(batch_submissions);
        total_batch_dots += static_cast<size_t>(batch_dots);
        if (!pass) ++failures;
        std::printf("D1_LENGTH=%zu verdict=%s full_vocab=%s per_position_logits=%s logits_positions=%zu/%zu logits_floats=%zu max_abs=%.9g kv_payload=%s kv_floats=%zu kv_max_abs=%.9g state=%s position=%zu last_token=%u committed_kv=%zu gpu_only=%s grouped_work=%s gpu_calls=%llu cpu_calls=%llu batch_submissions=%llu batch_dots=%llu lmhead_batch_submissions=%llu lmhead_batch_positions=%llu vulkan_submit_delta=%llu vulkan_wait_delta=%llu elapsed_ms=%.3f\n",
                    k, pass ? "PASS" : "FAIL", full_vocab ? "YES" : "NO",
                    logits_same ? "BIT_EXACT" : "MISMATCH",
                    batch_logits.size(), k, logits_floats, logits_max_abs,
                    kv_same ? "BIT_EXACT" : "MISMATCH", kv_floats, kv_max_abs,
                    state_same ? "MATCH" : "MISMATCH", batch.Position(), batch.LastToken(),
                    batch.CommittedKvTokens(), gpu_only ? "YES" : "NO",
                    grouped_work ? "YES" : "NO",
                    static_cast<unsigned long long>(batch.Stats().gpu_calls),
                    static_cast<unsigned long long>(batch.Stats().cpu_calls),
                    static_cast<unsigned long long>(batch_submissions),
                    static_cast<unsigned long long>(batch_dots),
                    static_cast<unsigned long long>(lmhead_batches),
                    static_cast<unsigned long long>(lmhead_positions),
                    static_cast<unsigned long long>(vk_submits),
                    static_cast<unsigned long long>(vk_waits), batch_ms);

        // Continue with the next known serial token, then compare the resulting
        // full logits and the newly written K/V row at the next causal position.
        if (k < count) {
            if (!batch.ExecuteToken(tokens[k], k)) {
                std::printf("D1_CONTINUATION_FAIL length=%zu next_pos=%zu error=%s\n",
                            k, k, batch.LastError().c_str());
                ++failures;
            } else {
                const Diff continuation = Compare(batch.Logits(), serial_logits[k]);
                size_t continuation_kv_floats = 0;
                double continuation_kv_max_abs = 0.0;
                const bool continuation_kv_same = CompareKvPosition(
                    serial, batch, k, continuation_kv_floats, continuation_kv_max_abs);
                const bool continuation_ok = continuation.same &&
                    continuation.elements == report.spec.vocab && continuation_kv_same &&
                    batch.Position() == k && batch.LastToken() == tokens[k] &&
                    batch.CommittedKvTokens() == k + 1 && batch.Stats().cpu_calls == 0;
                if (!continuation_ok) ++failures;
                std::printf("D1_CONTINUATION length=%zu logits=%s max_abs=%.9g all_block_kv=%s kv_floats=%zu kv_max_abs=%.9g state=%s cpu_calls=%llu\n",
                            k, continuation.same ? "BIT_EXACT" : "MISMATCH", continuation.max_abs,
                            continuation_kv_same ? "BIT_EXACT" : "MISMATCH",
                            continuation_kv_floats, continuation_kv_max_abs,
                            continuation_ok ? "PASS" : "FAIL",
                            static_cast<unsigned long long>(batch.Stats().cpu_calls));
            }
        }
    }

    const auto& final_backend = BackendCounters();
    std::printf("D1_MATRIX totals_lengths=5 logits_floats=%zu kv_floats=%zu batch_submissions=%zu batch_dots=%zu backend_process_totals_submits=%llu backend_process_totals_waits=%llu serial_cpu_fallback_calls=%llu\n",
                total_logit_floats, total_kv_floats, total_batch_submissions, total_batch_dots,
                static_cast<unsigned long long>(final_backend.submits),
                static_cast<unsigned long long>(final_backend.waits),
                static_cast<unsigned long long>(serial.Stats().cpu_calls));
    std::printf("D1_MATRIX_VERDICT=%s failures=%d\n", failures == 0 ? "PASS" : "FAIL", failures);
    return failures == 0 ? 0 : 1;
}
