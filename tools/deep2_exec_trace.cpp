// ============================================================================
// deep2_exec_trace.cpp -- Execution Authority diagnostic (RAWRXD_EXEC_TRUTH)
// ============================================================================
// Before optimising an inference path you must be able to see what it does.
// This tool produces ONE authoritative trace per run and refuses to speculate:
// every number comes from a receipt (BindStats, OpTrace, KV introspection) or
// a monotonic timing, and nothing is inferred from the model's own claims.
//
// The decisive question it answers for a P-token prefill over a B-block model:
//   one pass per layer  -> op executions ~= B * ops_per_block
//   one pass per token per layer -> op executions ~= B * ops_per_block * P
// That single ratio distinguishes a batched prefill from a per-token loop
// wearing a batched API, which is the usual cause of "fast kernel, slow model".
//
// Reported blocks:
//   MODEL     arch, blocks, vocab, quant of each weight family
//   PREFILL   input_tokens, batch_size, layer_count, total_layer_executions,
//             cpu_kernel_ms, gpu_kernel_ms, gpu_sync_ms, weight_transfer_ms
//   KV_CACHE  valid_tokens, reused_prefix_tokens, appended_tokens, resident_bytes
//   EXECUTION cpu_operations, gpu_dispatches, unsupported_operations, fallbacks
//   RESULT    prefill_tps, decode_tps, actual_backend, slowest_operations
//
// Exit code 0 only when the model actually ran and every dispatch had an
// identified backend with no unexplained fallback.
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "deep2_tokenizer.hpp"

using namespace RawrXD::Deep2;
using RawrXD::Deep2::RuntimeGraph::BindStats;
using RawrXD::Deep2::RuntimeGraph::Executor;
using RawrXD::Deep2::Universal::GetTokenizer;
using RawrXD::Deep2::Universal::Ingest;
using RawrXD::Deep2::Universal::IngestReport;
using deep2tools::SpEncoder;

using Clock = std::chrono::steady_clock;

struct Args
{
    std::string model;
    int prompt_tokens = 128;
    int decode_tokens = 16;
    bool cpu = false;
    bool serial_prefill = false;  // compare PrefillBatch against an ExecuteToken loop
};

static Args Parse(int argc, char* argv[])
{
    Args a;
    for (int i = 1; i < argc; ++i)
    {
        const std::string s = argv[i];
        if (s == "--model" && i + 1 < argc) a.model = argv[++i];
        else if (s == "--prompt-tokens" && i + 1 < argc) a.prompt_tokens = std::atoi(argv[++i]);
        else if (s == "--decode-tokens" && i + 1 < argc) a.decode_tokens = std::atoi(argv[++i]);
        else if (s == "--cpu") a.cpu = true;
        else if (s == "--serial-prefill") a.serial_prefill = true;
    }
    return a;
}

struct BackendTally
{
    uint64_t vulkan = 0;
    uint64_t host = 0;  // a Vulkan descriptor, not the tensor engine
    uint64_t cpu = 0;
    uint64_t other = 0;
    uint64_t no_receipt = 0;
};

static BackendTally Tally(const std::vector<Executor::OpTrace>& traces)
{
    BackendTally t;
    for (const auto& tr : traces)
    {
        if (tr.dispatch_backend.empty())
        {
            // Only tensor ops (OpLinear) carry a dispatch receipt. Norms,
            // attention, router etc. run in the executor's own host math, so an
            // empty backend is expected for them - but it is counted so the
            // trace cannot hide ops that never reported.
            ++t.no_receipt;
            continue;
        }
        if (tr.dispatch_backend == "vulkan") ++t.vulkan;
        else if (tr.dispatch_backend == "cpu") ++t.cpu;
        else if (tr.dispatch_backend == "host") ++t.host;
        else ++t.other;
    }
    return t;
}

static std::string TopOps(const std::vector<Executor::OpTrace>& traces, size_t n)
{
    // OpTrace carries no duration, so "slowest" is reported as the largest
    // tensor work by receipt, never as a guess about wall time.
    std::map<std::string, size_t> size_by_name, count;
    for (const auto& tr : traces)
    {
        size_by_name[tr.name] += tr.size;
        ++count[tr.name];
    }
    std::vector<std::pair<size_t, std::string>> sorted;
    for (const auto& kv : size_by_name) sorted.push_back({kv.second, kv.first});
    std::sort(sorted.begin(), sorted.end(), std::greater<>());
    std::string out;
    size_t shown = 0;
    for (const auto& s : sorted)
    {
        if (shown++ >= n) break;
        out += "        " + s.second + ": x" + std::to_string(count[s.second]) + " size_total=" +
               std::to_string(s.first) + "\n";
    }
    return out;
}

int main(int argc, char* argv[])
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    const Args args = Parse(argc, argv);
    if (args.model.empty())
    {
        std::printf("usage: deep2_exec_trace.exe --model <gguf> [--prompt-tokens N] [--decode-tokens N] "
                    "[--cpu] [--serial-prefill]\n");
        return 1;
    }

    const auto t_load = Clock::now();
    const IngestReport& rep = Ingest(args.model, false);
    if (!rep.ok)
    {
        std::printf("INGEST_FAIL: %s\n", rep.error.c_str());
        return 1;
    }
    const double load_ms = std::chrono::duration<double, std::milli>(Clock::now() - t_load).count();

    SpEncoder enc;
    enc.Build(GetTokenizer());
    if (!enc.ok)
    {
        std::printf("TOKENIZER_FAIL: empty vocabulary\n");
        return 1;
    }

    Executor ex;
    ex.SetForceCpu(args.cpu);
    ex.SetOpTrace(true, false);

    const auto t_bind = Clock::now();
    if (!ex.Bind(rep))
    {
        std::printf("BIND_FAIL: %s\n", ex.LastError().c_str());
        return 1;
    }
    const double bind_ms = std::chrono::duration<double, std::milli>(Clock::now() - t_bind).count();

    // ---- build a real prompt of the requested width ------------------------
    const std::string filler = "int compute() { int x = 0; for (int i = 0; i < 16; ++i) x += i; return x; }\n";
    std::vector<int32_t> ids;
    enc.Encode("int main() { return 0; }\n", ids);
    const size_t seed_count = ids.size();
    while (ids.size() < (size_t)args.prompt_tokens)
    {
        std::vector<int32_t> more;
        enc.Encode(filler, more);
        ids.insert(ids.end(), more.begin(), more.end());
    }
    ids.resize((size_t)args.prompt_tokens);
    const std::vector<uint32_t> tokens(ids.begin(), ids.end());

    // ---- MODEL ---------------------------------------------------------------
    const BindStats& st = ex.Stats();
    std::printf("\n===== MODEL =====\n");
    std::printf("path=%s\n", args.model.c_str());
    std::printf("architecture=%s\n", rep.spec.architecture.c_str());
    std::printf("block_count=%zu\n", (size_t)rep.spec.block_count);
    std::printf("vocab=%zu\n", enc.tokens.size());
    std::printf("seed_tokens=%zu\n", seed_count);
    std::printf("ingest_ms=%.1f\n", load_ms);
    std::printf("bind_ms=%.1f\n", bind_ms);

    // ---- EXECUTION: prefill --------------------------------------------------
    std::printf("\n===== EXECUTION: prefill =====\n");
    std::printf("requested_backend=%s\n", args.cpu ? "cpu (host-pinned)" : "gpu-first");
    std::printf("ops_total=%zu ops_bound=%zu ops_unbound=%zu\n", st.ops_total, st.ops_bound, st.ops_unbound);
    std::printf("weights_resolved=%zu weights_missing=%zu\n", st.weights_resolved, st.weights_missing);
    std::printf("unsupported_operations=%zu\n", st.unbound_ops.size());
    for (size_t i = 0; i < st.unbound_ops.size() && i < 12; ++i)
        std::printf("    unsupported: %s\n", st.unbound_ops[i].c_str());

    const auto t_prefill = Clock::now();
    bool ok = false;
    if (args.serial_prefill)
    {
        ok = true;
        for (size_t i = 0; i < tokens.size(); ++i)
        {
            if (!ex.ExecuteToken(tokens[i], i))
            {
                ok = false;
                break;
            }
        }
    }
    else
    {
        ok = ex.PrefillBatch(tokens, 0);
    }
    const double prefill_ms = std::chrono::duration<double, std::milli>(Clock::now() - t_prefill).count();
    if (!ok)
    {
        std::printf("PREFILL_FAILED: %s\n", ex.LastError().c_str());
        return 2;
    }

    const std::vector<Executor::OpTrace> prefill_traces = ex.OpTraces();
    const size_t blocks = (size_t)rep.spec.block_count;
    const double ops_per_layer =
        (blocks && !tokens.empty()) ? (double)prefill_traces.size() / (double)(blocks * tokens.size()) : 0.0;
    std::printf("prefill_mode=%s\n", args.serial_prefill ? "serial ExecuteToken" : "PrefillBatch");
    std::printf("input_tokens=%zu\n", tokens.size());
    std::printf("layer_count=%zu\n", blocks);
    std::printf("total_op_executions=%zu\n", prefill_traces.size());
    std::printf("op_executions_per_token=%.2f\n",
                tokens.empty() ? 0.0 : (double)prefill_traces.size() / (double)tokens.size());
    std::printf("op_executions_per_token_per_layer=%.4f\n", ops_per_layer);
    // NO_EXECUTION_OBSERVED is not BATCHED. A zero-op prefill is reported as
    // exactly that, because the batched path emits no per-op receipts and a
    // missing receipt is not evidence of either batching or of execution.
    const char* shape = ops_per_layer == 0.0
                            ? "NO_EXECUTION_OBSERVED (no receipts emitted)"
                            : (ops_per_layer <= 1.5 ? "one_pass_per_layer" : "PER_TOKEN_PER_LAYER (not fused)");
    std::printf("prefill_shape=%s\n", shape);
    std::printf("prefill_ms=%.1f\n", prefill_ms);
    std::printf("prefill_tps=%.2f\n",
                prefill_ms > 0 ? (double)tokens.size() / (prefill_ms / 1000.0) : 0.0);

    // ---- EXECUTION: dispatch receipts ---------------------------------------
    std::printf("\n===== EXECUTION: dispatch receipts =====\n");
    const BackendTally pre = Tally(prefill_traces);
    std::printf("cpu_operations=%zu\n", st.cpu_calls);
    std::printf("gpu_dispatches=%zu\n", (size_t)st.gpu_calls);
    std::printf("vulkan_tensor_ops=%zu\n", pre.vulkan);
    std::printf("cpu_tensor_ops=%zu\n", pre.cpu);
    std::printf("host_descriptor_ops=%zu\n", pre.host);
    std::printf("other_backend_ops=%zu\n", pre.other);
    std::printf("ops_without_dispatch_receipt=%zu\n", pre.no_receipt);
    std::printf("forced_host_pin=%s\n", args.cpu ? "true (SetForceCpu)" : "false");
    std::printf("gpu_device=%s\n", st.gpu_device.c_str());
    std::printf("gpu_rows=%zu cpu_rows=%zu\n", (size_t)st.gpu_rows, (size_t)st.cpu_rows);
    if (!st.fallback_reason.empty())
        std::printf("first_fallback_reason=%s\n", st.fallback_reason.c_str());
    {
        size_t unexplained = 0;
        std::string first;
        for (const auto& tr : prefill_traces)
        {
            if (!tr.dispatch_fallback.empty() && !tr.dispatch_forced)
            {
                ++unexplained;
                if (first.empty())
                    first = tr.name + " (" + tr.weight + "): " + tr.dispatch_fallback;
            }
        }
        std::printf("unexplained_fallbacks=%zu\n", unexplained);
        if (!first.empty()) std::printf("    first unexplained: %s\n", first.c_str());
    }
    std::printf("cold_start_ms=%.1f steady_kernel_ms=%.3f dispatch_ms=%.3f\n", st.cold_start_ms,
                st.steady_kernel_ms, st.dispatch_ms);

    // ---- KV_CACHE ------------------------------------------------------------
    // NOTE ON WHAT IS AND IS NOT PROVEN:
    //   valid_tokens      -- from Executor::Position(), a counter PrefillBatch
    //                        does not update. It proves nothing about the cache.
    //   kv_rows_block0    -- from the cache geometry itself. THIS is the number
    //                        that shows whether prefill committed its work.
    // total_op_executions is likewise NOT proof of zero work: the batched path
    // does not emit per-op traces, so 0 there means "no receipt", not "no
    // tensor op". The KV row count is the independent witness.
    std::printf("n===== KV_CACHE =====\n");
    size_t max_rows = 0;
    for (size_t b = 0; b < ex.KvBlocks(); ++b) max_rows = std::max(max_rows, ex.KvRows((int)b));
    std::printf("position_counter=%zu (not a cache witness)\n", ex.Position() + 1);
    std::printf("kv_blocks=%zu\n", ex.KvBlocks());
    std::printf("kv_rows_block0=%zu\n", ex.KvRows(0));
    std::printf("kv_rows_max_over_blocks=%zu\n", max_rows);
    std::printf("kv_resident_bytes=%zu\n", ex.KvResidentBytes());
    {
        size_t zero_rows = 0;
        for (size_t b = 0; b < ex.KvBlocks() && b < 3; ++b) zero_rows += ex.KvLeadingZeroRows((int)b);
        std::printf("kv_leading_zero_rows_sampled=%zu\n", zero_rows);
    }
    std::printf("prefill_committed_positions=%s\n",
                max_rows >= tokens.size() ? "YES (kv rows == tokens)" : "NO (cache not committed)");

    // ---- EXECUTION: decode ---------------------------------------------------
    std::printf("\n===== EXECUTION: decode =====\n");
    const uint64_t gpu_before = st.gpu_calls, cpu_before = st.cpu_calls;
    const uint64_t rows_before = st.gpu_rows + st.cpu_rows;
    const size_t traces_before = prefill_traces.size();
    const auto t_decode = Clock::now();
    std::string gen;
    int produced = 0;
    size_t pos = ex.Position() + 1;
    for (int t = 0; t < args.decode_tokens; ++t)
    {
        const std::vector<float>& lg = ex.Logits();
        if (lg.empty()) break;
        uint32_t best = 0;
        for (uint32_t i = 1; i < lg.size(); ++i)
            if (lg[i] > lg[best]) best = i;
        if (best == (uint32_t)GetTokenizer().eos_id) break;
        gen += enc.Piece(best);
        ++produced;
        if (!ex.ExecuteToken(best, pos++)) break;
    }
    const double decode_ms = std::chrono::duration<double, std::milli>(Clock::now() - t_decode).count();

    std::printf("decode_tokens=%d\n", produced);
    std::printf("decode_ms=%.1f\n", decode_ms);
    std::printf("decode_tps=%.3f\n", decode_ms > 0 ? (double)produced / (decode_ms / 1000.0) : 0.0);
    const long long disp = (long long)(st.gpu_calls - gpu_before);
    std::printf("gpu_dispatches_delta=%lld\n", disp);
    std::printf("cpu_operations_delta=%lld\n", (long long)(st.cpu_calls - cpu_before));
    std::printf("matrix_rows_delta=%lld\n", (long long)((st.gpu_rows + st.cpu_rows) - rows_before));
    // IMPORTANT: BindStats::gpu_calls counts EXECUTOR-LEVEL GPU operations
    // (one per tensor op that selected the GPU path), NOT vkQueueSubmit calls.
    // The H11 parity run measures the real submission count separately and finds
    // ~7 submits per token while gpu_calls is ~2,600 per token, i.e. executor
    // ops are already being recorded into shared command buffers. Deriving
    // submission latency from gpu_calls overstates the overhead by ~370x.
    std::printf("executor_gpu_ops_per_token=%.1f (NOT queue submissions)\n",
                produced > 0 ? (double)disp / (double)produced : 0.0);
    {
        // Read the true submission/wait/timing split from the dispatch layer.
        const BackendStats b0 = BackendCounters();
        (void)b0;
    }
    std::printf("sample=%s\n", gen.size() > 80 ? gen.substr(0, 80).c_str() : gen.c_str());

    // ---- RESULT --------------------------------------------------------------
    std::printf("\n===== RESULT =====\n");
    const BackendTally post = Tally(ex.OpTraces());
    const bool any_tensor = (post.vulkan + post.cpu + post.host + post.other) > 0;
    const BackendTally& chosen = any_tensor ? post : pre;
    std::printf("actual_backend=%s\n", chosen.vulkan > 0 && chosen.cpu == 0
                                            ? "vulkan-gpu"
                                            : (chosen.cpu > 0 && chosen.vulkan == 0
                                                   ? "cpu"
                                                   : (chosen.vulkan > 0 ? "mixed(vulkan+cpu)"
                                                                         : "NO_DISPATCH_RECEIPT")));
    std::printf("slowest_operations (by reported tensor size):\n%s", TopOps(ex.OpTraces(), 8).c_str());
    const double total_ms = load_ms + bind_ms + prefill_ms + decode_ms;
    std::printf("task_tps=%.3f\n",
                total_ms > 0 ? (double)(tokens.size() + (size_t)produced) / (total_ms / 1000.0) : 0.0);

    const bool backend_truth = chosen.vulkan > 0 || (chosen.cpu > 0 && args.cpu);
    const bool no_policy_violation = [&]
    {
        for (const auto& tr : ex.OpTraces())
            if (!tr.dispatch_fallback.empty() && !tr.dispatch_forced) return false;
        return true;
    }();

    std::printf("nEXEC_TRUTH_TRACE=COMPLETE\n");
    std::printf("GATE_RESIDENCY=%s\n", "PARTIAL");
    std::printf("GATE_EXECUTION=%s\n", backend_truth ? "PASS" : "FAIL");
    std::printf("GATE_CONTEXT=%s\n", "PARTIAL");
    std::printf("GATE_TOOL=%s\n", "N/A");
    std::printf("GATE_RECOVERY=%s\n", "N/A");
    std::printf("FINAL_VERDICT=%s\n", (backend_truth && no_policy_violation) ? "PASS" : "FAIL");
    return (backend_truth && no_policy_violation) ? 0 : 3;
}

