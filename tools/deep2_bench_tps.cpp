// ============================================================================
// deep2_bench_tps.cpp -- RAWRXD_GATE7_TPS_001
// ============================================================================
// Trace-free production benchmark for Deep2's native GPU forward.
//
// Unlike deep2_parity_trace (which exists to DUMP every operator's output
// for parity forensics), this tool performs NO per-operator tensor dumps,
// NO trace files and NO extra host synchronization: it executes exactly the
// production path - Universal::Ingest -> Executor::Bind -> ExecuteToken with
// a persistent KV cache, greedy decode - and measures wall-clock TPS with
// prefill and decode separated.
//
// GPU completion: every quantised dot completes inside ExecuteToken (the
// Vulkan kernel path fence-waits before DotBlocked returns, so the logits
// readback is host-valid when the call returns). The run is additionally
// required to end with zero in-flight descriptor sets
// (QuantDot::BackendCounters().descriptor_sets_in_flight == 0); a non-zero
// value means GPU work outlived the measured window and the run FAILS
// instead of reporting an inflated TPS.
//
// Usage: deep2_bench_tps.exe --model <gguf> --tokens "1 185 ..." [--decode N]
//                            [--runs N] [--cpu] [--serial-prefill] [--no-batch]
//                            [--wide-batch]
// Default GPU path: PrefillBatch + DEEP2_WIDE_DOT_BATCH (fewer host fences).
// --serial-prefill / --no-batch restore the prior differential baselines.
// ============================================================================
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <windows.h>
#include <psapi.h>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "quant_dot_dispatch.hpp"

using namespace RawrXD::Deep2;

namespace {

void SetEnv1(const char* key, const char* val) {
#ifdef _WIN32
    _putenv_s(key, val);
#else
    setenv(key, val, 1);
#endif
}

double MsSince(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(
               std::chrono::steady_clock::now() - t0).count();
}

void RamCounters(SIZE_T& peak_ws, SIZE_T& cur_ws) {
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    pmc.cb = sizeof(pmc);
    if (GetProcessMemoryInfo(GetCurrentProcess(),
                             reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc),
                             sizeof(pmc))) {
        peak_ws = pmc.PeakWorkingSetSize;
        cur_ws = pmc.WorkingSetSize;
    } else {
        peak_ws = cur_ws = 0;
    }
}

uint32_t ArgmaxOf(const std::vector<float>& lg) {
    if (lg.empty()) return 0;
    size_t a = 0;
    for (size_t i = 1; i < lg.size(); ++i)
        if (lg[i] > lg[a]) a = i;
    return (uint32_t)a;
}

// Optional full-vocab logits capture. The production path stays trace-free;
// this flag exists ONLY so the D2 batched-vs-serial parity check can compare
// every logit value, not just the argmax. Writes d2_logits_pos<N>.bin.
void DumpLogits(const std::string& dir, size_t pos, const std::vector<float>& lg) {
    if (dir.empty()) return;
    char path[1024];
    std::snprintf(path, sizeof(path), "%s/d2_logits_pos%zu.bin", dir.c_str(), pos);
    if (std::FILE* f = std::fopen(path, "wb")) {
        std::fwrite(lg.data(), sizeof(float), lg.size(), f);
        std::fclose(f);
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::string model, tokensArg = "1 185 278 20606 23808 7936 14336 28416";
    std::string dumpLogitsDir;   // optional: full-vocab logits per position
    size_t decode_n = 128;
    size_t runs = 1;
    bool gpu = true;
    bool serial_prefill = false;
    bool wide_batch = true;
    int device_index = -1;   // -1 = score-based auto-select; >=0 pins the Vulkan device
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc) model = argv[++i];
        else if (a == "--tokens" && i + 1 < argc) tokensArg = argv[++i];
        else if (a == "--decode" && i + 1 < argc) decode_n = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--runs" && i + 1 < argc) runs = (size_t)std::strtoull(argv[++i], nullptr, 10);
        else if (a == "--cpu") gpu = false;
        else if (a == "--device" && i + 1 < argc) device_index = (int)std::strtol(argv[++i], nullptr, 10);
        else if (a == "--dump-logits" && i + 1 < argc) dumpLogitsDir = argv[++i];
        else if (a == "--serial-prefill") serial_prefill = true;
        else if (a == "--no-wide-batch") wide_batch = false;
        else if (a == "--wide-batch") wide_batch = true;
        else if (a == "--no-batch") {
            SetEnv1("DEEP2_NO_DOT_BATCH", "1");
            wide_batch = false;
        }
        else { std::printf("unknown arg %s\n", a.c_str()); return 1; }
    }
    if (model.empty()) {
        std::printf("usage: deep2_bench_tps.exe --model <gguf> --tokens \"1 185\" "
                    "[--decode N] [--runs N] [--cpu] [--device N] "
                    "[--serial-prefill] [--wide-batch|--no-wide-batch] [--no-batch]\n");
        return 1;
    }
    if (!dumpLogitsDir.empty()) serial_prefill = true;
    if (gpu && wide_batch && !std::getenv("DEEP2_NO_DOT_BATCH")) {
        SetEnv1("DEEP2_WIDE_DOT_BATCH", "1");
    }

    // STRATA_S05 device pin (multi-GPU): apply BEFORE the first QuantDot::Gpu()
    // static init so a process can be pinned to a specific physical Vulkan device.
    if (device_index >= 0) {
        RawrXD::Deep2::QuantDot::SetPreferredDevice(device_index);
        std::printf("device-pin requested index=%d\n", device_index);
    }

    std::printf("BENCH model=%s decode=%zu runs=%zu backend=%s prefill=%s wide_dot_batch=%s\n",
                model.c_str(), decode_n, runs, gpu ? "vulkan-native" : "cpu-pinned",
                (gpu && !serial_prefill) ? "PrefillBatch" : "serial ExecuteToken",
                (gpu && wide_batch && !std::getenv("DEEP2_NO_DOT_BATCH")) ? "1" : "0");

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
    if (tokens.empty()) { std::printf("NO_TOKENS\n"); return 1; }
    std::printf("prompt tokens: %zu:", tokens.size());
    for (uint32_t t : tokens) std::printf(" %u", t);
    std::printf("\n");

    for (size_t run = 1; run <= runs; ++run) {
        // ---- ingest + bind (reported, excluded from the TPS windows) -------
        const auto t_bind0 = std::chrono::steady_clock::now();
        std::printf("ingesting %s ...\n", model.c_str());
        const Universal::IngestReport& rep = Universal::Ingest(model, false);        if (!rep.ok) { std::printf("INGEST_FAIL: %s\n", rep.error.c_str()); return 1; }
        std::printf("arch=%s blocks=%llu embd=%llu heads=%llu kv=%llu rope_dim=%llu "
                    "experts=%llu used=%llu\n", rep.spec.architecture.c_str(),
                    (unsigned long long)rep.spec.block_count,
                    (unsigned long long)rep.spec.embd, (unsigned long long)rep.spec.heads,
                    (unsigned long long)rep.spec.heads_kv,
                    (unsigned long long)rep.spec.rope_dim,
                    (unsigned long long)rep.spec.expert_count,
                    (unsigned long long)rep.spec.expert_used);
        RuntimeGraph::Executor ex;
        ex.SetForceCpu(!gpu);
        if (!ex.Bind(rep)) {
            std::printf("BIND_FAIL: %s\n", ex.Stats().error.c_str());
            return 1;
        }
        const double bind_ms = MsSince(t_bind0);
        std::printf("bound ops=%zu (bind %.1f ms)\n", ex.Stats().ops_total, bind_ms);

        // ---- prefill -------------------------------------------------------
        // Backend counters are process-wide cumulative; snapshot at the run
        // start so the per-run submits/waits and GPU ms are deltas.
        const QuantDot::BackendStats bs0 = QuantDot::BackendCounters();
        if (!dumpLogitsDir.empty()) std::filesystem::create_directories(dumpLogitsDir);
        const auto t_pf0 = std::chrono::steady_clock::now();
        if (gpu && !serial_prefill) {
            std::vector<std::vector<float>> perPos;
            std::vector<std::vector<float>>* perPosPtr =
                dumpLogitsDir.empty() ? nullptr : &perPos;
            if (!ex.PrefillBatch(tokens, 0, perPosPtr)) {
                std::printf("PREFILL_BATCH_FAIL err=%s; falling back to serial\n",
                            ex.LastError().c_str());
                for (size_t i = 0; i < tokens.size(); ++i) {
                    if (!ex.ExecuteToken(tokens[i], i)) {
                        std::printf("PREFILL_FAIL pos=%zu err=%s\n", i, ex.LastError().c_str());
                        return 1;
                    }
                    DumpLogits(dumpLogitsDir, i, ex.Logits());
                }
            } else if (perPosPtr) {
                for (size_t i = 0; i < perPos.size(); ++i)
                    DumpLogits(dumpLogitsDir, i, perPos[i]);
            }
            std::printf("  prefill PrefillBatch n=%zu\n", tokens.size());
        } else {
            for (size_t i = 0; i < tokens.size(); ++i) {
                const auto tt = std::chrono::steady_clock::now();
                if (!ex.ExecuteToken(tokens[i], i)) {
                    std::printf("PREFILL_FAIL pos=%zu err=%s\n", i, ex.LastError().c_str());
                    return 1;
                }
                DumpLogits(dumpLogitsDir, i, ex.Logits());
                std::printf("  prefill pos=%zu token=%u (%.1f ms)\n", i, tokens[i], MsSince(tt));
            }
        }
        const double prefill_ms = MsSince(t_pf0);
        // Snapshot after prefill so the decode phase's GPU/kernel/sync counters
        // can be reported as their OWN boundary. The backend counters are
        // process-cumulative, so every reported figure is a delta over exactly
        // the wall interval it is divided by - no overlapping timers.
        const QuantDot::BackendStats bs1 = QuantDot::BackendCounters();

        // ---- decode (greedy, persistent KV) ---------------------------------
        std::vector<uint32_t> gen;
        std::vector<double> gen_ms;
        uint32_t tok = ArgmaxOf(ex.Logits());
        gen.push_back(tok);  // the argmax of the last prefill logits is gen[0]
        const auto t_dc0 = std::chrono::steady_clock::now();
        for (size_t i = 1; i < decode_n; ++i) {
            const size_t pos = tokens.size() + i - 1;
            const auto tt = std::chrono::steady_clock::now();
            if (!ex.ExecuteToken(gen.back(), pos)) {
                std::printf("DECODE_FAIL pos=%zu err=%s\n", pos, ex.LastError().c_str());
                return 1;
            }
            gen_ms.push_back(MsSince(tt));
            gen.push_back(ArgmaxOf(ex.Logits()));
            DumpLogits(dumpLogitsDir, tokens.size() + i - 1, ex.Logits());
        }
        const double decode_ms = MsSince(t_dc0);
        const double first_decode_ms = gen_ms.empty() ? 0.0 : gen_ms.front();
        const double steady_ms =
            gen_ms.empty() ? 0.0 : decode_ms - first_decode_ms;

        // ---- finiteness over every logits vector produced this pass --------
        bool finite = (ex.NonFiniteLogits() == 0);

        const double e2e_ms = prefill_ms + decode_ms;
        const double prefill_tps = tokens.size() * 1000.0 / prefill_ms;
        const double decode_tps = (double)(gen.size() - 1) * 1000.0 / decode_ms;
        const double steady_tps =
            gen_ms.size() > 1 ? (double)(gen_ms.size() - 1) * 1000.0 / steady_ms : 0.0;

        // ---- GPU completion evidence ---------------------------------------
        const QuantDot::BackendStats& bs = QuantDot::BackendCounters();
        // Per-dot fence waits already complete the work inside ExecuteToken;
        // this run is only valid if nothing is still in flight.
        const bool gpu_complete = (bs.descriptor_sets_in_flight == 0);
        // Per-run deltas: the counters are cumulative for the process.
        const uint64_t run_submits = bs.submits - bs0.submits;
        const uint64_t run_waits = bs.waits - bs0.waits;
        const double run_gpu_ms = bs.gpu_ms - bs0.gpu_ms;
        const double run_submit_ms = bs.submit_ms - bs0.submit_ms;
        const double run_wait_ms = bs.wait_ms - bs0.wait_ms;
        const double run_kernel_ms = bs.kernel_ms - bs0.kernel_ms;
        const double gen_steps = (double)(gen.size() - 1);
        const double exec_positions = (double)tokens.size() + gen_steps;
        // Per-phase deltas over exactly the interval each is divided by.
        const double pf_gpu_ms = bs1.gpu_ms - bs0.gpu_ms;
        const double dc_gpu_ms = bs.gpu_ms - bs1.gpu_ms;
        const double pf_wait_ms = bs1.wait_ms - bs0.wait_ms;
        const double dc_wait_ms = bs.wait_ms - bs1.wait_ms;
        const double pf_submit_ms = bs1.submit_ms - bs0.submit_ms;
        const double dc_submit_ms = bs.submit_ms - bs1.submit_ms;
        const uint64_t pf_submits = bs1.submits - bs0.submits;
        const uint64_t dc_submits = bs.submits - bs1.submits;

        SIZE_T peak_ws = 0, cur_ws = 0;
        RamCounters(peak_ws, cur_ws);

        const RuntimeGraph::BindStats& st = ex.Stats();
        std::printf("RUN%zu: logits_finite=%s gpu_complete=%s\n", run,
                    finite ? "yes" : "NO", gpu_complete ? "yes" : "NO");
        std::printf("RUN%zu: bind_ms=%.1f prefill_ms=%.1f decode_ms=%.1f e2e_ms=%.1f\n",
                    run, bind_ms, prefill_ms, decode_ms, e2e_ms);
        std::printf("RUN%zu: PREFILL_TPS=%.3f DECODE_TPS=%.3f STEADY_DECODE_TPS=%.3f "
                    "E2E_TPS=%.3f\n", run, prefill_tps, decode_tps, steady_tps,
                    tokens.size() * 1000.0 / e2e_ms);
        std::printf("RUN%zu: first_decode_ms=%.1f tokens_in=%zu tokens_out=%zu\n",
                    run, first_decode_ms, tokens.size(), gen.size());
        std::printf("RUN%zu: gpu_calls=%llu cpu_calls=%llu fallback=%s submits=%llu waits=%llu "
                    "kernel_ms=%.1f wait_ms=%.1f\n", run,
                    (unsigned long long)st.gpu_calls, (unsigned long long)st.cpu_calls,
                    st.fallback_reason.empty() ? "<none>" : st.fallback_reason.c_str(),
                    (unsigned long long)run_submits, (unsigned long long)run_waits,
                    run_kernel_ms, run_wait_ms);
        std::printf("RUN%zu: per_token submits=%.1f waits=%.1f gpu_ms=%.1f submit_ms=%.1f "
                    "wait_ms=%.1f\n", run,
                    run_submits / exec_positions, run_waits / exec_positions,
                    run_gpu_ms, run_submit_ms, run_wait_ms);
        // Accounting note: the blended per_token rate above divides (prefill+decode)
        // submits by (prefill+decode) positions, so it is NOT a decode-only rate.
        // tokens_out counts the free argmax of the last prefill position as gen[0];
        // the authoritative per-phase rates are the boundary submits/position below.
        {
            const size_t decode_fwd = gen.size() ? gen.size() - 1 : 0;  // decode forward passes
            std::printf("RUN%zu: ACCOUNT positions=%.0f decode_forward_passes=%zu "
                        "prefill_submits_per_pos=%.1f decode_submits_per_fwd=%.1f\n",
                        run, exec_positions, decode_fwd,
                        tokens.size() ? (double)pf_submits / (double)tokens.size() : 0.0,
                        decode_fwd ? (double)dc_submits / (double)decode_fwd : 0.0);
        }
        std::printf("RUN%zu: gpu_time_share=%.1f%% of the measured window "
                    "(gpu %.1f ms of prefill+decode %.1f ms)\n",
                    run, e2e_ms > 0 ? 100.0 * run_gpu_ms / e2e_ms : 0.0,
                    run_gpu_ms, e2e_ms);
        // ---- timing boundaries, one line per phase, no overlapping timers ----
        std::printf("RUN%zu: BOUNDARY bind_ms=%.1f (model load+bind, excluded from TPS)\n",
                    run, bind_ms);
        std::printf("RUN%zu: BOUNDARY prefill wall=%.1f ms gpu=%.1f ms host_wait=%.1f ms "
                    "submit=%.1f ms submits=%llu\n", run, prefill_ms, pf_gpu_ms, pf_wait_ms,
                    pf_submit_ms, (unsigned long long)pf_submits);
        std::printf("RUN%zu: BOUNDARY decode wall=%.1f ms gpu=%.1f ms host_wait=%.1f ms "
                    "submit=%.1f ms submits=%llu\n", run, decode_ms, dc_gpu_ms, dc_wait_ms,
                    dc_submit_ms, (unsigned long long)dc_submits);
        std::printf("RUN%zu: BOUNDARY decode gpu_share=%.1f%% wall; unaccounted(host+queue)="
                    "%.1f ms; kernel_ms is a HOST-WAIT alias, gpu_ms is device timeline\n",
                    run, decode_ms > 0 ? 100.0 * dc_gpu_ms / decode_ms : 0.0,
                    decode_ms - dc_wait_ms);
        std::printf("RUN%zu: device_bytes_peak=%.1f MB device_bytes_live=%.1f MB "
                    "weight_cache_hits=%llu misses=%llu upload=%.1f MB\n", run,
                    bs.device_bytes_peak / 1048576.0, bs.device_bytes_live / 1048576.0,
                    (unsigned long long)bs.weight_cache_hits,
                    (unsigned long long)bs.weight_cache_misses,
                    bs.upload_bytes / 1048576.0);
        std::printf("RUN%zu: ram_peak=%.1f MB ram_cur=%.1f MB\n", run,
                    peak_ws / 1048576.0, cur_ws / 1048576.0);
        std::printf("RUN%zu GENSTREAM:", run);
        for (uint32_t t : gen) std::printf(" %u", t);
        std::printf("\n");
        if (!finite || (gpu && st.cpu_calls != 0) || !gpu_complete) {
            std::printf("RUN%zu VERDICT: FAIL (finite=%d cpu_calls_on_gpu=%llu "
                        "gpu_complete=%d)\n", run, (int)finite,
                        (unsigned long long)st.cpu_calls, (int)gpu_complete);
            return 2;
        }
        std::printf("RUN%zu VERDICT: PASS\n", run);
    }
    return 0;
}
