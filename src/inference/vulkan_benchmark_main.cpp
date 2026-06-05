// ============================================================================
// vulkan_benchmark_main.cpp — Sovereign Vulkan Kernel Benchmark Harness
// ============================================================================
//
// Benchmarks the production RMSNorm implementation:
//   1. Baseline (shared memory, UBO static pipeline)
//   2. Burst-submit amortization
//   3. Layer-chain static command buffer smoke test
//
// Reports: wall-clock time per dispatch, throughput (GB/s), correctness.
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <vector>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <process.h>
#endif

#include <vulkan/vulkan.h>

#include "RawrXD_VulkanAccelerator.h"

using namespace std::chrono;

// ---------------------------------------------------------------------------
// CPU reference RMSNorm for correctness verification
// ---------------------------------------------------------------------------
static void cpu_rmsnorm(const float* in, const float* w, float* out,
                        uint32_t hidden_size, float eps) {
    float sum_sq = 0.0f;
    for (uint32_t i = 0; i < hidden_size; ++i) {
        sum_sq += in[i] * in[i];
    }
    float rms = std::sqrt(sum_sq / hidden_size + eps);
    float inv_rms = 1.0f / rms;
    for (uint32_t i = 0; i < hidden_size; ++i) {
        out[i] = in[i] * inv_rms * w[i];
    }
}

// ---------------------------------------------------------------------------
// Benchmark one kernel: warm-up + measured runs
// ---------------------------------------------------------------------------
struct BenchResult {
    const char* name;
    double      avg_us;       // Average dispatch time (microseconds)
    double      gpu_avg_us;   // Average pure GPU kernel time (microseconds)
    double      trimmed_avg_us; // 5% trimmed mean (outlier-resistant)
    double      min_us;       // Minimum dispatch time
    double      max_us;       // Maximum dispatch time
    double      p50_us;       // Median latency
    double      p95_us;       // 95th percentile latency
    double      p99_us;       // 99th percentile latency
    double      stddev_us;    // Standard deviation
    double      jitter_ratio; // max/min ratio (higher => more unstable)
    double      throughput_gb_s;
    double      submit_to_signal_us; // CPU submit->completion span (telemetry)
    double      host_residual_us;    // submit_to_signal - gpu_avg_us (telemetry)
    double      upload_wait_us;      // Upload dependency wait per run (telemetry)
    double      upload_wait_p95_us;  // Upload wait p95 per run
    double      upload_wait_p99_us;  // Upload wait p99 per run
    double      upload_wait_max_us;  // Upload wait max per run
    double      upload_wait_count;   // Upload dependency wait count per run
    double      upload_ring_full_count; // Upload ring full events per run
    float       max_error;
    bool        correct;
};

struct BenchConfig {
    uint32_t hidden_size;
    uint32_t num_rows;
    const char* label;
};

static double percentile_us(std::vector<double> v, double pct) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    double pos = (pct / 100.0) * static_cast<double>(v.size() - 1);
    size_t lo = static_cast<size_t>(std::floor(pos));
    size_t hi = static_cast<size_t>(std::ceil(pos));
    if (lo == hi) return v[lo];
    double t = pos - static_cast<double>(lo);
    return v[lo] * (1.0 - t) + v[hi] * t;
}

static double trimmed_mean_us(std::vector<double> v, double trim_fraction) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t n = v.size();
    size_t trim = static_cast<size_t>(std::floor(static_cast<double>(n) * trim_fraction));
    if (trim * 2 >= n) trim = 0;
    double sum = 0.0;
    size_t count = 0;
    for (size_t i = trim; i < n - trim; ++i) {
        sum += v[i];
        ++count;
    }
    return count ? (sum / static_cast<double>(count)) : 0.0;
}

    static void print_occupancy_report(const rawrxd::ComputeLimits& limits,
                        uint32_t groups_x,
                        uint32_t groups_y,
                        uint32_t groups_z,
                        uint32_t local_size_x,
                        uint32_t local_size_y,
                        uint32_t local_size_z) {
        const uint64_t total_groups = static_cast<uint64_t>(groups_x) * groups_y * groups_z;
        const uint64_t threads_per_group = static_cast<uint64_t>(local_size_x) * local_size_y * local_size_z;
        const uint64_t total_threads = total_groups * threads_per_group;
        const double total_wavefronts = static_cast<double>(total_threads) / 32.0;
        const double wavefronts_per_60cu_proxy = total_wavefronts / 60.0;
        const double x_limit = limits.max_compute_work_group_count[0] ? static_cast<double>(limits.max_compute_work_group_count[0]) : 0.0;
        const double invoc_limit = limits.max_compute_work_group_invocations ? static_cast<double>(limits.max_compute_work_group_invocations) : 0.0;
        const double x_util_pct = x_limit > 0.0 ? (static_cast<double>(groups_x) * 100.0 / x_limit) : 0.0;
        const double group_util_pct = invoc_limit > 0.0 ? (static_cast<double>(threads_per_group) * 100.0 / invoc_limit) : 0.0;

        printf("  [Occupancy] groups=(%u,%u,%u) total_groups=%llu local_size=(%u,%u,%u) threads/group=%llu total_threads=%llu wavefronts=%.2f\n",
            groups_x, groups_y, groups_z,
            static_cast<unsigned long long>(total_groups),
            local_size_x, local_size_y, local_size_z,
            static_cast<unsigned long long>(threads_per_group),
            static_cast<unsigned long long>(total_threads),
            total_wavefronts);
        printf("  [Occupancy] max_groups=(%u,%u,%u) max_invocations=%u waves_per_60cu_proxy=%.4f x_util=%.4f%% invocations_util=%.4f%%\n",
            limits.max_compute_work_group_count[0],
            limits.max_compute_work_group_count[1],
            limits.max_compute_work_group_count[2],
            limits.max_compute_work_group_invocations,
            wavefronts_per_60cu_proxy,
            x_util_pct,
            group_util_pct);
    }

static BenchResult benchmark_kernel(rawrxd::VulkanAccelerator& accel,
                                     uint32_t kernel_id,
                                     const char* name,
                                     const std::vector<float>& host_in,
                                     const std::vector<float>& host_w,
                                     std::vector<float>& host_out,
                                     uint32_t hidden_size,
                                     float eps,
                                     uint32_t num_rows,
                                     uint32_t dispatches_per_submit,
                                     rawrxd::GpuTensorHandle h_in,
                                     rawrxd::GpuTensorHandle h_w,
                                     rawrxd::GpuTensorHandle h_out) {
    constexpr uint32_t warm_up = 10;
    constexpr uint32_t runs    = 100;

    rawrxd::RMSNormDesc rms{};
    rms.input       = h_in;
    rms.output      = h_out;
    rms.weight      = h_w;
    rms.hidden_size = hidden_size;
    rms.eps         = eps;
    rms.num_rows    = num_rows;

    // Warm-up
    for (uint32_t i = 0; i < warm_up; ++i) {
        if (dispatches_per_submit <= 1) {
            accel.DispatchRMSNorm(rms, kernel_id);
        } else {
            accel.DispatchRMSNormBurst(rms, kernel_id, dispatches_per_submit);
        }
    }
    accel.Wait(10'000'000'000ULL);

    // Measured runs
    double min_us = 1e9, max_us = 0.0, total_us = 0.0;
    std::vector<double> samples_us;
    std::vector<double> samples_gpu_us;
    std::vector<double> samples_submit_to_signal_us;
    std::vector<double> samples_host_residual_us;
    std::vector<double> samples_upload_wait_us;
    std::vector<double> samples_upload_wait_count;
    std::vector<double> samples_upload_ring_full_count;
    samples_us.reserve(runs);
    samples_gpu_us.reserve(runs);
    samples_submit_to_signal_us.reserve(runs);
    samples_host_residual_us.reserve(runs);
    samples_upload_wait_us.reserve(runs);
    samples_upload_wait_count.reserve(runs);
    samples_upload_ring_full_count.reserve(runs);
    for (uint32_t i = 0; i < runs; ++i) {
        rawrxd::VulkanAccelerator::Stats stats_before = accel.GetStats();
        auto t0 = high_resolution_clock::now();
        if (dispatches_per_submit <= 1) {
            accel.DispatchRMSNorm(rms, kernel_id);
        } else {
            accel.DispatchRMSNormBurst(rms, kernel_id, dispatches_per_submit);
        }
        accel.Wait(10'000'000'000ULL);
        auto t1 = high_resolution_clock::now();
        rawrxd::VulkanAccelerator::Stats stats_after = accel.GetStats();
        double us = duration_cast<microseconds>(t1 - t0).count() / static_cast<double>(dispatches_per_submit);
        samples_us.push_back(us);
        if (stats_after.last_dispatch_ns != 0 && stats_after.gpu_busy_ns >= stats_before.gpu_busy_ns) {
            samples_gpu_us.push_back((static_cast<double>(stats_after.last_dispatch_ns) / 1000.0) /
                                     static_cast<double>(dispatches_per_submit));
        }
        if (stats_after.last_submit_to_signal_ns != 0) {
            samples_submit_to_signal_us.push_back((static_cast<double>(stats_after.last_submit_to_signal_ns) / 1000.0) /
                                                  static_cast<double>(dispatches_per_submit));
        }
        if (stats_after.last_host_residual_ns != 0) {
            samples_host_residual_us.push_back((static_cast<double>(stats_after.last_host_residual_ns) / 1000.0) /
                                               static_cast<double>(dispatches_per_submit));
        }
        if (stats_after.upload_wait_ns >= stats_before.upload_wait_ns) {
            samples_upload_wait_us.push_back((static_cast<double>(stats_after.upload_wait_ns - stats_before.upload_wait_ns) / 1000.0) /
                                             static_cast<double>(dispatches_per_submit));
        }
        if (stats_after.upload_wait_count >= stats_before.upload_wait_count) {
            samples_upload_wait_count.push_back(static_cast<double>(stats_after.upload_wait_count - stats_before.upload_wait_count) /
                                                static_cast<double>(dispatches_per_submit));
        }
        if (stats_after.upload_ring_full_count >= stats_before.upload_ring_full_count) {
            samples_upload_ring_full_count.push_back(static_cast<double>(stats_after.upload_ring_full_count - stats_before.upload_ring_full_count) /
                                                     static_cast<double>(dispatches_per_submit));
        }
        total_us += us;
        if (us < min_us) min_us = us;
        if (us > max_us) max_us = us;
    }

    // Readback and verify
    std::fill(host_out.begin(), host_out.end(), 0.0f);
    accel.ReadbackTensor(h_out, host_out.data());

    std::vector<float> cpu_ref(hidden_size * num_rows);
    for (uint32_t r = 0; r < num_rows; ++r) {
        cpu_rmsnorm(host_in.data() + r * hidden_size,
                    host_w.data(),
                    cpu_ref.data() + r * hidden_size,
                    hidden_size, eps);
    }

    float max_err = 0.0f;
    bool correct = true;
    for (size_t i = 0; i < host_out.size(); ++i) {
        float err = std::abs(host_out[i] - cpu_ref[i]);
        if (err > max_err) max_err = err;
        if (err > 1e-3f) correct = false;
    }

    double avg_us = total_us / runs;
    double gpu_avg_us = 0.0;
    if (!samples_gpu_us.empty()) {
        gpu_avg_us = std::accumulate(samples_gpu_us.begin(), samples_gpu_us.end(), 0.0) /
                     static_cast<double>(samples_gpu_us.size());
    }
    double submit_to_signal_us = 0.0;
    if (!samples_submit_to_signal_us.empty()) {
        submit_to_signal_us = std::accumulate(samples_submit_to_signal_us.begin(), samples_submit_to_signal_us.end(), 0.0) /
                              static_cast<double>(samples_submit_to_signal_us.size());
    }
    double host_residual_us = 0.0;
    if (!samples_host_residual_us.empty()) {
        host_residual_us = std::accumulate(samples_host_residual_us.begin(), samples_host_residual_us.end(), 0.0) /
                           static_cast<double>(samples_host_residual_us.size());
    }
    double upload_wait_us = 0.0;
    if (!samples_upload_wait_us.empty()) {
        upload_wait_us = std::accumulate(samples_upload_wait_us.begin(), samples_upload_wait_us.end(), 0.0) /
                         static_cast<double>(samples_upload_wait_us.size());
    }
    double upload_wait_p95_us = percentile_us(samples_upload_wait_us, 95.0);
    double upload_wait_p99_us = percentile_us(samples_upload_wait_us, 99.0);
    double upload_wait_max_us = samples_upload_wait_us.empty()
        ? 0.0
        : *std::max_element(samples_upload_wait_us.begin(), samples_upload_wait_us.end());
    double upload_wait_count = 0.0;
    if (!samples_upload_wait_count.empty()) {
        upload_wait_count = std::accumulate(samples_upload_wait_count.begin(), samples_upload_wait_count.end(), 0.0) /
                            static_cast<double>(samples_upload_wait_count.size());
    }
    double upload_ring_full_count = 0.0;
    if (!samples_upload_ring_full_count.empty()) {
        upload_ring_full_count = std::accumulate(samples_upload_ring_full_count.begin(), samples_upload_ring_full_count.end(), 0.0) /
                                 static_cast<double>(samples_upload_ring_full_count.size());
    }
    double variance = 0.0;
    for (double s : samples_us) {
        double d = s - avg_us;
        variance += d * d;
    }
    variance /= static_cast<double>(samples_us.size());
    double stddev_us = std::sqrt(variance);
    double p50_us = percentile_us(samples_us, 50.0);
    double p95_us = percentile_us(samples_us, 95.0);
    double p99_us = percentile_us(samples_us, 99.0);
    double trimmed_avg_us = trimmed_mean_us(samples_us, 0.05); // trim 5% tails
    double jitter_ratio = (min_us > 0.0) ? (max_us / min_us) : 0.0;

    size_t bytes_moved = (host_in.size() + host_w.size() + host_out.size()) * sizeof(float);
    double throughput_gb_s = (bytes_moved / (1024.0 * 1024.0 * 1024.0)) / (avg_us / 1e6);

    return BenchResult{
        name, avg_us, gpu_avg_us, trimmed_avg_us, min_us, max_us,
        p50_us, p95_us, p99_us, stddev_us, jitter_ratio,
        throughput_gb_s, submit_to_signal_us, host_residual_us,
        upload_wait_us, upload_wait_p95_us, upload_wait_p99_us, upload_wait_max_us,
        upload_wait_count, upload_ring_full_count,
        max_err, correct
    };
}

static BenchResult benchmark_layer_chain(rawrxd::VulkanAccelerator& accel,
                                         uint32_t kernel_id,
                                         const char* name,
                                         const std::vector<float>& host_in,
                                         const std::vector<float>& host_w,
                                         std::vector<float>& host_mid,
                                         std::vector<float>& host_out,
                                         uint32_t hidden_size,
                                         float eps,
                                         uint32_t num_rows,
                                         uint32_t chain_steps,
                                         rawrxd::GpuTensorHandle h_in,
                                         rawrxd::GpuTensorHandle h_w,
                                         rawrxd::GpuTensorHandle h_mid,
                                         rawrxd::GpuTensorHandle h_out) {
    constexpr uint32_t warm_up = 10;
    constexpr uint32_t runs    = 100;

    struct ChainStepParams {
        uint32_t hidden_size;
        float eps;
        uint32_t layer_idx;
        uint32_t seq_pos;
    };

    rawrxd::StaticLayerDesc chain{};
    std::vector<ChainStepParams> chain_params;
    chain_params.reserve(chain_steps);
    chain.steps.resize(chain_steps);
    if (chain_steps > 1) {
        chain.barriers.resize(chain_steps - 1);
    }

    rawrxd::GpuTensorHandle current_input = h_in;
    for (uint32_t step_idx = 0; step_idx < chain_steps; ++step_idx) {
        chain_params.push_back(ChainStepParams{hidden_size, eps, step_idx, 0});

        rawrxd::GpuTensorHandle step_output = h_out;
        if (step_idx + 1U < chain_steps) {
            step_output = (step_idx % 2U == 0U) ? h_mid : h_out;
        }

        chain.steps[step_idx].kernel_id = kernel_id;
        chain.steps[step_idx].groups_x = num_rows;
        chain.steps[step_idx].groups_y = 1;
        chain.steps[step_idx].groups_z = 1;
        chain.steps[step_idx].ubo_offset = 0;
        chain.steps[step_idx].params = &chain_params.back();
        chain.steps[step_idx].params_size = sizeof(ChainStepParams);
        chain.steps[step_idx].bindings.push_back({0, current_input});
        chain.steps[step_idx].bindings.push_back({1, step_output});
        chain.steps[step_idx].bindings.push_back({2, h_w});

        if (step_idx + 1U < chain_steps) {
            rawrxd::StaticLayerBarrier& barrier = chain.barriers[step_idx];
            barrier.buffer = step_output.buffer;
            barrier.offset = 0;
            barrier.size = step_output.size_bytes;
            barrier.src_stage_mask = VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT;
            barrier.dst_stage_mask = VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT;
            barrier.src_access_mask = VK_ACCESS_SHADER_WRITE_BIT;
            barrier.dst_access_mask = VK_ACCESS_SHADER_READ_BIT;
        }

        current_input = step_output;
    }

    for (uint32_t i = 0; i < warm_up; ++i) {
        accel.DispatchStaticLayerChain(chain);
    }
    accel.Wait(10'000'000'000ULL);

    double min_us = 1e9, max_us = 0.0, total_us = 0.0;
    std::vector<double> samples_us;
    std::vector<double> samples_gpu_us;
    std::vector<double> samples_submit_to_signal_us;
    std::vector<double> samples_host_residual_us;
    std::vector<double> samples_upload_wait_us;
    std::vector<double> samples_upload_wait_count;
    std::vector<double> samples_upload_ring_full_count;
    samples_us.reserve(runs);
    samples_gpu_us.reserve(runs);
    samples_submit_to_signal_us.reserve(runs);
    samples_host_residual_us.reserve(runs);
    samples_upload_wait_us.reserve(runs);
    samples_upload_wait_count.reserve(runs);
    samples_upload_ring_full_count.reserve(runs);
    for (uint32_t i = 0; i < runs; ++i) {
        rawrxd::VulkanAccelerator::Stats stats_before = accel.GetStats();
        auto t0 = high_resolution_clock::now();
        accel.DispatchStaticLayerChain(chain);
        accel.Wait(10'000'000'000ULL);
        auto t1 = high_resolution_clock::now();
        rawrxd::VulkanAccelerator::Stats stats_after = accel.GetStats();
        double us = static_cast<double>(duration_cast<microseconds>(t1 - t0).count());
        samples_us.push_back(us);
        if (stats_after.last_dispatch_ns != 0 && stats_after.gpu_busy_ns >= stats_before.gpu_busy_ns) {
            samples_gpu_us.push_back(static_cast<double>(stats_after.last_dispatch_ns) / 1000.0);
        }
        if (stats_after.last_submit_to_signal_ns != 0) {
            samples_submit_to_signal_us.push_back(static_cast<double>(stats_after.last_submit_to_signal_ns) / 1000.0);
        }
        if (stats_after.last_host_residual_ns != 0) {
            samples_host_residual_us.push_back(static_cast<double>(stats_after.last_host_residual_ns) / 1000.0);
        }
        if (stats_after.upload_wait_ns >= stats_before.upload_wait_ns) {
            samples_upload_wait_us.push_back(static_cast<double>(stats_after.upload_wait_ns - stats_before.upload_wait_ns) / 1000.0);
        }
        if (stats_after.upload_wait_count >= stats_before.upload_wait_count) {
            samples_upload_wait_count.push_back(static_cast<double>(stats_after.upload_wait_count - stats_before.upload_wait_count));
        }
        if (stats_after.upload_ring_full_count >= stats_before.upload_ring_full_count) {
            samples_upload_ring_full_count.push_back(static_cast<double>(stats_after.upload_ring_full_count - stats_before.upload_ring_full_count));
        }
        total_us += us;
        if (us < min_us) min_us = us;
        if (us > max_us) max_us = us;
    }

    std::fill(host_out.begin(), host_out.end(), 0.0f);
    accel.ReadbackTensor(h_out, host_out.data());

    std::vector<float> cpu_ping = host_in;
    std::vector<float> cpu_pong(hidden_size * num_rows);
    for (uint32_t step_idx = 0; step_idx < chain_steps; ++step_idx) {
        for (uint32_t r = 0; r < num_rows; ++r) {
            cpu_rmsnorm(cpu_ping.data() + r * hidden_size,
                        host_w.data(),
                        cpu_pong.data() + r * hidden_size,
                        hidden_size, eps);
        }
        cpu_ping.swap(cpu_pong);
    }

    float max_err = 0.0f;
    bool correct = true;
    for (size_t i = 0; i < host_out.size(); ++i) {
        float err = std::abs(host_out[i] - cpu_ping[i]);
        if (err > max_err) max_err = err;
        if (err > 1e-3f) correct = false;
    }

    double avg_us = total_us / runs;
    double gpu_avg_us = 0.0;
    if (!samples_gpu_us.empty()) {
        gpu_avg_us = std::accumulate(samples_gpu_us.begin(), samples_gpu_us.end(), 0.0) /
                     static_cast<double>(samples_gpu_us.size());
    }
    double submit_to_signal_us = 0.0;
    if (!samples_submit_to_signal_us.empty()) {
        submit_to_signal_us = std::accumulate(samples_submit_to_signal_us.begin(), samples_submit_to_signal_us.end(), 0.0) /
                              static_cast<double>(samples_submit_to_signal_us.size());
    }
    double host_residual_us = 0.0;
    if (!samples_host_residual_us.empty()) {
        host_residual_us = std::accumulate(samples_host_residual_us.begin(), samples_host_residual_us.end(), 0.0) /
                           static_cast<double>(samples_host_residual_us.size());
    }
    double upload_wait_us = 0.0;
    if (!samples_upload_wait_us.empty()) {
        upload_wait_us = std::accumulate(samples_upload_wait_us.begin(), samples_upload_wait_us.end(), 0.0) /
                         static_cast<double>(samples_upload_wait_us.size());
    }
    double upload_wait_p95_us = percentile_us(samples_upload_wait_us, 95.0);
    double upload_wait_p99_us = percentile_us(samples_upload_wait_us, 99.0);
    double upload_wait_max_us = samples_upload_wait_us.empty()
        ? 0.0
        : *std::max_element(samples_upload_wait_us.begin(), samples_upload_wait_us.end());
    double upload_wait_count = 0.0;
    if (!samples_upload_wait_count.empty()) {
        upload_wait_count = std::accumulate(samples_upload_wait_count.begin(), samples_upload_wait_count.end(), 0.0) /
                            static_cast<double>(samples_upload_wait_count.size());
    }
    double upload_ring_full_count = 0.0;
    if (!samples_upload_ring_full_count.empty()) {
        upload_ring_full_count = std::accumulate(samples_upload_ring_full_count.begin(), samples_upload_ring_full_count.end(), 0.0) /
                                 static_cast<double>(samples_upload_ring_full_count.size());
    }
    double variance = 0.0;
    for (double s : samples_us) {
        double d = s - avg_us;
        variance += d * d;
    }
    variance /= static_cast<double>(samples_us.size());
    double stddev_us = std::sqrt(variance);
    double p50_us = percentile_us(samples_us, 50.0);
    double p95_us = percentile_us(samples_us, 95.0);
    double p99_us = percentile_us(samples_us, 99.0);
    double trimmed_avg_us = trimmed_mean_us(samples_us, 0.05);
    double jitter_ratio = (min_us > 0.0) ? (max_us / min_us) : 0.0;

    size_t bytes_moved_per_step = (host_in.size() + host_w.size() + host_out.size()) * sizeof(float);
    size_t bytes_moved = bytes_moved_per_step * static_cast<size_t>(chain_steps);
    double throughput_gb_s = (bytes_moved / (1024.0 * 1024.0 * 1024.0)) / (avg_us / 1e6);

    return BenchResult{
        name, avg_us, gpu_avg_us, trimmed_avg_us, min_us, max_us,
        p50_us, p95_us, p99_us, stddev_us, jitter_ratio,
        throughput_gb_s, submit_to_signal_us, host_residual_us,
        upload_wait_us, upload_wait_p95_us, upload_wait_p99_us, upload_wait_max_us,
        upload_wait_count, upload_ring_full_count,
        max_err, correct
    };
}

static BenchResult benchmark_fused_prefill(rawrxd::VulkanAccelerator& accel,
                                           uint32_t kernel_id,
                                           const char* name,
                                           const std::vector<float>& host_in,
                                           const std::vector<float>& host_gamma,
                                           const std::vector<float>& host_matmul_w,
                                           std::vector<float>& host_out,
                                           uint32_t hidden_size,
                                           uint32_t output_size,
                                           float eps,
                                           uint32_t num_rows,
                                           uint32_t tile_m,
                                           uint32_t tile_n,
                                           bool stream_input_upload,
                                           bool force_burst,
                                           rawrxd::GpuTensorHandle h_in,
                                           rawrxd::GpuTensorHandle h_gamma,
                                           rawrxd::GpuTensorHandle h_matmul_w,
                                           rawrxd::GpuTensorHandle h_out) {
    constexpr uint32_t warm_up = 10;
    constexpr uint32_t runs = 100;

    rawrxd::FusedRMSNormMatMulDesc desc{};
    desc.input = h_in;
    desc.output = h_out;
    desc.rmsnorm_weight = h_gamma;
    desc.matmul_weight = h_matmul_w;
    desc.hidden_size = hidden_size;
    desc.output_size = output_size;
    desc.eps = eps;
    desc.num_rows = num_rows;
    desc.tile_m = tile_m;
    desc.tile_n = tile_n;

    rawrxd::TensorDesc stream_input_desc{};
    if (stream_input_upload) {
        stream_input_desc.name = "prefill_stream_in";
        stream_input_desc.format = rawrxd::TensorFormat::F32;
        stream_input_desc.rows = num_rows;
        stream_input_desc.cols = hidden_size;
        stream_input_desc.host_ptr = host_in.data();
        stream_input_desc.size_bytes = host_in.size() * sizeof(float);
    }

    for (uint32_t i = 0; i < warm_up; ++i) {
        accel.DispatchFusedRMSNormMatMul(desc, kernel_id);
    }
    accel.Wait(10'000'000'000ULL);

    double min_us = 1e9, max_us = 0.0, total_us = 0.0;
    std::vector<double> samples_us;
    std::vector<double> samples_gpu_us;
    std::vector<double> samples_submit_to_signal_us;
    std::vector<double> samples_host_residual_us;
    std::vector<double> samples_upload_wait_us;
    std::vector<double> samples_upload_wait_count;
    std::vector<double> samples_upload_ring_full_count;
    samples_us.reserve(runs);
    samples_gpu_us.reserve(runs);
    samples_submit_to_signal_us.reserve(runs);
    samples_host_residual_us.reserve(runs);
    samples_upload_wait_us.reserve(runs);
    samples_upload_wait_count.reserve(runs);
    samples_upload_ring_full_count.reserve(runs);
    uint32_t burst_drop_count = 0;

    for (uint32_t i = 0; i < runs; ++i) {
        rawrxd::VulkanAccelerator::Stats stats_before = accel.GetStats();
        rawrxd::GpuTensorHandle stream_input{};
        if (stream_input_upload) {
            stream_input = accel.UploadTensor(stream_input_desc, false);
            if (!stream_input.IsValid()) {
                if (force_burst) {
                    ++burst_drop_count;
                    desc.input = h_in;
                } else {
                    return BenchResult{ name, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0f, false };
                }
            } else {
                desc.input = stream_input;
            }
        }
        auto t0 = high_resolution_clock::now();
        accel.DispatchFusedRMSNormMatMul(desc, kernel_id);
        accel.Wait(10'000'000'000ULL);
        auto t1 = high_resolution_clock::now();
        rawrxd::VulkanAccelerator::Stats stats_after = accel.GetStats();
        if (stream_input_upload && stream_input.IsValid()) {
            accel.ReleaseTensor(stream_input);
            desc.input = h_in;
        }

        double us = duration_cast<microseconds>(t1 - t0).count();
        samples_us.push_back(us);
        if (stats_after.last_dispatch_ns != 0 && stats_after.gpu_busy_ns >= stats_before.gpu_busy_ns) {
            samples_gpu_us.push_back(static_cast<double>(stats_after.last_dispatch_ns) / 1000.0);
        }
        if (stats_after.last_submit_to_signal_ns != 0) {
            samples_submit_to_signal_us.push_back(static_cast<double>(stats_after.last_submit_to_signal_ns) / 1000.0);
        }
        if (stats_after.last_host_residual_ns != 0) {
            samples_host_residual_us.push_back(static_cast<double>(stats_after.last_host_residual_ns) / 1000.0);
        }
        if (stats_after.upload_wait_ns >= stats_before.upload_wait_ns) {
            samples_upload_wait_us.push_back(static_cast<double>(stats_after.upload_wait_ns - stats_before.upload_wait_ns) / 1000.0);
        }
        if (stats_after.upload_wait_count >= stats_before.upload_wait_count) {
            samples_upload_wait_count.push_back(static_cast<double>(stats_after.upload_wait_count - stats_before.upload_wait_count));
        }
        if (stats_after.upload_ring_full_count >= stats_before.upload_ring_full_count) {
            samples_upload_ring_full_count.push_back(static_cast<double>(stats_after.upload_ring_full_count - stats_before.upload_ring_full_count));
        }
        total_us += us;
        if (us < min_us) min_us = us;
        if (us > max_us) max_us = us;
    }

    std::fill(host_out.begin(), host_out.end(), 0.0f);
    accel.ReadbackTensor(h_out, host_out.data());

    // Fused path validation: compare GPU output against CPU fused reference.
    const bool full_verify = (static_cast<uint64_t>(num_rows) * output_size * hidden_size) <= 64ULL * 1024ULL * 1024ULL;
    const uint32_t verify_rows = full_verify ? num_rows : std::min<uint32_t>(num_rows, 4);
    const uint32_t verify_out_step = full_verify ? 1U : std::max<uint32_t>(1U, output_size / 64U);
    float max_err = 0.0f;
    bool correct = true;

    std::vector<float> cpu_ref;
    if (full_verify) {
        cpu_ref.assign(output_size * num_rows, 0.0f);
    }

    for (uint32_t r = 0; r < verify_rows; ++r) {
        const float* in_row = host_in.data() + static_cast<size_t>(r) * hidden_size;
        float sum_sq = 0.0f;
        for (uint32_t i = 0; i < hidden_size; ++i) {
            sum_sq += in_row[i] * in_row[i];
        }
        const float inv_rms = 1.0f / std::sqrt(sum_sq / static_cast<float>(hidden_size) + eps);

        for (uint32_t o = 0; o < output_size; o += verify_out_step) {
            float dot = 0.0f;
            for (uint32_t i = 0; i < hidden_size; ++i) {
                const float norm = in_row[i] * inv_rms * host_gamma[i];
                dot += norm * host_matmul_w[static_cast<size_t>(i) * output_size + o];
            }
            if (full_verify) {
                cpu_ref[static_cast<size_t>(r) * output_size + o] = dot;
            } else {
                const float v = host_out[static_cast<size_t>(r) * output_size + o];
                if (!std::isfinite(v) || !std::isfinite(dot)) {
                    correct = false;
                    continue;
                }
                const float err = std::abs(v - dot);
                if (err > max_err) max_err = err;
                if (err > 1e-2f) {
                    correct = false;
                }
            }
        }
    }

    if (full_verify) {
        bool ok = true;
        for (size_t i = 0; i < host_out.size(); ++i) {
            const float v = host_out[i];
            const float ref = cpu_ref[i];
            if (!std::isfinite(v) || !std::isfinite(ref)) {
                ok = false;
                break;
            }
            const float err = std::abs(v - ref);
            if (err > max_err) max_err = err;
            if (err > 1e-2f) {
                ok = false;
            }
        }
        correct = ok;
    }

    double avg_us = total_us / runs;
    double gpu_avg_us = 0.0;
    if (!samples_gpu_us.empty()) {
        gpu_avg_us = std::accumulate(samples_gpu_us.begin(), samples_gpu_us.end(), 0.0) /
                     static_cast<double>(samples_gpu_us.size());
    }
    double submit_to_signal_us = 0.0;
    if (!samples_submit_to_signal_us.empty()) {
        submit_to_signal_us = std::accumulate(samples_submit_to_signal_us.begin(), samples_submit_to_signal_us.end(), 0.0) /
                              static_cast<double>(samples_submit_to_signal_us.size());
    }
    double host_residual_us = 0.0;
    if (!samples_host_residual_us.empty()) {
        host_residual_us = std::accumulate(samples_host_residual_us.begin(), samples_host_residual_us.end(), 0.0) /
                           static_cast<double>(samples_host_residual_us.size());
    }
    double upload_wait_us = 0.0;
    if (!samples_upload_wait_us.empty()) {
        upload_wait_us = std::accumulate(samples_upload_wait_us.begin(), samples_upload_wait_us.end(), 0.0) /
                         static_cast<double>(samples_upload_wait_us.size());
    }
    double upload_wait_p95_us = percentile_us(samples_upload_wait_us, 95.0);
    double upload_wait_p99_us = percentile_us(samples_upload_wait_us, 99.0);
    double upload_wait_max_us = samples_upload_wait_us.empty()
        ? 0.0
        : *std::max_element(samples_upload_wait_us.begin(), samples_upload_wait_us.end());
    double upload_wait_count = 0.0;
    if (!samples_upload_wait_count.empty()) {
        upload_wait_count = std::accumulate(samples_upload_wait_count.begin(), samples_upload_wait_count.end(), 0.0) /
                            static_cast<double>(samples_upload_wait_count.size());
    }
    double upload_ring_full_count = 0.0;
    if (!samples_upload_ring_full_count.empty()) {
        upload_ring_full_count = std::accumulate(samples_upload_ring_full_count.begin(), samples_upload_ring_full_count.end(), 0.0) /
                                 static_cast<double>(samples_upload_ring_full_count.size());
    }
    double variance = 0.0;
    for (double s : samples_us) {
        double d = s - avg_us;
        variance += d * d;
    }
    variance /= static_cast<double>(samples_us.size());
    double stddev_us = std::sqrt(variance);
    double p50_us = percentile_us(samples_us, 50.0);
    double p95_us = percentile_us(samples_us, 95.0);
    double p99_us = percentile_us(samples_us, 99.0);
    double trimmed_avg_us = trimmed_mean_us(samples_us, 0.05);
    double jitter_ratio = (min_us > 0.0) ? (max_us / min_us) : 0.0;

    size_t bytes_moved = (host_in.size() + host_gamma.size() + host_matmul_w.size() + host_out.size()) * sizeof(float);
    double throughput_gb_s = (bytes_moved / (1024.0 * 1024.0 * 1024.0)) / (avg_us / 1e6);

    if (force_burst && burst_drop_count > 0) {
        fprintf(stderr, "[DEBUG] force-burst stream upload drops: %u/%u\n", burst_drop_count, runs);
    }

    return BenchResult{
        name, avg_us, gpu_avg_us, trimmed_avg_us, min_us, max_us,
        p50_us, p95_us, p99_us, stddev_us, jitter_ratio,
        throughput_gb_s, submit_to_signal_us, host_residual_us,
        upload_wait_us, upload_wait_p95_us, upload_wait_p99_us, upload_wait_max_us,
        upload_wait_count, upload_ring_full_count,
        max_err, correct
    };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[]) {
    printf("[VulkanBench] Sovereign Kernel Benchmark Harness\n");
    printf("[VulkanBench] Target: AMD Radeon RX 7800 XT (RDNA3, wavefront=32)\n\n");
    std::srand(12345); // deterministic input for reproducible benchmarks

    int sessions = 3;
    int dispatches_per_submit = 1;
    bool layer_chain_mode = false;
    bool prefill_mode = false;
    bool prefill_sweep = false;
    bool sweep_ring_size = false;
    bool prefill_fused = false;
    bool prefill_stream_upload = false;
    bool force_burst = false;
    uint32_t prefill_batch = 1;
    uint32_t prefill_seq = 1024;
    uint32_t prefill_hidden = 4096;
    uint32_t prefill_output_multiplier = 3;
    uint32_t prefill_fused_tile_m = 16;
    uint32_t prefill_fused_tile_n = 16;
    const char* prefill_fused_kernel_path_override = nullptr;
    uint32_t layer_chain_steps = 2;
    for (int i = 1; i < argc; ++i) {
        if ((std::strcmp(argv[i], "--sessions") == 0 || std::strcmp(argv[i], "-s") == 0) && i + 1 < argc) {
            sessions = std::max(1, std::atoi(argv[i + 1]));
            ++i;
        } else if ((std::strcmp(argv[i], "--dispatches-per-submit") == 0 || std::strcmp(argv[i], "-d") == 0) && i + 1 < argc) {
            dispatches_per_submit = std::max(1, std::atoi(argv[i + 1]));
            ++i;
        } else if ((std::strcmp(argv[i], "--layer-steps") == 0) && i + 1 < argc) {
            layer_chain_steps = static_cast<uint32_t>(std::max(1, std::atoi(argv[i + 1])));
            ++i;
        } else if (std::strcmp(argv[i], "--layer-chain") == 0) {
            layer_chain_mode = true;
        } else if (std::strcmp(argv[i], "--prefill") == 0) {
            prefill_mode = true;
        } else if (std::strcmp(argv[i], "--prefill-sweep") == 0) {
            prefill_sweep = true;
        } else if (std::strcmp(argv[i], "--sweep-ring-size") == 0) {
            sweep_ring_size = true;
        } else if ((std::strcmp(argv[i], "--prefill-batch") == 0) && i + 1 < argc) {
            prefill_batch = static_cast<uint32_t>(std::max(1, std::atoi(argv[i + 1])));
            ++i;
        } else if ((std::strcmp(argv[i], "--prefill-seq") == 0) && i + 1 < argc) {
            prefill_seq = static_cast<uint32_t>(std::max(1, std::atoi(argv[i + 1])));
            ++i;
        } else if ((std::strcmp(argv[i], "--prefill-hidden") == 0) && i + 1 < argc) {
            prefill_hidden = static_cast<uint32_t>(std::max(1, std::atoi(argv[i + 1])));
            ++i;
        } else if (std::strcmp(argv[i], "--prefill-fused") == 0) {
            prefill_fused = true;
        } else if (std::strcmp(argv[i], "--prefill-stream-upload") == 0) {
            prefill_stream_upload = true;
        } else if (std::strcmp(argv[i], "--force-burst") == 0) {
            force_burst = true;
        } else if ((std::strcmp(argv[i], "--prefill-output-mult") == 0) && i + 1 < argc) {
            prefill_output_multiplier = static_cast<uint32_t>(std::max(1, std::atoi(argv[i + 1])));
            ++i;
        } else if ((std::strcmp(argv[i], "--prefill-fused-tile-m") == 0) && i + 1 < argc) {
            prefill_fused_tile_m = static_cast<uint32_t>(std::max(1, std::atoi(argv[i + 1])));
            ++i;
        } else if ((std::strcmp(argv[i], "--prefill-fused-tile-n") == 0) && i + 1 < argc) {
            prefill_fused_tile_n = static_cast<uint32_t>(std::max(1, std::atoi(argv[i + 1])));
            ++i;
        } else if ((std::strcmp(argv[i], "--prefill-fused-kernel-path") == 0) && i + 1 < argc) {
            prefill_fused_kernel_path_override = argv[i + 1];
            ++i;
        }
    }
    printf("[VulkanBench] Sessions per config: %d\n\n", sessions);
    printf("[VulkanBench] Dispatches per submit: %d\n\n", dispatches_per_submit);
    if (prefill_mode) {
                                                 printf("[VulkanBench] Prefill mode enabled (batch=%u, seq=%u, hidden=%u, sweep=%s, ring_sweep=%s, fused=%s, stream_upload=%s, force_burst=%s, out_mult=%u, tile_m=%u, tile_n=%u)\n\n",
               prefill_batch,
               prefill_seq,
               prefill_hidden,
             prefill_sweep ? "on" : "off",
                         sweep_ring_size ? "on" : "off",
             prefill_fused ? "on" : "off",
                     prefill_stream_upload ? "on" : "off",
                     force_burst ? "on" : "off",
                         prefill_output_multiplier,
                         prefill_fused_tile_m,
                         prefill_fused_tile_n);
    }

#ifdef _WIN32
    if (force_burst) {
        _putenv_s("RAWRXD_UPLOAD_FORCE_BURST", "1");
        if (prefill_stream_upload) {
            _putenv_s("RAWRXD_UPLOAD_BURST_MARGIN", "2");
        }
    }
#endif
    if (layer_chain_mode) {
        printf("[VulkanBench] Layer-chain mode enabled (steps=%u)\n\n", layer_chain_steps);
    }

    if (sweep_ring_size) {
        const uint32_t ring_caps[] = {2, 4, 8, 16};
        std::vector<const char*> child_argv;
        child_argv.reserve(static_cast<size_t>(argc) + 1);
        child_argv.push_back(argv[0]);
        for (int i = 1; i < argc; ++i) {
            if (std::strcmp(argv[i], "--sweep-ring-size") == 0) {
                continue;
            }
            child_argv.push_back(argv[i]);
        }
        child_argv.push_back(nullptr);

        printf("[VulkanBench] Executing isolated ring sweep across 2/4/8/16 with fresh process state.\n\n");
        for (uint32_t cap : ring_caps) {
#ifdef _WIN32
            char cap_buf[16] = {};
            std::snprintf(cap_buf, sizeof(cap_buf), "%u", cap);
            _putenv_s("RAWRXD_UPLOAD_RING_CAP", cap_buf);
            int rc = _spawnv(_P_WAIT, argv[0], child_argv.data());
#endif
            printf("=== Ring Sweep: cap=%u ===\n", cap);
#ifndef _WIN32
            int rc = std::system("Unsupported sweep launcher on this platform");
#endif
            if (rc != 0) {
                printf("[VulkanBench] FAIL: child run failed for cap=%u (rc=%d)\n", cap, rc);
                return rc;
            }
            printf("\n");
        }

        printf("[VulkanBench] Complete.\n");
        return 0;
    }

    rawrxd::VulkanAccelerator& accel = rawrxd::GetVulkanAccelerator();
    if (!accel.Initialize()) {
        printf("[VulkanBench] FAIL: Initialize() returned false\n");
        return 1;
    }
    if (!accel.IsReady()) {
        printf("[VulkanBench] FAIL: accelerator not ready\n");
        return 1;
    }
    const rawrxd::ComputeLimits compute_limits = accel.GetComputeLimits();

    // Test configurations
    BenchConfig configs[] = {
        {256,  1, "Small (256x1)"},
        {4096, 1, "LLM Hidden (4096x1)"},
        {4096, 8, "Batch-8 (4096x8)"},
        {4096, 32, "Batch-32 (4096x32)"},
        {4096, 64, "Batch-64 (4096x64)"},
    };

    const char* kernel_name = "rmsnorm";
    const char* kernel_path = "../../src/inference/kernels/rmsnorm.spv";

    if (prefill_mode) {
        const uint32_t hidden_size = prefill_hidden;
        const float eps = 1e-6f;
        const uint32_t sweep_seqs[] = {128, 512, 1024, 2048};
        const uint32_t ring_caps[] = {2, 4, 8, 16};
        const uint32_t output_size = prefill_fused
            ? (hidden_size * prefill_output_multiplier)
            : hidden_size;
        const char* prefill_kernel_name = prefill_fused ? "fused_rmsnorm_matmul" : "rmsnorm";
        const char* prefill_kernel_path = prefill_fused
            ? (prefill_fused_kernel_path_override ? prefill_fused_kernel_path_override : "../../src/inference/kernels/fused_rmsnorm_matmul.spv")
            : "../../src/inference/kernels/rmsnorm.spv";
        const uint32_t prefill_binding_count = prefill_fused ? 4 : 3;

        // Prefill lane performs per-ring clean re-init so each sweep point has isolated resources.
        accel.Shutdown();

        const size_t ring_iters = sweep_ring_size ? (sizeof(ring_caps) / sizeof(ring_caps[0])) : 1;
        for (size_t ring_idx = 0; ring_idx < ring_iters; ++ring_idx) {
            const uint32_t ring_cap = sweep_ring_size ? ring_caps[ring_idx] : 0;
#ifdef _WIN32
            if (sweep_ring_size) {
                char cap_buf[16] = {};
                std::snprintf(cap_buf, sizeof(cap_buf), "%u", ring_cap);
                _putenv_s("RAWRXD_UPLOAD_RING_CAP", cap_buf);
            }
#endif

            if (!accel.Initialize()) {
                printf("[VulkanBench] FAIL: Initialize() returned false (ring_cap=%u)\n", ring_cap);
                return 1;
            }
            if (!accel.IsReady()) {
                printf("[VulkanBench] FAIL: accelerator not ready (ring_cap=%u)\n", ring_cap);
                return 1;
            }
            const rawrxd::ComputeLimits ring_compute_limits = accel.GetComputeLimits();
            if (sweep_ring_size) {
                printf("=== Ring Sweep: cap=%u ===\n\n", ring_cap);
            }

        for (size_t seq_idx = 0; seq_idx < (prefill_sweep ? (sizeof(sweep_seqs) / sizeof(sweep_seqs[0])) : 1); ++seq_idx) {
            const uint32_t seq_len = prefill_sweep ? sweep_seqs[seq_idx] : prefill_seq;
            const uint64_t total_rows_u64 = static_cast<uint64_t>(prefill_batch) * static_cast<uint64_t>(seq_len);
            if (total_rows_u64 == 0 || total_rows_u64 > static_cast<uint64_t>(0xFFFFFFFFu)) {
                printf("[VulkanBench] FAIL: prefill rows overflow (batch=%u, seq=%u)\n", prefill_batch, seq_len);
                return 1;
            }
            const uint32_t num_rows = static_cast<uint32_t>(total_rows_u64);

            printf("=== Prefill (batch=%u, seq=%u, tokens=%u) ===\n", prefill_batch, seq_len, num_rows);
            printf("hidden_size=%u, output_size=%u, num_rows=%u\n\n", hidden_size, output_size, num_rows);
            const uint32_t dispatch_groups_x = prefill_fused ? ((num_rows + (prefill_fused_tile_m - 1u)) / prefill_fused_tile_m) : num_rows;
            const uint32_t dispatch_groups_y = prefill_fused ? ((output_size + (prefill_fused_tile_n - 1u)) / prefill_fused_tile_n) : 1u;
            const uint32_t local_x = prefill_fused ? prefill_fused_tile_n : 256u;
            const uint32_t local_y = prefill_fused ? prefill_fused_tile_m : 1u;
            print_occupancy_report(ring_compute_limits, dispatch_groups_x, dispatch_groups_y, 1, local_x, local_y, 1);
            printf("\n");

            std::vector<float> host_in(hidden_size * num_rows);
            std::vector<float> host_gamma(hidden_size);
            std::vector<float> host_matmul_w;
            std::vector<float> host_out(output_size * num_rows);

            for (auto& v : host_in) v = static_cast<float>(rand()) / RAND_MAX;
            for (auto& v : host_gamma)  v = 1.0f + static_cast<float>(rand()) / RAND_MAX;
            if (prefill_fused) {
                host_matmul_w.resize(static_cast<size_t>(hidden_size) * output_size);
                for (auto& v : host_matmul_w) v = (static_cast<float>(rand()) / RAND_MAX) * 0.01f;
            }

            rawrxd::TensorDesc desc_in{};
            desc_in.name = "prefill_in";
            desc_in.format = rawrxd::TensorFormat::F32;
            desc_in.rows = num_rows;
            desc_in.cols = hidden_size;
            desc_in.host_ptr = host_in.data();
            desc_in.size_bytes = host_in.size() * sizeof(float);

            rawrxd::TensorDesc desc_w{};
            desc_w.name = "prefill_gamma";
            desc_w.format = rawrxd::TensorFormat::F32;
            desc_w.rows = 1;
            desc_w.cols = hidden_size;
            desc_w.host_ptr = host_gamma.data();
            desc_w.size_bytes = host_gamma.size() * sizeof(float);

            rawrxd::TensorDesc desc_matmul_w{};
            if (prefill_fused) {
                desc_matmul_w.name = "prefill_matmul_w";
                desc_matmul_w.format = rawrxd::TensorFormat::F32;
                desc_matmul_w.rows = hidden_size;
                desc_matmul_w.cols = output_size;
                desc_matmul_w.host_ptr = host_matmul_w.data();
                desc_matmul_w.size_bytes = host_matmul_w.size() * sizeof(float);
            }

            rawrxd::TensorDesc desc_out{};
            desc_out.name = "prefill_out";
            desc_out.format = rawrxd::TensorFormat::F32;
            desc_out.rows = num_rows;
            desc_out.cols = output_size;
            desc_out.host_ptr = nullptr;
            desc_out.size_bytes = host_out.size() * sizeof(float);

            rawrxd::GpuTensorHandle h_in = accel.UploadTensor(desc_in, false);
            rawrxd::GpuTensorHandle h_gamma = accel.UploadTensor(desc_w, false);
            rawrxd::GpuTensorHandle h_matmul_w{};
            if (prefill_fused) {
                h_matmul_w = accel.UploadTensor(desc_matmul_w, false);
            }
            rawrxd::GpuTensorHandle h_out = accel.UploadTensor(desc_out, false);
            if (!h_in.IsValid() || !h_gamma.IsValid() || !h_out.IsValid() || (prefill_fused && !h_matmul_w.IsValid())) {
                printf("[VulkanBench] FAIL: prefill tensor upload\n");
                return 1;
            }

            double sum_tps = 0.0;
            double sum_tflops = 0.0;
            double sum_bpf = 0.0;
            int valid_sessions = 0;
            for (int s = 0; s < sessions; ++s) {
                printf("  -- Session %d/%d --\n", s + 1, sessions);
                uint32_t kid = accel.LoadKernel(prefill_kernel_name, prefill_kernel_path, prefill_binding_count);
                if (kid == 0) {
                    printf("[VulkanBench] WARN: failed to load '%s'\n", prefill_kernel_name);
                    continue;
                }

                BenchResult r = prefill_fused
                    ? benchmark_fused_prefill(accel, kid, prefill_kernel_name,
                                              host_in, host_gamma, host_matmul_w, host_out,
                                              hidden_size, output_size, eps, num_rows,
                                              prefill_fused_tile_m, prefill_fused_tile_n, prefill_stream_upload, force_burst,
                                              h_in, h_gamma, h_matmul_w, h_out)
                    : benchmark_kernel(accel, kid, prefill_kernel_name,
                                       host_in, host_gamma, host_out,
                                       hidden_size, eps, num_rows,
                                       static_cast<uint32_t>(dispatches_per_submit),
                                       h_in, h_gamma, h_out);

                const double tokens_per_second = static_cast<double>(num_rows) / (r.avg_us / 1e6);
                const double us_per_token = r.avg_us / static_cast<double>(num_rows);
                const double flops_per_token = prefill_fused
                    ? ((4.0 * static_cast<double>(hidden_size)) +
                       (2.0 * static_cast<double>(hidden_size) * static_cast<double>(output_size)))
                    : (4.0 * static_cast<double>(hidden_size));
                const double bytes_per_token = prefill_fused
                    ? ((static_cast<double>(hidden_size) +
                        static_cast<double>(hidden_size) +
                        (static_cast<double>(hidden_size) * static_cast<double>(output_size)) +
                        static_cast<double>(output_size)) * sizeof(float))
                    : ((static_cast<double>(hidden_size) +
                        static_cast<double>(hidden_size) +
                        static_cast<double>(output_size)) * sizeof(float));
                const double bytes_per_flop = (flops_per_token > 0.0) ? (bytes_per_token / flops_per_token) : 0.0;
                const double tflops = (flops_per_token * static_cast<double>(num_rows)) / (r.avg_us / 1e6) / 1e12;
                sum_tps += tokens_per_second;
                sum_tflops += tflops;
                sum_bpf += bytes_per_flop;
                ++valid_sessions;

                  printf("  %-20s  prefill_tokens=%u  per=%8.2f µs  tok=%6.4f µs  gpu=%8.2f µs  host2=%8.2f µs  u_wait=%7.2f µs  u_wait_p99=%7.2f µs  u_wait_max=%7.2f µs  u_wait_n=%5.2f  u_full=%5.2f  prefill_tps=%11.2f  throughput=%7.2f GB/s  tflops=%7.2f  B/F=%7.4f  max_err=%.6f  %s\n",
                       r.name,
                       num_rows,
                       r.avg_us,
                       us_per_token,
                       r.gpu_avg_us,
                       r.host_residual_us,
                      r.upload_wait_us,
                      r.upload_wait_p99_us,
                      r.upload_wait_max_us,
                      r.upload_wait_count,
                      r.upload_ring_full_count,
                       tokens_per_second,
                       r.throughput_gb_s,
                       tflops,
                       bytes_per_flop,
                       r.max_error,
                       r.correct ? "PASS" : "FAIL");
            }

            printf("\n  -- Consolidated (%d sessions) --\n", sessions);
            if (valid_sessions > 0) {
                printf("  Prefill TPS (avg): %.2f tokens/s\n", sum_tps / static_cast<double>(valid_sessions));
                printf("  Prefill TFLOPS (avg): %.2f\n", sum_tflops / static_cast<double>(valid_sessions));
                printf("  Arithmetic Intensity (avg B/F): %.4f\n", sum_bpf / static_cast<double>(valid_sessions));
            }
            printf("\n");
        }

            accel.Shutdown();
        }

        printf("[VulkanBench] Complete.\n");
        return 0;
    }

    struct AggregateResult {
        const char* name = nullptr;
        int count = 0;
        double sum_avg_us = 0.0;
        double sum_gpu_avg_us = 0.0;
        double sum_trimmed_avg_us = 0.0;
        double sum_p95_us = 0.0;
        double sum_stddev_us = 0.0;
        double sum_jitter_ratio = 0.0;
        double sum_throughput_gb_s = 0.0;
        double sum_submit_to_signal_us = 0.0;
        double sum_host_residual_us = 0.0;
        double sum_upload_wait_us = 0.0;
        double sum_upload_wait_p99_us = 0.0;
        double max_upload_wait_max_us = 0.0;
        double sum_upload_wait_count = 0.0;
        double sum_upload_ring_full_count = 0.0;
        float max_error = 0.0f;
        bool all_correct = true;
    };

    for (const auto& cfg : configs) {
        printf("=== %s ===\n", cfg.label);
        printf("hidden_size=%u, num_rows=%u\n\n", cfg.hidden_size, cfg.num_rows);
        print_occupancy_report(compute_limits, cfg.num_rows, 1, 1, 256, 1, 1);
        printf("\n");

        std::vector<float> host_in(cfg.hidden_size * cfg.num_rows);
        std::vector<float> host_w(cfg.hidden_size);
        std::vector<float> host_out(cfg.hidden_size * cfg.num_rows);
        std::vector<float> host_mid;

        // Random-ish data
        for (auto& v : host_in) v = static_cast<float>(rand()) / RAND_MAX;
        for (auto& v : host_w)  v = 1.0f + static_cast<float>(rand()) / RAND_MAX;

        rawrxd::TensorDesc desc_in{};
        desc_in.name = "bench_in";
        desc_in.format = rawrxd::TensorFormat::F32;
        desc_in.rows = cfg.num_rows;
        desc_in.cols = cfg.hidden_size;
        desc_in.host_ptr = host_in.data();
        desc_in.size_bytes = host_in.size() * sizeof(float);

        rawrxd::TensorDesc desc_w{};
        desc_w.name = "bench_w";
        desc_w.format = rawrxd::TensorFormat::F32;
        desc_w.rows = 1;
        desc_w.cols = cfg.hidden_size;
        desc_w.host_ptr = host_w.data();
        desc_w.size_bytes = host_w.size() * sizeof(float);

        rawrxd::TensorDesc desc_out{};
        desc_out.name = "bench_out";
        desc_out.format = rawrxd::TensorFormat::F32;
        desc_out.rows = cfg.num_rows;
        desc_out.cols = cfg.hidden_size;
        desc_out.host_ptr = nullptr;
        desc_out.size_bytes = host_out.size() * sizeof(float);

        rawrxd::TensorDesc desc_mid{};
        rawrxd::GpuTensorHandle h_mid{};
        if (layer_chain_mode) {
            host_mid.resize(cfg.hidden_size * cfg.num_rows);
            desc_mid.name = "bench_mid";
            desc_mid.format = rawrxd::TensorFormat::F32;
            desc_mid.rows = cfg.num_rows;
            desc_mid.cols = cfg.hidden_size;
            desc_mid.host_ptr = nullptr;
            desc_mid.size_bytes = host_mid.size() * sizeof(float);
        }

        rawrxd::GpuTensorHandle h_in  = accel.UploadTensor(desc_in, false);
        rawrxd::GpuTensorHandle h_w   = accel.UploadTensor(desc_w, false);
        rawrxd::GpuTensorHandle h_out = accel.UploadTensor(desc_out, false);
        if (layer_chain_mode) {
            h_mid = accel.UploadTensor(desc_mid, false);
        }

        if (!h_in.IsValid() || !h_w.IsValid() || !h_out.IsValid() || (layer_chain_mode && !h_mid.IsValid())) {
            printf("[VulkanBench] FAIL: tensor upload\n");
            return 1;
        }

        AggregateResult agg = {};

        for (int s = 0; s < sessions; ++s) {
            printf("  -- Session %d/%d --\n", s + 1, sessions);
            uint32_t kid = accel.LoadKernel(kernel_name, kernel_path, 3);
            if (kid == 0) {
                printf("[VulkanBench] WARN: failed to load '%s'\n", kernel_name);
                continue;
            }

            BenchResult r = layer_chain_mode
                ? benchmark_layer_chain(accel, kid, kernel_name,
                                        host_in, host_w, host_mid, host_out,
                                        cfg.hidden_size, 1e-6f, cfg.num_rows, layer_chain_steps,
                                        h_in, h_w, h_mid, h_out)
                : benchmark_kernel(accel, kid, kernel_name,
                                   host_in, host_w, host_out,
                                   cfg.hidden_size, 1e-6f, cfg.num_rows,
                                   static_cast<uint32_t>(dispatches_per_submit),
                                   h_in, h_w, h_out);

            agg.name = r.name;
            agg.count += 1;
            agg.sum_avg_us += r.avg_us;
            agg.sum_gpu_avg_us += r.gpu_avg_us;
            agg.sum_trimmed_avg_us += r.trimmed_avg_us;
            agg.sum_p95_us += r.p95_us;
            agg.sum_stddev_us += r.stddev_us;
            agg.sum_jitter_ratio += r.jitter_ratio;
            agg.sum_throughput_gb_s += r.throughput_gb_s;
            agg.sum_submit_to_signal_us += r.submit_to_signal_us;
            agg.sum_host_residual_us += r.host_residual_us;
            agg.sum_upload_wait_us += r.upload_wait_us;
            agg.sum_upload_wait_p99_us += r.upload_wait_p99_us;
            agg.max_upload_wait_max_us = std::max(agg.max_upload_wait_max_us, r.upload_wait_max_us);
            agg.sum_upload_wait_count += r.upload_wait_count;
            agg.sum_upload_ring_full_count += r.upload_ring_full_count;
            agg.max_error = std::max(agg.max_error, r.max_error);
            agg.all_correct = agg.all_correct && r.correct;

            const double host_overhead_us = (r.gpu_avg_us > 0.0 && r.avg_us > r.gpu_avg_us)
                ? (r.avg_us - r.gpu_avg_us)
                : 0.0;
            if (layer_chain_mode) {
                const double total_steps = static_cast<double>(layer_chain_steps);
                   printf("  %-20s  total=%6.2f µs  step=%6.2f  gpu=%6.2f/step  host=%6.2f/step  s2s=%6.2f/step  host2=%6.2f/step  u_wait=%6.2f/step  u_wait_p99=%6.2f/step  u_wait_max=%6.2f/step  u_wait_n=%5.2f/step  u_full=%5.2f/step  "
                       "tavg=%6.2f  p95=%6.2f  max_err=%.6f  %s\n",
                       r.name,
                       r.avg_us,
                       r.avg_us / total_steps,
                       r.gpu_avg_us / total_steps,
                       host_overhead_us / total_steps,
                       r.submit_to_signal_us / total_steps,
                       r.host_residual_us / total_steps,
                       r.upload_wait_us / total_steps,
                       r.upload_wait_p99_us / total_steps,
                       r.upload_wait_max_us / total_steps,
                       r.upload_wait_count / total_steps,
                       r.upload_ring_full_count / total_steps,
                       r.trimmed_avg_us,
                       r.p95_us,
                       r.max_error,
                       r.correct ? "PASS" : "FAIL");
            } else {
                const double burst_total_us = r.avg_us * static_cast<double>(dispatches_per_submit);
                const double burst_gpu_total_us = r.gpu_avg_us * static_cast<double>(dispatches_per_submit);
                const double burst_host_total_us = host_overhead_us * static_cast<double>(dispatches_per_submit);
                const double burst_submit_to_signal_us = r.submit_to_signal_us * static_cast<double>(dispatches_per_submit);
                const double burst_host_residual_us = r.host_residual_us * static_cast<double>(dispatches_per_submit);
                  printf("  %-20s  total=%6.2f µs  per=%6.2f µs  gpu=%6.2f total/%6.2f per  "
                      "host=%6.2f total/%6.2f per  s2s=%6.2f total/%6.2f per  host2=%6.2f total/%6.2f per  "
                      "u_wait=%6.2f total/%6.2f per  u_wait_p99=%6.2f per  u_wait_max=%6.2f per  u_wait_n=%5.2f total/%5.2f per  u_full=%5.2f total/%5.2f per  "
                       "tavg=%6.2f  p50=%6.2f  p95=%6.2f  p99=%6.2f  "
                       "min=%6.2f  max=%6.2f  sd=%6.2f  jitter=%4.2fx  "
                       "throughput=%5.2f GB/s  max_err=%.6f  %s\n",
                       r.name,
                       burst_total_us,
                       r.avg_us,
                       burst_gpu_total_us,
                       r.gpu_avg_us,
                       burst_host_total_us,
                       host_overhead_us,
                       burst_submit_to_signal_us,
                       r.submit_to_signal_us,
                       burst_host_residual_us,
                       r.host_residual_us,
                       r.upload_wait_us * static_cast<double>(dispatches_per_submit),
                       r.upload_wait_us,
                       r.upload_wait_p99_us,
                       r.upload_wait_max_us,
                       r.upload_wait_count * static_cast<double>(dispatches_per_submit),
                       r.upload_wait_count,
                       r.upload_ring_full_count * static_cast<double>(dispatches_per_submit),
                       r.upload_ring_full_count,
                       r.trimmed_avg_us, r.p50_us, r.p95_us, r.p99_us,
                       r.min_us, r.max_us, r.stddev_us, r.jitter_ratio,
                       r.throughput_gb_s, r.max_error,
                       r.correct ? "PASS" : "FAIL");
            }
        }

        printf("\n  -- Consolidated (%d sessions) --\n", sessions);
        if (agg.count > 0) {
            const double inv = 1.0 / static_cast<double>(agg.count);
            const double avg_us = agg.sum_avg_us * inv;
            const double gpu_avg_us = agg.sum_gpu_avg_us * inv;
            const double host_overhead_us = (gpu_avg_us > 0.0 && avg_us > gpu_avg_us)
                ? (avg_us - gpu_avg_us)
                : 0.0;
            if (layer_chain_mode) {
                const double total_steps = static_cast<double>(layer_chain_steps);
                   printf("  %-20s  total=%6.2f µs  step=%6.2f  gpu=%6.2f/step  host=%6.2f/step  s2s=%6.2f/step  host2=%6.2f/step  u_wait=%6.2f/step  u_wait_p99=%6.2f/step  u_wait_max=%6.2f/step  u_wait_n=%5.2f/step  u_full=%5.2f/step  "
                       "tavg=%6.2f  p95=%6.2f  max_err=%.6f  %s\n",
                       agg.name,
                       avg_us,
                       avg_us / total_steps,
                       gpu_avg_us / total_steps,
                       host_overhead_us / total_steps,
                       (agg.sum_submit_to_signal_us * inv) / total_steps,
                       (agg.sum_host_residual_us * inv) / total_steps,
                       (agg.sum_upload_wait_us * inv) / total_steps,
                       (agg.sum_upload_wait_p99_us * inv) / total_steps,
                       agg.max_upload_wait_max_us / total_steps,
                       (agg.sum_upload_wait_count * inv) / total_steps,
                       (agg.sum_upload_ring_full_count * inv) / total_steps,
                       agg.sum_trimmed_avg_us * inv,
                       agg.sum_p95_us * inv,
                       agg.max_error,
                       agg.all_correct ? "PASS" : "FAIL");
            } else {
                const double burst_total_us = avg_us * static_cast<double>(dispatches_per_submit);
                const double burst_gpu_total_us = gpu_avg_us * static_cast<double>(dispatches_per_submit);
                const double burst_host_total_us = host_overhead_us * static_cast<double>(dispatches_per_submit);
                const double burst_submit_to_signal_us = (agg.sum_submit_to_signal_us * inv) * static_cast<double>(dispatches_per_submit);
                const double burst_host_residual_us = (agg.sum_host_residual_us * inv) * static_cast<double>(dispatches_per_submit);
                  printf("  %-20s  total=%6.2f µs  per=%6.2f µs  gpu=%6.2f total/%6.2f per  "
                      "host=%6.2f total/%6.2f per  s2s=%6.2f total/%6.2f per  host2=%6.2f total/%6.2f per  "
                      "u_wait=%6.2f total/%6.2f per  u_wait_p99=%6.2f per  u_wait_max=%6.2f per  u_wait_n=%5.2f total/%5.2f per  u_full=%5.2f total/%5.2f per  "
                       "tavg=%6.2f  p95=%6.2f  sd=%6.2f  jitter=%4.2fx  "
                       "throughput=%5.2f GB/s  max_err=%.6f  %s\n",
                       agg.name,
                       burst_total_us,
                       avg_us,
                       burst_gpu_total_us,
                       gpu_avg_us,
                       burst_host_total_us,
                       host_overhead_us,
                       burst_submit_to_signal_us,
                       agg.sum_submit_to_signal_us * inv,
                       burst_host_residual_us,
                       agg.sum_host_residual_us * inv,
                       (agg.sum_upload_wait_us * inv) * static_cast<double>(dispatches_per_submit),
                       agg.sum_upload_wait_us * inv,
                       agg.sum_upload_wait_p99_us * inv,
                       agg.max_upload_wait_max_us,
                       (agg.sum_upload_wait_count * inv) * static_cast<double>(dispatches_per_submit),
                       agg.sum_upload_wait_count * inv,
                       (agg.sum_upload_ring_full_count * inv) * static_cast<double>(dispatches_per_submit),
                       agg.sum_upload_ring_full_count * inv,
                       agg.sum_trimmed_avg_us * inv,
                       agg.sum_p95_us * inv,
                       agg.sum_stddev_us * inv,
                       agg.sum_jitter_ratio * inv,
                       agg.sum_throughput_gb_s * inv,
                       agg.max_error,
                       agg.all_correct ? "PASS" : "FAIL");
            }
        }
        printf("\n");
    }

    accel.Shutdown();
    printf("[VulkanBench] Complete.\n");
    return 0;
}
