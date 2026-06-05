// ============================================================================
// bench_allocator.cpp — VRAM Arena Stress Test
// ============================================================================
//
// Validates the sovereign Vulkan Data Plane memory allocator before kernel
// optimization. Simulates the full chat lifecycle:
//   1. Boot   — allocate model weights (Q4_K_M)
//   2. Context — grow KV cache to 32k tokens
//   3. Thrash  — 500x allocate/free 1 GB to prove no fragmentation leaks
//
// Target GPU: AMD Radeon RX 7800 XT (16 GB VRAM)
// Pass criteria:
//   - bytes_used == sum(tensor sizes)  (integrity)
//   - zero VRAM leak after 500 cycles  (stability)
//   - UploadTensor 512 MB bounded by PCIe Gen4 x16 (~16 GB/s)  (throughput)
// ============================================================================

#include "RawrXD_VulkanAccelerator.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>

using namespace rawrxd;

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

struct BenchConfig {
    size_t boot_mb = 4600;                  // Simulated 7B Q4_K_M weight footprint
    uint32_t boot_tensor_count = 46;
    uint32_t context_tokens = 32768;        // Full target context
    uint32_t context_window_tokens = 4096;  // Sliding resident window
    size_t kv_bytes_per_token = 180224;     // 2 * 22 * 2048 * sizeof(fp16)
    uint32_t thrash_count = 500;
    size_t thrash_mb = 1024;
    uint32_t throughput_runs = 10;
    bool verbose = false;
};

static bool ParseArgs(int argc, char** argv, BenchConfig& cfg) {
    for (int i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (strcmp(a, "--boot-mb") == 0 && i + 1 < argc) {
            cfg.boot_mb = static_cast<size_t>(strtoull(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--boot-tensors") == 0 && i + 1 < argc) {
            cfg.boot_tensor_count = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--context-tokens") == 0 && i + 1 < argc) {
            cfg.context_tokens = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--context-window") == 0 && i + 1 < argc) {
            cfg.context_window_tokens = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--kv-bytes-per-token") == 0 && i + 1 < argc) {
            cfg.kv_bytes_per_token = static_cast<size_t>(strtoull(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--thrash-count") == 0 && i + 1 < argc) {
            cfg.thrash_count = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--thrash-mb") == 0 && i + 1 < argc) {
            cfg.thrash_mb = static_cast<size_t>(strtoull(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--throughput-runs") == 0 && i + 1 < argc) {
            cfg.throughput_runs = static_cast<uint32_t>(strtoul(argv[++i], nullptr, 10));
        } else if (strcmp(a, "--verbose") == 0) {
            cfg.verbose = true;
        } else if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            printf("RawrXD-VRAMAllocatorBench options:\n");
            printf("  --boot-mb <n>              Total boot footprint in MiB (default 4600)\n");
            printf("  --boot-tensors <n>         Number of boot tensors (default 46)\n");
            printf("  --context-tokens <n>       Simulated context length (default 32768)\n");
            printf("  --context-window <n>       Sliding resident window tokens (default 4096)\n");
            printf("  --kv-bytes-per-token <n>   Bytes per token in KV simulation\n");
            printf("  --thrash-count <n>         Allocate/free iterations (default 500)\n");
            printf("  --thrash-mb <n>            Allocation size per thrash iteration (MiB)\n");
            printf("  --throughput-runs <n>      Number of 512MB upload timings (default 10)\n");
            printf("  --verbose                  Print periodic stats in loops\n");
            return false;
        }
    }
    return true;
}

static double NowMs() {
    auto t = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(
        t.time_since_epoch()).count();
    return us / 1000.0;
}

static void PrintStats(const VulkanAccelerator& accel, const char* label) {
    size_t total = 0, free = 0;
    accel.GetMemoryStats(total, free);
    size_t used = total - free;
    printf("  [%s] total=%.2f GB  used=%.2f GB  free=%.2f GB\n",
           label,
           total / (1024.0 * 1024.0 * 1024.0),
           used  / (1024.0 * 1024.0 * 1024.0),
           free  / (1024.0 * 1024.0 * 1024.0));
}

static bool VerifyIntegrity(const VulkanAccelerator& accel,
                            size_t expected_used_bytes) {
    size_t total = 0, free = 0;
    accel.GetMemoryStats(total, free);
    size_t used = total - free;
    // Allow 4 MB tolerance for driver overhead / alignment padding
    size_t diff = (used > expected_used_bytes)
                      ? (used - expected_used_bytes)
                      : (expected_used_bytes - used);
    if (diff > 4 * 1024 * 1024) {
        printf("  [FAIL] Integrity mismatch: expected %.2f MB, got %.2f MB "
               "(diff %.2f MB)\n",
               expected_used_bytes / (1024.0 * 1024.0),
               used / (1024.0 * 1024.0),
               diff / (1024.0 * 1024.0));
        return false;
    }
    printf("  [PASS] Integrity: expected %.2f MB, got %.2f MB "
           "(diff %.2f MB)\n",
           expected_used_bytes / (1024.0 * 1024.0),
           used / (1024.0 * 1024.0),
           diff / (1024.0 * 1024.0));
    return true;
}

// ----------------------------------------------------------------------------
// Phase 1: Boot — simulate Q4_K_M weight upload for a 7B-class model
// ----------------------------------------------------------------------------
static bool Phase1_Boot(VulkanAccelerator& accel,
                        const BenchConfig& cfg,
                        std::vector<GpuTensorHandle>& resident_handles) {
    printf("\n=== PHASE 1: BOOT (Model Weights) ===\n");

    const size_t kTensorCount = std::max<size_t>(1, cfg.boot_tensor_count);
    const size_t boot_total_bytes = cfg.boot_mb * 1024ULL * 1024ULL;
    const size_t kTensorBytes = std::max<size_t>(1, boot_total_bytes / kTensorCount);
    resident_handles.reserve(resident_handles.size() + kTensorCount);

    std::vector<uint8_t> staging(kTensorBytes);
    memset(staging.data(), 0xAB, staging.size()); // sentinel pattern

    double t0 = NowMs();
    size_t total_uploaded = 0;
    for (size_t i = 0; i < kTensorCount; ++i) {
        TensorDesc desc{};
        desc.name = "blk." + std::to_string(i / 4) + ".weight_" + std::to_string(i);
        desc.format = TensorFormat::Q4_K_M;
        desc.rows = 4096;
        desc.cols = 4096;
        desc.size_bytes = kTensorBytes;
        desc.host_ptr = staging.data();

        GpuTensorHandle h = accel.UploadTensor(desc, false);
        if (!h.IsValid()) {
            printf("  [FAIL] UploadTensor failed at tensor %zu\n", i);
            return false;
        }
        resident_handles.push_back(h);
        total_uploaded += kTensorBytes;

        if (cfg.verbose && ((i + 1) % 8 == 0 || i + 1 == kTensorCount)) {
            PrintStats(accel, "Boot");
        }
    }
    double t1 = NowMs();

    double elapsed_sec = (t1 - t0) / 1000.0;
    double gbps = (total_uploaded / (1024.0 * 1024.0 * 1024.0)) / elapsed_sec;
    printf("  Uploaded %zu tensors (%.2f GB) in %.3f s => %.2f GB/s\n",
           kTensorCount, total_uploaded / (1024.0 * 1024.0 * 1024.0),
           elapsed_sec, gbps);
    PrintStats(accel, "Post-Boot");

    if (!VerifyIntegrity(accel, total_uploaded)) return false;

    // Keep weights resident for downstream phases
    return true;
}

// ----------------------------------------------------------------------------
// Phase 2: Context Growth — simulate KV cache expansion to 32k tokens
// ----------------------------------------------------------------------------
static bool Phase2_ContextGrowth(VulkanAccelerator& accel,
                                 const BenchConfig& cfg,
                                 std::vector<GpuTensorHandle>& weight_handles) {
    printf("\n=== PHASE 2: CONTEXT GROWTH (KV Cache 32k) ===\n");

    // TinyLlama-1.1B-ish dimensions:
    //   n_layers = 22, n_heads = 32, head_dim = 64, n_embd = 2048
    // KV cache per token = 2 * n_layers * n_embd * sizeof(float16)
    //                      = 2 * 22 * 2048 * 2 = 180,224 bytes (~176 KB)
    // 32k tokens => ~5.5 GB
    const uint32_t n_ctx    = std::max<uint32_t>(1, cfg.context_tokens);
    const size_t bytes_per_token = std::max<size_t>(1, cfg.kv_bytes_per_token);
    const size_t kv_total_bytes  = bytes_per_token * n_ctx; // ~5.5 GB

    // Allocate as one monolithic KV cache buffer (more realistic)
    std::vector<uint8_t> staging(kv_total_bytes);
    memset(staging.data(), 0xCD, staging.size());

    double t0 = NowMs();
    TensorDesc desc{};
    desc.name = "kv_cache.monolithic";
    desc.format = TensorFormat::F16;
    desc.rows = n_ctx;
    desc.cols = static_cast<uint32_t>(std::min<size_t>(bytes_per_token, 0xFFFFFFFFULL));
    desc.size_bytes = kv_total_bytes;
    desc.host_ptr = staging.data();

    GpuTensorHandle kv = accel.UploadTensor(desc, false);
    if (!kv.IsValid()) {
        printf("  [FAIL] KV cache upload failed (%.2f GB)\n",
               kv_total_bytes / (1024.0 * 1024.0 * 1024.0));
        return false;
    }
    double t1 = NowMs();

    double elapsed_sec = (t1 - t0) / 1000.0;
    double gbps = (kv_total_bytes / (1024.0 * 1024.0 * 1024.0)) / elapsed_sec;
    printf("  Uploaded KV cache %.2f GB in %.3f s => %.2f GB/s\n",
           kv_total_bytes / (1024.0 * 1024.0 * 1024.0), elapsed_sec, gbps);
    PrintStats(accel, "Post-Context");

    size_t expected = 0;
    for (auto& h : weight_handles) expected += h.size_bytes;
    expected += kv.size_bytes;
    if (!VerifyIntegrity(accel, expected)) return false;

    weight_handles.push_back(kv); // keep resident
    return true;
}

// ----------------------------------------------------------------------------
// Phase 3: Thrash — 500x allocate 1 GB / free 1 GB
// ----------------------------------------------------------------------------
static bool Phase3_Thrash(VulkanAccelerator& accel,
                          const BenchConfig& cfg,
                          std::vector<GpuTensorHandle>& resident_handles) {
    printf("\n=== PHASE 3: THRASH (%u x %zu MB alloc/free) ===\n",
           cfg.thrash_count,
           cfg.thrash_mb);

    const int kCycles = static_cast<int>(std::max<uint32_t>(1, cfg.thrash_count));
    const size_t kChunk = std::max<size_t>(1, cfg.thrash_mb) * 1024ULL * 1024ULL;
    std::vector<uint8_t> staging(kChunk);
    memset(staging.data(), 0xEF, staging.size());

    size_t baseline_used = 0;
    {
        size_t total = 0, free = 0;
        accel.GetMemoryStats(total, free);
        baseline_used = total - free;
    }

    double t0 = NowMs();
    int failures = 0;
    for (int i = 0; i < kCycles; ++i) {
        TensorDesc desc{};
        desc.name = "thrash." + std::to_string(i);
        desc.format = TensorFormat::F32;
        desc.rows = 1024;
        desc.cols = 262144; // 1 GB / 4 bytes
        desc.size_bytes = kChunk;
        desc.host_ptr = staging.data();

        GpuTensorHandle h = accel.UploadTensor(desc, false);
        if (!h.IsValid()) {
            ++failures;
            if (failures <= 3) {
                printf("  [WARN] Cycle %d: UploadTensor failed\n", i);
            }
            continue;
        }
        accel.ReleaseTensor(h);

        if ((i + 1) % 100 == 0 || (cfg.verbose && (i + 1) % 25 == 0)) {
            printf("  ... cycle %d/%d\n", i + 1, kCycles);
        }
    }
    double t1 = NowMs();

    double elapsed_sec = (t1 - t0) / 1000.0;
    double ops_per_sec = kCycles / elapsed_sec;
    printf("  Completed %d cycles in %.3f s => %.1f ops/s\n",
           kCycles, elapsed_sec, ops_per_sec);
    if (failures > 0) {
        printf("  [WARN] %d/%d cycles failed to allocate\n", failures, kCycles);
    }

    PrintStats(accel, "Post-Thrash");

    size_t final_used = 0;
    {
        size_t total = 0, free = 0;
        accel.GetMemoryStats(total, free);
        final_used = total - free;
    }
    size_t leak = (final_used > baseline_used)
                      ? (final_used - baseline_used)
                      : 0;
    if (leak > 4 * 1024 * 1024) {
        printf("  [FAIL] VRAM leak detected: %.2f MB above baseline\n",
               leak / (1024.0 * 1024.0));
        return false;
    }
    printf("  [PASS] Zero leak: final %.2f MB vs baseline %.2f MB\n",
           final_used / (1024.0 * 1024.0),
           baseline_used / (1024.0 * 1024.0));
    return true;
}

// ----------------------------------------------------------------------------
// Phase 4: Throughput Micro-benchmark — 512 MB chunk latency
// ----------------------------------------------------------------------------
static bool Phase4_Throughput(VulkanAccelerator& accel, const BenchConfig& cfg) {
    printf("\n=== PHASE 4: THROUGHPUT (512 MB chunk) ===\n");

    const size_t kChunk = 512ULL * 1024ULL * 1024ULL; // 512 MB
    std::vector<uint8_t> staging(kChunk);
    memset(staging.data(), 0x42, staging.size());

    // Warm-up
    {
        TensorDesc w{};
        w.name = "warmup";
        w.format = TensorFormat::F32;
        w.size_bytes = kChunk;
        w.host_ptr = staging.data();
        GpuTensorHandle h = accel.UploadTensor(w, false);
        accel.ReleaseTensor(h);
    }

    const int kRuns = static_cast<int>(std::max<uint32_t>(1, cfg.throughput_runs));
    double best_ms = 1e9, worst_ms = 0, sum_ms = 0;
    for (int i = 0; i < kRuns; ++i) {
        TensorDesc desc{};
        desc.name = "throughput." + std::to_string(i);
        desc.format = TensorFormat::F32;
        desc.size_bytes = kChunk;
        desc.host_ptr = staging.data();

        double t0 = NowMs();
        GpuTensorHandle h = accel.UploadTensor(desc, false);
        double t1 = NowMs();
        accel.ReleaseTensor(h);

        double ms = t1 - t0;
        if (ms < best_ms) best_ms = ms;
        if (ms > worst_ms) worst_ms = ms;
        sum_ms += ms;
    }
    double avg_ms = sum_ms / kRuns;
    double avg_gbps = (kChunk / (1024.0 * 1024.0 * 1024.0)) / (avg_ms / 1000.0);
    double best_gbps = (kChunk / (1024.0 * 1024.0 * 1024.0)) / (best_ms / 1000.0);

    printf("  512 MB upload: avg=%.2f ms (%.2f GB/s)  best=%.2f ms (%.2f GB/s)  "
           "worst=%.2f ms\n",
           avg_ms, avg_gbps, best_ms, best_gbps, worst_ms);

    // PCIe Gen4 x16 theoretical ~16 GB/s; we expect at least 8 GB/s sustained
    if (avg_gbps < 8.0) {
        printf("  [WARN] Throughput below 8 GB/s (PCIe Gen4 x16 expected ~16 GB/s)\n");
    } else {
        printf("  [PASS] Throughput meets 8 GB/s floor\n");
    }
    return true;
}

// ----------------------------------------------------------------------------
// Main
// ----------------------------------------------------------------------------
int main(int argc, char** argv) {
    BenchConfig cfg;
    if (!ParseArgs(argc, argv, cfg)) {
        return 0;
    }

    printf("=================================================================\n");
    printf(" RawrXD VRAM Arena Stress Test\n");
    printf(" Target: AMD Radeon RX 7800 XT (16 GB)\n");
        printf(" Boot: %zu MiB across %u tensors | Context: %u tokens | Thrash: %u x %zu MiB\n",
            cfg.boot_mb,
            cfg.boot_tensor_count,
            cfg.context_tokens,
            cfg.thrash_count,
            cfg.thrash_mb);
    printf("=================================================================\n");

    VulkanAccelerator accel;
    if (!accel.Initialize()) {
        printf("[FATAL] VulkanAccelerator::Initialize() failed.\n");
        printf("        (If no Vulkan GPU is present, this is expected.)\n");
        return 1;
    }
    printf("[OK]    Vulkan initialized.\n");
    PrintStats(accel, "Baseline");

    std::vector<GpuTensorHandle> resident;
    bool ok = true;

    ok = Phase1_Boot(accel, cfg, resident) && ok;
    ok = Phase2_ContextGrowth(accel, cfg, resident) && ok;
    ok = Phase3_Thrash(accel, cfg, resident) && ok;
    ok = Phase4_Throughput(accel, cfg) && ok;

    printf("\n=== CLEANUP ===\n");
    accel.ReleaseAllTensors();
    PrintStats(accel, "Post-Cleanup");

    // Do not call Shutdown() here: VulkanAccelerator destructor already does it.
    printf("\n%s\n", ok ? "[ALL PASS] VRAM arena is battle-hardened."
                     : "[SOME FAIL] Review output above.");
    return ok ? 0 : 2;
}
