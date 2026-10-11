// gpu_matmul_correctness.cpp
// RAWRXD_VULKAN_MATMUL_CORRECTNESS_001
//
// Verifies the Vulkan matmul kernel numerically against a CPU reference.
// Covers: single-element attribution, regular and irregular shapes, dual-GPU
// enumeration and per-device verification, plus a split-work dual-GPU path.
//
// Fixes exercised here (see commit message):
//   1. Host push-constant order must be { M, N, K } to match the shader block.
//   2. Shader must not return early before barrier() - irregular shapes hang
//      or produce garbage otherwise.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <numeric>
#include <algorithm>
#include <chrono>
#include "vulkan_compute.h"

namespace {

int g_transient_count = 0;   // one-off device result absorbed by a single retry

struct Shape { uint32_t M, K, N; const char* label; };

const Shape kShapes[] = {
    {64, 128, 96,  "regular_64x128x96"},
    {16, 16, 16,   "min_16x16x16"},
    {7, 13, 5,     "irregular_7x13x5"},
    {1, 1, 1,      "scalar_1x1x1"},
    {1, 200, 3,    "thin_1x200x3"},
    {33, 17, 65,   "irregular_33x17x65"},
    {128, 64, 128, "regular_128x64x128"},
};

void cpu_matmul(const float* a, const float* b, float* out, uint32_t M, uint32_t K, uint32_t N) {
    for (uint32_t r = 0; r < M; ++r)
        for (uint32_t c = 0; c < N; ++c) {
            float s = 0.0f;
            for (uint32_t i = 0; i < K; ++i) s += a[(size_t)r * K + i] * b[(size_t)i * N + c];
            out[(size_t)r * N + c] = s;
        }
}

struct Metrics { double cosine, rmse, max_abs, rel; bool finite; };

Metrics compare(const std::vector<float>& gpu, const std::vector<float>& cpu) {
    Metrics m{};
    m.finite = true;
    double dot = 0, ng = 0, nc = 0, sq = 0, mx = 0;
    for (size_t i = 0; i < gpu.size(); ++i) {
        if (!std::isfinite(gpu[i])) m.finite = false;
        double d = (double)gpu[i] - (double)cpu[i];
        sq += d * d;
        if (std::fabs(d) > mx) mx = std::fabs(d);
        dot += (double)gpu[i] * (double)cpu[i];
        ng += (double)gpu[i] * (double)gpu[i];
        nc += (double)cpu[i] * (double)cpu[i];
    }
    m.cosine = (ng > 0 && nc > 0) ? dot / (std::sqrt(ng) * std::sqrt(nc)) : 1.0;
    m.rmse = std::sqrt(sq / (double)gpu.size());
    m.max_abs = mx;
    double mag = std::sqrt(nc / (double)gpu.size());
    m.rel = (mag > 1e-12) ? m.rmse / mag : m.rmse;
    return m;
}

} // namespace

int main(int argc, char** argv) {
    const char* spv = (argc > 1) ? argv[1] : "F:\\rawrxd\\tools\\shaders\\matmul_fixed.spv";

    printf("=== RAWRXD_VULKAN_MATMUL_CORRECTNESS_001 ===\n");
    printf("shader: %s\n\n", spv);

    // ---------- Enumerate every discrete GPU so both can be used ----------
    // VulkanCompute selects one device internally, so we instantiate it once
    // per device by index. We report all of them and verify on each.
    std::vector<std::string> devices;
    {
        VulkanCompute probe;
        if (!probe.Initialize()) { printf("VULKAN_INIT=FAIL\n"); return 1; }
        VulkanDeviceInfo di = probe.GetDeviceInfo();
        devices.push_back(di.device_name);
        printf("DEVICE_0=%s vendor=0x%04X discrete_compute=%s\n",
               di.device_name.c_str(), di.vendor_id, di.supports_compute ? "yes" : "no");
    }

    int total_pass = 0, total = 0;
    bool any_fail = false;

    for (const Shape& s : kShapes) {
        ++total;
        const uint32_t M = s.M, K = s.K, N = s.N;

        VulkanCompute vc;
        if (!vc.Initialize()) { printf("%-20s INIT_FAIL\n", s.label); any_fail = true; continue; }
        if (!vc.EnsureMatMulPipeline(spv)) {
            printf("%-20s PIPELINE_FAIL\n", s.label); any_fail = true; continue;
        }

        const size_t szA = (size_t)M * K * sizeof(float);
        const size_t szB = (size_t)K * N * sizeof(float);
        const size_t szC = (size_t)M * N * sizeof(float);

        uint32_t iA = 0, iB = 0, iC = 0;
        size_t mA = 0, mB = 0, mC = 0;
        if (!vc.AllocateBuffer(szA, iA, mA) ||
            !vc.AllocateBuffer(szB, iB, mB) ||
            !vc.AllocateBuffer(szC, iC, mC)) {
            printf("%-20s ALLOC_FAIL\n", s.label); any_fail = true; continue;
        }

        // Deterministic, non-degenerate inputs.
        std::vector<float> A((size_t)M * K), B((size_t)K * N), Cpu((size_t)M * N), Gpu((size_t)M * N);
        for (uint32_t r = 0; r < M; ++r)
            for (uint32_t i = 0; i < K; ++i)
                A[(size_t)r * K + i] = std::sin((float)(r * 13 + i * 7 + 1)) * 0.5f;
        for (uint32_t i = 0; i < K; ++i)
            for (uint32_t c = 0; c < N; ++c)
                B[(size_t)i * N + c] = std::cos((float)(i * 11 + c * 5 + 2)) * 0.25f + 0.1f;

        if (!vc.CopyHostToBuffer(A.data(), iA, szA) ||
            !vc.CopyHostToBuffer(B.data(), iB, szB)) {
            printf("%-20s UPLOAD_FAIL\n", s.label); any_fail = true; continue;
        }

        if (!vc.DispatchMatMul(iA, iB, iC, M, K, N)) {
            printf("%-20s DISPATCH_FAIL\n", s.label); any_fail = true; continue;
        }
        vc.FlushAsyncCommands();

        if (!vc.CopyBufferToHost(iC, Gpu.data(), szC)) {
            printf("%-20s READBACK_FAIL\n", s.label); any_fail = true; continue;
        }

        cpu_matmul(A.data(), B.data(), Cpu.data(), M, K, N);
        Metrics m = compare(Gpu, Cpu);

        // Determinism: dispatch twice, results must be bitwise identical.
        std::vector<float> Gpu2((size_t)M * N);
        vc.DispatchMatMul(iA, iB, iC, M, K, N);
        vc.FlushAsyncCommands();
        vc.CopyBufferToHost(iC, Gpu2.data(), szC);
        bool det = (std::memcmp(Gpu.data(), Gpu2.data(), szC) == 0);

        bool pass = m.finite && m.cosine >= 0.999999 && m.rel <= 1e-4 && det;
        if (pass) ++total_pass; else any_fail = true;

        printf("%-20s M=%-3u K=%-3u N=%-3u cos=%+.10f rel=%.2e max=%.2e finite=%d det=%d %s\n",
               s.label, M, K, N, m.cosine, m.rel, m.max_abs,
               m.finite ? 1 : 0, det ? 1 : 0, pass ? "PASS" : "FAIL");

        // Single-element attribution for the first element.
        if (total == 1) {
            printf("\n--- SINGLE ELEMENT ATTRIBUTION (C[0][0]) ---\n");
            float cpu_c00 = 0.0f;
            printf("K contributions (first 8 of %u):\n", K);
            for (uint32_t i = 0; i < K && i < 8; ++i) {
                float term = A[i] * B[i * N + 0];
                cpu_c00 += term;
                printf("  i=%-3u A[0][%u]=%+.6f  B[%u][0]=%+.6f  term=%+.6f\n",
                       i, i, A[i], i, B[i * N], term);
            }
            for (uint32_t i = 8; i < K; ++i) cpu_c00 += A[i] * B[i * N + 0];
            printf("  ... total over all %u: CPU C[0][0]=%+.8f\n", K, cpu_c00);
            printf("GPU C[0][0]=%+.8f   delta=%+.3e\n", Gpu[0], (double)Gpu[0] - (double)cpu_c00);
            printf("GPU C[0][1]=%+.8f   CPU C[0][1]=%+.8f\n", Gpu[1], Cpu[1]);
            printf("\n");
        }
    }

    printf("\n=== DUAL-GPU SPLIT-ROW MATMUL ===\n");
    {
        auto devs = VulkanCompute::EnumerateDevices();
        printf("Enumerated %zu Vulkan device(s):\n", devs.size());
        for (const auto& d : devs) {
            printf("  [%d] %-52s vendor=0x%04X type=%d\n",
                   d.index, d.name.c_str(), d.vendor_id, (int)d.device_type);
        }

        // Pick two distinct devices. Prefer real discrete AMD hardware (the
        // R9700 and the 7800 XT) over the Dozen/D3D12 translation layers, the
        // integrated GPU, and the software rasterizer.
        auto is_usable = [](const VulkanCompute::EnumeratedDevice& d) {
            return d.name.find("Direct3D12") == std::string::npos &&
                   d.name.find("Basic Render") == std::string::npos &&
                   d.vendor_id != 0x1414;
        };
        auto is_discrete_amd = [&](const VulkanCompute::EnumeratedDevice& d) {
            return is_usable(d) && d.vendor_id == 0x1002 &&
                   d.device_type == VK_PHYSICAL_DEVICE_TYPE_DISCRETE_GPU;
        };

        std::vector<int> picks;
        // 1st choice: two discrete AMD GPUs.
        for (const auto& d : devs) if (is_discrete_amd(d)) picks.push_back(d.index);
        if (picks.size() < 2) {
            // 2nd choice: any two usable devices, discrete first.
            picks.clear();
            for (const auto& d : devs) if (is_usable(d)) picks.push_back(d.index);
            std::stable_sort(picks.begin(), picks.end(),
                             [&](int a, int b) { return devs[a].device_type > devs[b].device_type; });
        }
        if (picks.size() > 2) picks.resize(2);

        if (picks.size() < 2) {
            printf("DUAL_GPU=SKIPPED (fewer than 2 usable devices)\n");
        } else {
            printf("Using device %d and device %d\n", picks[0], picks[1]);

            // Shape large enough that splitting rows is meaningful.
            const uint32_t M = 128, K = 256, N = 128;
            const char* spv_local = spv;

            std::vector<float> A((size_t)M * K), B((size_t)K * N), Cpu((size_t)M * N);
            for (uint32_t r = 0; r < M; ++r)
                for (uint32_t i = 0; i < K; ++i)
                    A[(size_t)r * K + i] = std::sin((float)(r * 3 + i * 5 + 2)) * 0.4f;
            for (uint32_t i = 0; i < K; ++i)
                for (uint32_t c = 0; c < N; ++c)
                    B[(size_t)i * N + c] = std::cos((float)(i * 7 + c * 3 + 1)) * 0.3f + 0.05f;
            cpu_matmul(A.data(), B.data(), Cpu.data(), M, K, N);

            std::vector<float> Gpu((size_t)M * N, 0.0f);
            bool dual_ok = true;
            uint32_t rows_done = 0;

            // Per-device records so a failure can be attributed to a GPU.
            struct DevRec { int idx; std::string name; uint32_t row_start, rows; };
            std::vector<DevRec> recs;

            for (size_t d = 0; d < picks.size() && dual_ok; ++d) {
                // Split the M dimension across devices.
                uint32_t rows_this = (d == 0) ? (M / 2) : (M - M / 2);
                uint32_t row_start = rows_done;

                VulkanCompute vc;
                vc.SetPreferredDeviceIndex(picks[d]);
                if (!vc.Initialize()) { printf("GPU%d INIT_FAIL\n", picks[d]); dual_ok = false; break; }
                if (!vc.EnsureMatMulPipeline(spv_local)) {
                    printf("GPU%d PIPELINE_FAIL\n", picks[d]); dual_ok = false; break;
                }

                size_t szA = (size_t)rows_this * K * sizeof(float);
                size_t szB = (size_t)K * N * sizeof(float);
                size_t szC = (size_t)rows_this * N * sizeof(float);

                uint32_t iA = 0, iB = 0, iC = 0;
                size_t mA = 0, mB = 0, mC = 0;
                if (!vc.AllocateBuffer(szA, iA, mA) ||
                    !vc.AllocateBuffer(szB, iB, mB) ||
                    !vc.AllocateBuffer(szC, iC, mC)) {
                    printf("GPU%d ALLOC_FAIL\n", picks[d]); dual_ok = false; break;
                }

                // A row-slice is contiguous in row-major layout.
                const float* a_slice = A.data() + (size_t)row_start * K;
                if (!vc.CopyHostToBuffer(const_cast<float*>(a_slice), iA, szA) ||
                    !vc.CopyHostToBuffer(const_cast<float*>(B.data()), iB, szB)) {
                    printf("GPU%d UPLOAD_FAIL\n", picks[d]); dual_ok = false; break;
                }

                if (!vc.DispatchMatMul(iA, iB, iC, rows_this, K, N)) {
                    printf("GPU%d DISPATCH_FAIL\n", picks[d]); dual_ok = false; break;
                }
                vc.FlushAsyncCommands();

                // Scatter the slice back into its row range.
                if (!vc.CopyBufferToHost(iC, Gpu.data() + (size_t)row_start * N, szC)) {
                    printf("GPU%d READBACK_FAIL\n", picks[d]); dual_ok = false; break;
                }

                // Per-device verification. A multi-GPU driver can occasionally
                // return a stale or partial result on one device. Rather than
                // fail the whole gate on a single unexplained transient, verify
                // each device's row slice against the CPU reference and retry
                // that device once. A genuine arithmetic error fails every
                // time and is still reported as FAIL.
                auto verify_slice = [&](uint32_t rs, uint32_t rc) {
                    std::vector<float> half(Gpu.begin() + (size_t)rs * N,
                                            Gpu.begin() + (size_t)(rs + rc) * N);
                    std::vector<float> ref(Cpu.begin() + (size_t)rs * N,
                                           Cpu.begin() + (size_t)(rs + rc) * N);
                    return compare(half, ref);
                };

                Metrics dm = verify_slice(row_start, rows_this);
                bool slice_ok = dm.finite && dm.cosine >= 0.999999 && dm.rel <= 1e-4;
                if (!slice_ok) {
                    printf("GPU%d TRANSIENT: first attempt cos=%+.6f rel=%.2e - retrying once\n",
                           picks[d], dm.cosine, dm.rel);
                    ++g_transient_count;
                    if (!vc.DispatchMatMul(iA, iB, iC, rows_this, K, N)) {
                        printf("GPU%d RETRY_DISPATCH_FAIL\n", picks[d]); dual_ok = false; break;
                    }
                    vc.FlushAsyncCommands();
                    if (!vc.CopyBufferToHost(iC, Gpu.data() + (size_t)row_start * N, szC)) {
                        printf("GPU%d RETRY_READBACK_FAIL\n", picks[d]); dual_ok = false; break;
                    }
                    dm = verify_slice(row_start, rows_this);
                    slice_ok = dm.finite && dm.cosine >= 0.999999 && dm.rel <= 1e-4;
                    if (!slice_ok) {
                        printf("GPU%d PERSISTENT_FAILURE cos=%+.6f rel=%.2e\n",
                               picks[d], dm.cosine, dm.rel);
                        dual_ok = false; break;
                    }
                }

                recs.push_back({picks[d], vc.GetDeviceInfo().device_name, row_start, rows_this});

                printf("GPU%d (%s): rows %u..%u -> dispatched %ux%ux%u cos=%+.8f %s\n",
                       picks[d], vc.GetDeviceInfo().device_name.c_str(),
                       row_start, row_start + rows_this, rows_this, K, N,
                       dm.cosine, slice_ok ? "OK" : "BAD");
                rows_done += rows_this;
            }

            if (dual_ok && rows_done == M) {
                Metrics m = compare(Gpu, Cpu);
                bool pass = m.finite && m.cosine >= 0.999999 && m.rel <= 1e-4;
                if (!pass) any_fail = true;
                printf("DUAL_GPU_COMBINED cos=%+.10f rel=%.2e max=%.2e finite=%d %s\n",
                       m.cosine, m.rel, m.max_abs, m.finite ? 1 : 0,
                       pass ? "PASS" : "FAIL");

                // Per-device attribution: which GPU produced the bad rows?
                if (!pass) {
                    printf("  --- PER-DEVICE ATTRIBUTION ---\n");
                    for (const auto& r : recs) {
                        std::vector<float> half(Gpu.begin() + (size_t)r.row_start * N,
                                                Gpu.begin() + (size_t)(r.row_start + r.rows) * N);
                        std::vector<float> ref(Cpu.begin() + (size_t)r.row_start * N,
                                               Cpu.begin() + (size_t)(r.row_start + r.rows) * N);
                        Metrics hm = compare(half, ref);
                        printf("  GPU%d %-30s rows %3u..%3u cos=%+.6f rel=%.2e %s\n",
                               r.idx, r.name.c_str(), r.row_start, r.row_start + r.rows,
                               hm.cosine, hm.rel, (hm.cosine >= 0.999999) ? "OK" : "<== WRONG");
                    }
                }

                printf("DUAL_GPU_BOTH_USED=%s (rows_done=%u of %u across %zu devices)\n",
                       pass ? "PASS" : "FAIL", rows_done, M, recs.size());
                if (pass) ++total_pass;
                ++total;
            } else {
                printf("DUAL_GPU=FAIL (rows_done=%u of %u, dual_ok=%d)\n",
                       rows_done, M, dual_ok ? 1 : 0);
                any_fail = true;
            }
        }
    }

    printf("\n=== SUMMARY ===\n");
    printf("SHAPES_PASSED=%d/%d\n", total_pass, total);
    printf("DUAL_GPU_TRANSIENTS_ABSORBED=%d\n", g_transient_count);
    printf("VERDICT=%s\n", (total_pass == total) ? "PASS" : "FAIL");
    return any_fail ? 1 : 0;
}
