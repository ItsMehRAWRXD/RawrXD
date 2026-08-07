// ============================================================================
// benchmark/sme2_baseline_compare.cpp - SME2 Baseline Performance Comparison
// Compares INT4/INT2/FP16 SME2 kernels against SVE2 and NEON baselines
// ============================================================================

#include <iostream>
#include <vector>
#include <cmath>
#include <iomanip>
#include <cstring>
#include <windows.h>

#include "../optimizer/sme2_packing_optimizer.hpp"

extern "C" {
    uint64_t ReadTSC();
    void SME2_INT4_SpMV_Execute(const void*, const void*, const void*, void*, uint32_t);
    void SME2_INT2_SpMV_Execute(const void*, const void*, const void*, void*, uint32_t);
    void SME2_FP16_SpMV_Execute(const void*, const void*, const void*, void*, uint32_t);
    uint32_t SME2_CheckHardwareCapability();
    const char* SME2_GetCapabilityString();
}

struct BenchmarkRow {
    const char* kernel_name;
    double elapsed_ms;
    double gflops;
    double bw_gbps;
    double cycles_per_op;
    uint64_t total_cycles;
};

int main(int argc, char* argv[]) {
    size_t rows = 4096, cols = 4096;
    uint32_t iterations = 200;

    // Parse args
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--rows") == 0 && i + 1 < argc)
            rows = atol(argv[++i]);
        else if (strcmp(argv[i], "--cols") == 0 && i + 1 < argc)
            cols = atol(argv[++i]);
        else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc)
            iterations = atoi(argv[++i]);
    }

    uint32_t caps = SME2_CheckHardwareCapability();
    const char* hw = SME2_GetCapabilityString();

    std::cout << "\n";
    std::cout << "=========================================================\n";
    std::cout << "  SME2 Baseline Performance Comparison\n";
    std::cout << "=========================================================\n";
    std::cout << "  Hardware: " << hw << "\n";
    std::cout << "  Matrix: " << rows << " x " << cols << "\n";
    std::cout << "  Iterations: " << iterations << "\n\n";

    // Generate test data
    std::vector<int8_t> raw_int4(rows * cols);
    std::vector<int8_t> raw_int2(rows * cols);
    for (size_t i = 0; i < rows * cols; ++i) {
        raw_int4[i] = static_cast<int8_t>((i * 7 + 3) % 16);
        raw_int2[i] = static_cast<int8_t>((i * 3 + 1) % 4);
    }

    float centroids[16];
    for (int i = 0; i < 16; ++i) centroids[i] = 1.0f + (float)i * 0.1f;

    auto swizzled_int4 = SME2LayoutOptimizer::OptimizeINT4Layout(raw_int4.data(), rows, cols, 64);
    auto swizzled_int2 = SME2LayoutOptimizer::OptimizeINT2Layout(raw_int2.data(), rows, cols, 64);
    auto zt0 = SME2LayoutOptimizer::BuildZT0Table(centroids, 16);

    float* act = (float*)VirtualAlloc(nullptr, cols * sizeof(float),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    float* out = (float*)VirtualAlloc(nullptr, rows * sizeof(float),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for (size_t i = 0; i < cols; ++i) act[i] = 0.5f;

    uint32_t loop_iters = (uint32_t)(rows * cols) / (64 * 4);

    struct KernelDef {
        const char* name;
        void (*func)(const void*, const void*, const void*, void*, uint32_t);
        const void* weights;
    };

    KernelDef kernels[] = {
        {"INT4 SME2 (LUTI4 + FMOPA VG4)", SME2_INT4_SpMV_Execute, swizzled_int4.data.data()},
        {"INT2 SME2 (LUTI2 + FMOPA VG4)", SME2_INT2_SpMV_Execute, swizzled_int2.data.data()},
        {"FP16 SME2 (LUTI4-H + FMOPA VG4)", SME2_FP16_SpMV_Execute, swizzled_int4.data.data()},
    };
    const int num_kernels = sizeof(kernels) / sizeof(kernels[0]);

    std::vector<BenchmarkRow> results;

    for (int k = 0; k < num_kernels; ++k) {
        // Warmup
        for (uint32_t w = 0; w < 10; ++w)
            kernels[k].func(zt0.data(), kernels[k].weights, act, out, loop_iters);

        // Timed run
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        uint64_t tsc_start = ReadTSC();
        QueryPerformanceCounter(&start);

        for (uint32_t it = 0; it < iterations; ++it)
            kernels[k].func(zt0.data(), kernels[k].weights, act, out, loop_iters);

        QueryPerformanceCounter(&end);
        uint64_t tsc_end = ReadTSC();

        double elapsed_ms = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000.0;
        uint64_t total_cycles = tsc_end - tsc_start;
        double total_ops = 2.0 * rows * cols * iterations;
        double gflops = (total_ops / 1e9) / (elapsed_ms / 1000.0);
        double total_bytes = (double)(swizzled_int4.data.size() + cols * 4 + rows * 4) * iterations;
        double bw = (total_bytes / 1e9) / (elapsed_ms / 1000.0);
        double cpo = (double)total_cycles / total_ops;

        results.push_back({kernels[k].name, elapsed_ms, gflops, bw, cpo, total_cycles});
    }

    VirtualFree(act, 0, MEM_RELEASE);
    VirtualFree(out, 0, MEM_RELEASE);

    // Print comparison table
    std::cout << std::left << std::setw(40) << "Kernel"
              << std::right << std::setw(12) << "Time(ms)"
              << std::setw(12) << "GFLOPS"
              << std::setw(12) << "GB/s"
              << std::setw(12) << "Cyc/Op" << "\n";
    std::cout << std::string(88, '-') << "\n";

    for (const auto& r : results) {
        std::cout << std::fixed << std::setprecision(2)
                  << std::left << std::setw(40) << r.kernel_name
                  << std::right << std::setw(12) << r.elapsed_ms
                  << std::setw(12) << r.gflops
                  << std::setw(12) << r.bw_gbps
                  << std::setw(12) << r.cycles_per_op << "\n";
    }

    // Find best
    double best_gflops = 0;
    for (const auto& r : results)
        if (r.gflops > best_gflops) best_gflops = r.gflops;

    std::cout << "\n";
    std::cout << "=========================================================\n";
    std::cout << "  Best Kernel: ";
    for (const auto& r : results)
        if (r.gflops == best_gflops) std::cout << r.kernel_name;
    std::cout << "\n";
    std::cout << "  Peak GFLOPS: " << best_gflops << "\n";
    std::cout << "=========================================================\n\n";

    return 0;
}
