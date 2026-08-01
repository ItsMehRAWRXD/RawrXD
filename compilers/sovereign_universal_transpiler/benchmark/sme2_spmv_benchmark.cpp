// ============================================================================
// benchmark/sme2_spmv_benchmark.cpp
// Full Integration Harness: GGUF Loader + Bit-Packing Optimizer + SME2 SpMV
// Measures throughput, bandwidth, and cycle counts for INT2/INT4/FP16 SpMV
// ============================================================================

#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <windows.h>

// Include local headers
#include "../optimizer/sme2_packing_optimizer.hpp"
#include "../optimizer/sme2_spmv_scheduler.hpp"
#include "../optimizer/sme2_luti_lowering.hpp"
#include "gguf_loader.hpp"

// External assembly functions
extern "C" {
    uint64_t ReadTSC();
    uint64_t ReadTSC_Serialized();
    uint64_t ReadTSC_Start();
    uint64_t ReadTSC_End(uint64_t start);

    void SME2_INT4_SpMV_Execute(
        const void* zt0_table,
        const void* weights,
        const void* activations,
        void* output,
        uint32_t iterations
    );

    void SME2_INT2_SpMV_Execute(
        const void* zt0_table,
        const void* weights,
        const void* activations,
        void* output,
        uint32_t iterations
    );

    void SME2_FP16_SpMV_Execute(
        const void* zt0_table,
        const void* weights,
        const void* activations,
        void* output,
        uint32_t iterations
    );
}

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    size_t   rows          = 4096;
    size_t   cols          = 4096;
    uint32_t iterations    = 500;
    uint32_t warmup_iters  = 10;
    uint32_t svl_bytes     = 64;  // 512-bit SVE
    bool     use_gguf      = false;
    const char* gguf_path  = nullptr;
    const char* tensor_name = "output.weight";
    QuantPrecision precision = QuantPrecision::INT4;
};

// ============================================================================
// Benchmark Results
// ============================================================================
struct BenchmarkResult {
    double elapsed_ms;
    uint64_t total_cycles;
    double cycles_per_iter;
    double gflops;
    double bandwidth_gbps;
    double ops_per_cycle;
};

// ============================================================================
// SME2 Benchmark Harness
// ============================================================================
class SME2BenchmarkHarness {
private:
    BenchmarkConfig cfg;
    std::vector<int8_t> raw_weights;
    std::vector<uint8_t> swizzled_weights;
    float zt0_scale_table[16];
    float* activations = nullptr;
    float* output = nullptr;

    void AllocateBuffers() {
        size_t activation_bytes = cfg.cols * sizeof(float);
        activations = static_cast<float*>(VirtualAlloc(
            nullptr, activation_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!activations) throw std::runtime_error("Failed to allocate activations");

        for (size_t i = 0; i < cfg.cols; ++i) {
            activations[i] = 0.5f + (static_cast<float>(i % 10) * 0.1f);
        }

        size_t output_bytes = cfg.rows * sizeof(float);
        output = static_cast<float*>(VirtualAlloc(
            nullptr, output_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!output) throw std::runtime_error("Failed to allocate output");
        memset(output, 0, output_bytes);
    }

    void FreeBuffers() {
        if (activations) { VirtualFree(activations, 0, MEM_RELEASE); activations = nullptr; }
        if (output) { VirtualFree(output, 0, MEM_RELEASE); output = nullptr; }
    }

    void InitZT0Table() {
        for (int i = 0; i < 16; ++i) {
            zt0_scale_table[i] = 1.0f + (static_cast<float>(i) * 0.1f);
        }
    }

    void LoadFromGGUF() {
        GGUFFile gguf_file;
        if (!gguf_file.Open(cfg.gguf_path)) {
            throw std::runtime_error("Failed to open GGUF file");
        }

        GGUFParser parser;
        if (!parser.Parse(gguf_file.Data(), gguf_file.Size())) {
            throw std::runtime_error("Failed to parse GGUF file");
        }

        auto* tensor = parser.FindTensor(cfg.tensor_name);
        if (!tensor) {
            throw std::runtime_error("Tensor not found in GGUF model");
        }

        std::cout << "  GGUF Tensor: " << tensor->name << "\n";
        std::cout << "  Type: " << tensor->type << " Elements: " << tensor->n_elements << "\n";

        const void* tensor_data = parser.GetTensorData(gguf_file.Data(), *tensor);
        raw_weights = GGUFParser::ConvertToINT4(tensor_data, tensor->n_elements, tensor->type);

        cfg.rows = static_cast<size_t>(tensor->dims[0]);
        cfg.cols = static_cast<size_t>(tensor->dims[1]);
    }

    void GenerateSyntheticWeights() {
        size_t total = cfg.rows * cfg.cols;
        raw_weights.resize(total);
        for (size_t i = 0; i < total; ++i) {
            raw_weights[i] = static_cast<int8_t>((i * 7 + 3) % 16);
        }
    }

    BenchmarkResult RunTimedBenchmark(
        const char* label,
        void(*kernel)(const void*, const void*, const void*, void*, uint32_t),
        uint32_t loop_iters)
    {
        std::cout << "  Running " << label << "...\n";

        // Warmup
        for (uint32_t w = 0; w < cfg.warmup_iters; ++w) {
            kernel(zt0_scale_table, swizzled_weights.data(),
                   activations, output, loop_iters);
        }

        // Timed execution
        LARGE_INTEGER freq, start_qpc, end_qpc;
        QueryPerformanceFrequency(&freq);

        uint64_t start_tsc = ReadTSC_Start();
        QueryPerformanceCounter(&start_qpc);

        for (uint32_t it = 0; it < cfg.iterations; ++it) {
            kernel(zt0_scale_table, swizzled_weights.data(),
                   activations, output, loop_iters);
        }

        QueryPerformanceCounter(&end_qpc);
        uint64_t end_tsc = ReadTSC_End(start_tsc);

        // Compute metrics
        BenchmarkResult r;
        r.elapsed_ms = (static_cast<double>(end_qpc.QuadPart - start_qpc.QuadPart) /
                        freq.QuadPart) * 1000.0;
        r.total_cycles = end_tsc;
        r.cycles_per_iter = static_cast<double>(end_tsc) / cfg.iterations;

        // GFLOPS: 2 ops per element (multiply + add) * elements * iterations
        double total_ops = 2.0 * cfg.rows * cfg.cols * cfg.iterations;
        r.gflops = (total_ops / 1e9) / (r.elapsed_ms / 1000.0);

        // Bandwidth: weights + activations + output
        double total_bytes = static_cast<double>(
            swizzled_weights.size() + (cfg.cols * sizeof(float)) + (cfg.rows * sizeof(float))
        ) * cfg.iterations;
        r.bandwidth_gbps = (total_bytes / 1e9) / (r.elapsed_ms / 1000.0);

        r.ops_per_cycle = total_ops / static_cast<double>(end_tsc);

        return r;
    }

public:
    SME2BenchmarkHarness() = default;

    ~SME2BenchmarkHarness() { FreeBuffers(); }

    void Configure(const BenchmarkConfig& config) { cfg = config; }

    void Run() {
        std::cout << "\n";
        std::cout << "=========================================================\n";
        std::cout << "  RawrXD SME2 SpMV Engine & GGUF Pipeline Benchmark\n";
        std::cout << "=========================================================\n";

        // 1. Load or generate weights
        if (cfg.use_gguf && cfg.gguf_path) {
            std::cout << "[GGUF Loader] Loading model from: " << cfg.gguf_path << "\n";
            LoadFromGGUF();
        } else {
            std::cout << "[Generator] Creating synthetic INT4 weight matrix\n";
            GenerateSyntheticWeights();
        }

        std::cout << "  Matrix: " << cfg.rows << " x " << cfg.cols << "\n";
        std::cout << "  SVL: " << cfg.svl_bytes * 8 << "-bit\n";
        std::cout << "  Iterations: " << cfg.iterations << "\n\n";

        // 2. Run bit-packing layout optimization
        std::cout << "[Layout Optimizer] Swizzling weights for LUTI alignment...\n";
        if (cfg.precision == QuantPrecision::INT4) {
            auto result = SME2LayoutOptimizer::OptimizeINT4Layout(
                raw_weights.data(), cfg.rows, cfg.cols, cfg.svl_bytes);
            swizzled_weights = std::move(result.data);
        } else {
            auto result = SME2LayoutOptimizer::OptimizeINT2Layout(
                raw_weights.data(), cfg.rows, cfg.cols, cfg.svl_bytes);
            swizzled_weights = std::move(result.data);
        }
        std::cout << "  Swizzled: " << swizzled_weights.size() << " bytes\n";

        // 3. Build ZT0 dequantization table
        InitZT0Table();
        auto zt0_buf = SME2LayoutOptimizer::BuildZT0Table(zt0_scale_table, 16);
        std::cout << "  ZT0 Table: " << zt0_buf.size() << " bytes (16 FP32 centroids)\n";

        // 4. Generate software-pipelined schedule
        std::cout << "\n[Scheduler] Generating 3-stage pipeline...\n";
        auto schedule = SME2SpMVScheduler::SchedulePipelinedLoop(cfg.precision, 1);
        std::cout << "  Pipeline stages: 3 (Prefetch -> Dequantize -> Outer Product)\n";
        std::cout << "  Instructions scheduled: " << schedule.size() << "\n";

        // 5. Allocate buffers
        AllocateBuffers();

        // 6. Calculate loop iterations
        uint32_t total_elements = static_cast<uint32_t>(cfg.rows * cfg.cols);
        uint32_t loop_iters = total_elements / (cfg.svl_bytes * 4);

        // 7. Run benchmarks
        std::cout << "\n[Benchmark] Executing timed runs...\n";
        std::cout << "---------------------------------------------------------\n";

        BenchmarkResult results[3];
        int num_kernels = 0;

        if (cfg.precision == QuantPrecision::INT4) {
            results[num_kernels++] = RunTimedBenchmark(
                "INT4 SpMV (LUTI4 + FMOPA VG4)",
                SME2_INT4_SpMV_Execute, loop_iters);
        } else {
            results[num_kernels++] = RunTimedBenchmark(
                "INT2 SpMV (LUTI2 + FMOPA VG4)",
                SME2_INT2_SpMV_Execute, loop_iters);
        }

        results[num_kernels++] = RunTimedBenchmark(
            "FP16 SpMV (LUTI4-H + FMOPA VG4)",
            SME2_FP16_SpMV_Execute, loop_iters);

        // 8. Print results table
        std::cout << "\n";
        std::cout << "=========================================================\n";
        std::cout << "  BENCHMARK RESULTS\n";
        std::cout << "=========================================================\n";
        std::cout << std::fixed << std::setprecision(2);
        std::cout << std::left << std::setw(30) << "Metric"
                  << std::right << std::setw(15) << "INT4/INT2"
                  << std::right << std::setw(15) << "FP16" << "\n";
        std::cout << "---------------------------------------------------------\n";

        for (int k = 0; k < num_kernels; ++k) {
            const auto& r = results[k];
            std::cout << std::left << std::setw(30) << "Execution Time (ms)"
                      << std::right << std::setw(15) << r.elapsed_ms
                      << std::right << std::setw(15) << r.elapsed_ms << "\n";
            std::cout << std::left << std::setw(30) << "Total CPU Cycles"
                      << std::right << std::setw(15) << r.total_cycles
                      << std::right << std::setw(15) << r.total_cycles << "\n";
            std::cout << std::left << std::setw(30) << "Cycles / Iteration"
                      << std::right << std::setw(15) << r.cycles_per_iter
                      << std::right << std::setw(15) << r.cycles_per_iter << "\n";
            std::cout << std::left << std::setw(30) << "Compute (GFLOPS)"
                      << std::right << std::setw(15) << r.gflops
                      << std::right << std::setw(15) << r.gflops << "\n";
            std::cout << std::left << std::setw(30) << "Bandwidth (GB/s)"
                      << std::right << std::setw(15) << r.bandwidth_gbps
                      << std::right << std::setw(15) << r.bandwidth_gbps << "\n";
            std::cout << std::left << std::setw(30) << "Ops / Cycle"
                      << std::right << std::setw(15) << r.ops_per_cycle
                      << std::right << std::setw(15) << r.ops_per_cycle << "\n";
            std::cout << "---------------------------------------------------------\n";
        }

        std::cout << "=========================================================\n";
        std::cout << "  Benchmark Complete\n";
        std::cout << "=========================================================\n\n";

        FreeBuffers();
    }
};

// ============================================================================
// Main entry point
// ============================================================================
int main(int argc, char* argv[]) {
    try {
        BenchmarkConfig cfg;

        // Parse command line arguments
        for (int i = 1; i < argc; ++i) {
            if (strcmp(argv[i], "--gguf") == 0 && i + 1 < argc) {
                cfg.use_gguf = true;
                cfg.gguf_path = argv[++i];
            } else if (strcmp(argv[i], "--tensor") == 0 && i + 1 < argc) {
                cfg.tensor_name = argv[++i];
            } else if (strcmp(argv[i], "--rows") == 0 && i + 1 < argc) {
                cfg.rows = static_cast<size_t>(atol(argv[++i]));
            } else if (strcmp(argv[i], "--cols") == 0 && i + 1 < argc) {
                cfg.cols = static_cast<size_t>(atol(argv[++i]));
            } else if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
                cfg.iterations = static_cast<uint32_t>(atoi(argv[++i]));
            } else if (strcmp(argv[i], "--int2") == 0) {
                cfg.precision = QuantPrecision::INT2;
            } else if (strcmp(argv[i], "--int4") == 0) {
                cfg.precision = QuantPrecision::INT4;
            } else if (strcmp(argv[i], "--help") == 0) {
                std::cout << "Usage: sme2_benchmark [options]\n";
                std::cout << "  --gguf <path>   Load weights from GGUF model\n";
                std::cout << "  --tensor <name> Tensor name in GGUF (default: output.weight)\n";
                std::cout << "  --rows <N>      Matrix rows (default: 4096)\n";
                std::cout << "  --cols <N>      Matrix cols (default: 4096)\n";
                std::cout << "  --iters <N>     Benchmark iterations (default: 500)\n";
                std::cout << "  --int2          Use INT2 precision\n";
                std::cout << "  --int4          Use INT4 precision (default)\n";
                return 0;
            }
        }

        SME2BenchmarkHarness harness;
        harness.Configure(cfg);
        harness.Run();

    } catch (const std::exception& ex) {
        std::cerr << "Benchmark Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
