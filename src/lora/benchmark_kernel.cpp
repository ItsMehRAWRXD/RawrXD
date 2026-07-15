// Standalone LoRA Kernel Micro-Benchmark
// Phase 20: Optimization Validation
// ============================================================================
// This benchmark validates the optimized LoRA kernel performance
// without requiring the full RawrXD build system.
//
// Build: ml64.exe /c ApplyLoRA_Optimized.asm && cl.exe /O2 /arch:AVX2 benchmark_kernel.cpp ApplyLoRA_Optimized.obj
//
// Target: < 10ms for rank=8, hidden_dim=768
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cmath>
#include <intrin.h>
#include <vector>
#include <chrono>
#include <algorithm>
#include <numeric>

// Align to 64 bytes for AVX-512 compatibility
#define ALIGN64 __declspec(align(64))

// LoRA Beacon State (matches MASM structure)
struct LoRABeaconState {
    uint32_t version;           // 0
    uint32_t status;            // 4
    uint32_t rank;              // 8
    uint32_t hidden_dim;        // 12
    float* ptr_A;               // 16
    float* ptr_B;               // 24
    float scale_factor;         // 32
    float _padding;             // 36
    LoRABeaconState* next_adapter; // 40
    float composite_weight;     // 48
    uint8_t _padding2[12];      // 52-64
};

static_assert(sizeof(LoRABeaconState) == 64, "LoRABeaconState must be 64 bytes");

// External MASM functions
extern "C" {
    int ApplyLoRA_Optimized(
        const float* base_output,
        const float* input,
        float* result,
        const LoRABeaconState* beacon,
        uint64_t token_count
    );
    
    int ApplyLoRA_Chain_Optimized(
        const float* base_output,
        const float* input,
        float* result,
        const LoRABeaconState* chain_head,
        uint64_t token_count
    );
}

// High-resolution timer using RDTSC
class RDTSC_Timer {
public:
    void start() {
        start_cycles = __rdtsc();
    }
    
    void stop() {
        stop_cycles = __rdtsc();
    }
    
    uint64_t cycles() const {
        return stop_cycles - start_cycles;
    }
    
    double microseconds(double cpu_ghz = 3.0) const {
        return cycles() / (cpu_ghz * 1000.0);
    }
    
    double milliseconds(double cpu_ghz = 3.0) const {
        return cycles() / (cpu_ghz * 1000000.0);
    }

private:
    uint64_t start_cycles;
    uint64_t stop_cycles;
};

// Initialize matrices with deterministic random values
void initialize_matrices(
    float* A, float* B,
    uint32_t rank, uint32_t hidden_dim,
    uint32_t seed = 42
) {
    // Simple LCG random number generator
    uint64_t state = seed;
    auto rand_float = [&]() -> float {
        state = state * 6364136223846793005ULL + 1;
        return static_cast<float>((state >> 33) & 0x7FFFFF) / 0x7FFFFF;
    };
    
    // Initialize A: rank x hidden_dim
    for (uint32_t r = 0; r < rank; ++r) {
        for (uint32_t h = 0; h < hidden_dim; ++h) {
            A[r * hidden_dim + h] = (rand_float() - 0.5f) * 0.1f;
        }
    }
    
    // Initialize B: hidden_dim x rank
    for (uint32_t h = 0; h < hidden_dim; ++h) {
        for (uint32_t r = 0; r < rank; ++r) {
            B[h * rank + r] = (rand_float() - 0.5f) * 0.1f;
        }
    }
}

// Verify alignment
bool check_alignment(const void* ptr, size_t alignment) {
    return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
}

// Reference CPU implementation for correctness verification
void reference_lora_compute(
    const float* base_output,
    const float* input,
    float* result,
    const float* A,
    const float* B,
    uint32_t rank,
    uint32_t hidden_dim,
    float scale
) {
    // Copy base output
    memcpy(result, base_output, hidden_dim * sizeof(float));
    
    // Compute temp = A * input (rank x 1)
    std::vector<float> temp(rank, 0.0f);
    for (uint32_t r = 0; r < rank; ++r) {
        float sum = 0.0f;
        for (uint32_t h = 0; h < hidden_dim; ++h) {
            sum += A[r * hidden_dim + h] * input[h];
        }
        temp[r] = sum;
    }
    
    // Compute result += scale * B * temp
    for (uint32_t h = 0; h < hidden_dim; ++h) {
        float sum = 0.0f;
        for (uint32_t r = 0; r < rank; ++r) {
            sum += B[h * rank + r] * temp[r];
        }
        result[h] += scale * sum;
    }
}

// Benchmark single adapter
void benchmark_single_adapter(uint32_t rank, uint32_t hidden_dim, uint32_t iterations = 1000) {
    printf("\n=== Benchmark: Single Adapter ===\n");
    printf("Rank: %u, Hidden Dim: %u, Iterations: %u\n", rank, hidden_dim, iterations);
    
    // Allocate aligned memory
    ALIGN64 float* A = (float*)_aligned_malloc(rank * hidden_dim * sizeof(float), 64);
    ALIGN64 float* B = (float*)_aligned_malloc(hidden_dim * rank * sizeof(float), 64);
    ALIGN64 float* input = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    ALIGN64 float* base_output = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    ALIGN64 float* result = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    ALIGN64 float* result_ref = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    
    if (!A || !B || !input || !base_output || !result || !result_ref) {
        printf("ERROR: Memory allocation failed\n");
        return;
    }
    
    // Verify alignment
    printf("Alignment check:\n");
    printf("  A: %s\n", check_alignment(A, 64) ? "OK (64-byte)" : "FAIL");
    printf("  B: %s\n", check_alignment(B, 64) ? "OK (64-byte)" : "FAIL");
    printf("  input: %s\n", check_alignment(input, 64) ? "OK (64-byte)" : "FAIL");
    printf("  result: %s\n", check_alignment(result, 64) ? "OK (64-byte)" : "FAIL");
    
    // Initialize data
    initialize_matrices(A, B, rank, hidden_dim, 42);
    for (uint32_t i = 0; i < hidden_dim; ++i) {
        input[i] = static_cast<float>(i) * 0.01f;
        base_output[i] = static_cast<float>(i) * 0.5f;
    }
    
    // Setup beacon
    LoRABeaconState beacon = {};
    beacon.version = 1;
    beacon.status = 1;  // Active
    beacon.rank = rank;
    beacon.hidden_dim = hidden_dim;
    beacon.ptr_A = A;
    beacon.ptr_B = B;
    beacon.scale_factor = 1.0f;
    beacon.next_adapter = nullptr;
    
    // Warmup
    printf("\nWarming up...\n");
    for (uint32_t i = 0; i < 100; ++i) {
        ApplyLoRA_Optimized(base_output, input, result, &beacon, 1);
    }
    
    // Benchmark
    printf("Running benchmark...\n");
    RDTSC_Timer timer;
    std::vector<uint64_t> cycle_counts;
    cycle_counts.reserve(iterations);
    
    for (uint32_t i = 0; i < iterations; ++i) {
        timer.start();
        ApplyLoRA_Optimized(base_output, input, result, &beacon, 1);
        timer.stop();
        cycle_counts.push_back(timer.cycles());
    }
    
    // Calculate statistics
    uint64_t min_cycles = *std::min_element(cycle_counts.begin(), cycle_counts.end());
    uint64_t max_cycles = *std::max_element(cycle_counts.begin(), cycle_counts.end());
    uint64_t total_cycles = 0;
    for (auto c : cycle_counts) total_cycles += c;
    double avg_cycles = static_cast<double>(total_cycles) / iterations;
    
    // Calculate P95
    std::sort(cycle_counts.begin(), cycle_counts.end());
    size_t p95_idx = static_cast<size_t>(iterations * 0.95);
    uint64_t p95_cycles = cycle_counts[p95_idx];
    
    // Assume 3.0 GHz CPU for time conversion
    double cpu_ghz = 3.0;
    double avg_ms = avg_cycles / (cpu_ghz * 1000000.0);
    double p95_ms = p95_cycles / (cpu_ghz * 1000000.0);
    double min_ms = min_cycles / (cpu_ghz * 1000000.0);
    
    printf("\nResults:\n");
    printf("  Average: %.2f cycles (%.3f ms)\n", avg_cycles, avg_ms);
    printf("  P95:     %llu cycles (%.3f ms)\n", p95_cycles, p95_ms);
    printf("  Min:     %llu cycles (%.3f ms)\n", min_cycles, min_ms);
    printf("  Max:     %llu cycles\n", max_cycles);
    
    // Verify correctness
    printf("\nVerifying correctness...\n");
    reference_lora_compute(base_output, input, result_ref, A, B, rank, hidden_dim, 1.0f);
    
    float max_error = 0.0f;
    for (uint32_t i = 0; i < hidden_dim; ++i) {
        float error = std::abs(result[i] - result_ref[i]);
        if (error > max_error) max_error = error;
    }
    printf("  Max error vs reference: %e\n", max_error);
    printf("  Correctness: %s\n", max_error < 1e-4f ? "PASS" : "FAIL");
    
    // Check budget
    printf("\nPerformance Budget:\n");
    printf("  Target: 10.0 ms\n");
    printf("  P95:    %.3f ms\n", p95_ms);
    printf("  Status: %s\n", p95_ms < 10.0 ? "PASS ✓" : "FAIL ✗");
    
    // Cleanup
    _aligned_free(A);
    _aligned_free(B);
    _aligned_free(input);
    _aligned_free(base_output);
    _aligned_free(result);
    _aligned_free(result_ref);
}

// Benchmark chain of adapters
void benchmark_adapter_chain(uint32_t rank, uint32_t hidden_dim, 
                                uint32_t chain_length, uint32_t iterations = 100) {
    printf("\n=== Benchmark: Adapter Chain ===\n");
    printf("Rank: %u, Hidden Dim: %u, Chain Length: %u, Iterations: %u\n", 
           rank, hidden_dim, chain_length, iterations);
    
    // Allocate memory for chain
    std::vector<ALIGN64 float*> A_buffers(chain_length);
    std::vector<ALIGN64 float*> B_buffers(chain_length);
    std::vector<LoRABeaconState> beacons(chain_length);
    
    for (uint32_t i = 0; i < chain_length; ++i) {
        A_buffers[i] = (float*)_aligned_malloc(rank * hidden_dim * sizeof(float), 64);
        B_buffers[i] = (float*)_aligned_malloc(hidden_dim * rank * sizeof(float), 64);
        initialize_matrices(A_buffers[i], B_buffers[i], rank, hidden_dim, 42 + i);
        
        beacons[i].version = 1;
        beacons[i].status = 1;
        beacons[i].rank = rank;
        beacons[i].hidden_dim = hidden_dim;
        beacons[i].ptr_A = A_buffers[i];
        beacons[i].ptr_B = B_buffers[i];
        beacons[i].scale_factor = 1.0f / chain_length;  // Normalize
        beacons[i].next_adapter = (i + 1 < chain_length) ? &beacons[i + 1] : nullptr;
    }
    
    ALIGN64 float* input = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    ALIGN64 float* base_output = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    ALIGN64 float* result = (float*)_aligned_malloc(hidden_dim * sizeof(float), 64);
    
    for (uint32_t i = 0; i < hidden_dim; ++i) {
        input[i] = static_cast<float>(i) * 0.01f;
        base_output[i] = static_cast<float>(i) * 0.5f;
    }
    
    // Warmup
    printf("\nWarming up...\n");
    for (uint32_t i = 0; i < 10; ++i) {
        ApplyLoRA_Chain_Optimized(base_output, input, result, &beacons[0], 1);
    }
    
    // Benchmark
    printf("Running benchmark...\n");
    RDTSC_Timer timer;
    std::vector<uint64_t> cycle_counts;
    cycle_counts.reserve(iterations);
    
    for (uint32_t i = 0; i < iterations; ++i) {
        timer.start();
        ApplyLoRA_Chain_Optimized(base_output, input, result, &beacons[0], 1);
        timer.stop();
        cycle_counts.push_back(timer.cycles());
    }
    
    // Statistics
    std::sort(cycle_counts.begin(), cycle_counts.end());
    uint64_t p95_cycles = cycle_counts[static_cast<size_t>(iterations * 0.95)];
    double avg_cycles = std::accumulate(cycle_counts.begin(), cycle_counts.end(), 0ULL) / 
                        static_cast<double>(iterations);
    
    double cpu_ghz = 3.0;
    double p95_ms = p95_cycles / (cpu_ghz * 1000000.0);
    double avg_ms = avg_cycles / (cpu_ghz * 1000000.0);
    
    printf("\nResults:\n");
    printf("  Average: %.3f ms\n", avg_ms);
    printf("  P95:     %.3f ms\n", p95_ms);
    printf("  Per-adapter overhead: %.3f ms\n", avg_ms / chain_length);
    
    // Budget check
    printf("\nPerformance Budget:\n");
    printf("  Target: 10.0 ms\n");
    printf("  P95:    %.3f ms\n", p95_ms);
    printf("  Status: %s\n", p95_ms < 10.0 ? "PASS ✓" : "FAIL ✗");
    
    // Cleanup
    for (uint32_t i = 0; i < chain_length; ++i) {
        _aligned_free(A_buffers[i]);
        _aligned_free(B_buffers[i]);
    }
    _aligned_free(input);
    _aligned_free(base_output);
    _aligned_free(result);
}

int main(int argc, char* argv[]) {
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║     RawrXD Phase 20: LoRA Kernel Micro-Benchmark                 ║\n");
    printf("║     Standalone Performance Validation                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
    
    // Check CPU features
    printf("\nCPU Feature Check:\n");
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    bool has_avx = (cpu_info[2] & (1 << 28)) != 0;
    bool has_avx2 = false;
    
    __cpuidex(cpu_info, 7, 0);
    has_avx2 = (cpu_info[1] & (1 << 5)) != 0;
    
    printf("  AVX:  %s\n", has_avx ? "Supported" : "Not supported");
    printf("  AVX2: %s\n", has_avx2 ? "Supported" : "Not supported");
    
    if (!has_avx2) {
        printf("\nWARNING: AVX2 not detected. Performance may be degraded.\n");
    }
    
    // Parse arguments
    uint32_t rank = 8;
    uint32_t hidden_dim = 768;
    uint32_t iterations = 1000;
    
    if (argc > 1) rank = atoi(argv[1]);
    if (argc > 2) hidden_dim = atoi(argv[2]);
    if (argc > 3) iterations = atoi(argv[3]);
    
    // Run benchmarks
    benchmark_single_adapter(rank, hidden_dim, iterations);
    benchmark_adapter_chain(rank, hidden_dim, 2, iterations / 10);
    benchmark_adapter_chain(rank, hidden_dim, 4, iterations / 10);
    
    printf("\n═══════════════════════════════════════════════════════════════════\n");
    printf("Benchmark complete.\n");
    printf("═══════════════════════════════════════════════════════════════════\n");
    
    return 0;
}
