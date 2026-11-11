// ============================================================================
// moe_test.cpp - Real MoE inference test
//
// Two modes:
//   1. moe_test.exe <path-to-gguf>     - load a real model, exercise it
//   2. moe_test.exe --bench            - synthetic Q4K kernel benchmark
// ============================================================================

#include "MoEWeightsLoader.hpp"
#include "MoEWeightProxy.hpp"
#include "ThreadPool.h"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <random>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
    #include <psapi.h>
    #pragma comment(lib, "psapi.lib")
#endif

// Real MASM kernel - row-major
extern "C" void Sovereign_Q4K_GEMV_AVX2(
    const void* q4_weights,
    const float* input,
    float* output,
    unsigned int num_blocks,
    unsigned int rows);

// Real MASM kernel - column-strided
extern "C" void Sovereign_Q4K_GEMV_AVX2_T(
    const void* q4_weights,
    const float* input,
    float* output,
    unsigned int num_blocks,
    unsigned int rows,
    unsigned int row_stride_bytes);

// F16 -> F32 conversion (IEEE 754 half)
static inline float F16ToF32(uint16_t h) {
    uint32_t sign = (uint32_t)(h >> 15) & 1;
    uint32_t exp  = (uint32_t)(h >> 10) & 0x1F;
    uint32_t mant = (uint32_t)(h) & 0x3FF;
    uint32_t f;
    if (exp == 0) {
        if (mant == 0) {
            f = sign << 31;
        } else {
            // Subnormal
            int e = -1;
            do { e++; mant <<= 1; } while ((mant & 0x400) == 0);
            mant &= 0x3FF;
            f = (sign << 31) | ((uint32_t)(127 - 15 - e) << 23) | (mant << 13);
        }
    } else if (exp == 31) {
        f = (sign << 31) | (0xFF << 23) | (mant << 13);
    } else {
        f = (sign << 31) | ((exp + 127 - 15) << 23) | (mant << 13);
    }
    union { uint32_t u; float fl; } cv; cv.u = f;
    return cv.fl;
}

// F16 GEMV: output[rows] = weights[rows x cols] @ input[cols]
// weights is row-major F16, input is F32, output is F32
static void F16_GEMV(const uint16_t* weights, const float* input,
                      float* output, int rows, int cols) {
    for (int r = 0; r < rows; ++r) {
        const uint16_t* row = weights + (size_t)r * cols;
        float sum = 0.0f;
        for (int c = 0; c < cols; ++c) {
            sum += F16ToF32(row[c]) * input[c];
        }
        output[r] = sum;
    }
}

// F32 GEMV: output[rows] = weights[rows x cols] @ input[cols]
static void F32_GEMV(const float* weights, const float* input,
                      float* output, int rows, int cols) {
    for (int r = 0; r < rows; ++r) {
        const float* row = weights + (size_t)r * cols;
        float sum = 0.0f;
        for (int c = 0; c < cols; ++c) {
            sum += row[c] * input[c];
        }
        output[r] = sum;
    }
}

static size_t GetFileSizeLocal(const char* path) {
#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (GetFileAttributesExA(path, GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER li;
        li.LowPart = fad.nFileSizeLow;
        li.HighPart = fad.nFileSizeHigh;
        return (size_t)li.QuadPart;
    }
    return 0;
#else
    FILE* f = fopen(path, "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fclose(f);
    return pos > 0 ? (size_t)pos : 0;
#endif
}

static size_t GetPeakMemoryMB() {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
        return pmc.PeakWorkingSetSize / (1024 * 1024);
    }
#endif
    return 0;
}

// ============================================================================
// Synthetic Q4_K generation - real Q4K blocks
// ============================================================================
struct alignas(32) SyntheticQ4K {
    uint16_t scales[32];
    uint16_t mins[32];
    uint8_t  weights[128];
};

static void FillSyntheticQ4K(std::vector<SyntheticQ4K>& buf, size_t blocksTotal, std::mt19937& gen) {
    buf.resize(blocksTotal);
    for (size_t b = 0; b < blocksTotal; ++b) {
        SyntheticQ4K& block = buf[b];
        for (int i = 0; i < 32; ++i) {
            union { float f; uint32_t u; } sv; sv.f = (gen() & 0xFF) / 4096.0f + 0.001f;
            union { float f; uint32_t u; } mv; mv.f = ((gen() & 0xFF) - 128) / 256.0f;
            block.scales[i] = (uint16_t)(sv.u >> 16);
            block.mins[i]   = (uint16_t)(mv.u >> 16);
            for (int j = 0; j < 4; ++j) {
                uint8_t q0 = (uint8_t)(gen() & 0xF);
                uint8_t q1 = (uint8_t)(gen() & 0xF);
                block.weights[i*4 + j] = q0 | (q1 << 4);
            }
        }
    }
}

static int RunKernelBenchmark(int iters) {
    printf("=== Synthetic Q4K Kernel Benchmark ===\n");
    printf("Iterations: %d\n\n", iters);

    std::mt19937 gen(42);
    const size_t hidden = 4096;
    const size_t expertDim = 4096;

    std::vector<float> input(hidden);
    std::vector<float> output(expertDim);
    std::normal_distribution<float> d(0.0f, 1.0f);
    for (auto& x : input) x = d(gen);

    size_t numBlocks = expertDim / 256;
    size_t blockCount = hidden * numBlocks;
    std::vector<SyntheticQ4K> gate;
    FillSyntheticQ4K(gate, blockCount, gen);
    size_t gateBytes = blockCount * sizeof(SyntheticQ4K);

    size_t numBlocksD = hidden / 256;
    std::vector<SyntheticQ4K> down;
    FillSyntheticQ4K(down, expertDim * numBlocksD, gen);
    size_t downBytes = down.size() * sizeof(SyntheticQ4K);

    printf("Gate: %zu rows x %zu cols, %.2f MB Q4K\n",
           hidden, expertDim, (double)gateBytes / (1024.0 * 1024.0));
    printf("Down: %zu rows x %zu cols, %.2f MB Q4K\n",
           expertDim, hidden, (double)downBytes / (1024.0 * 1024.0));
    printf("Total: %.2f MB\n\n", (double)(gateBytes + downBytes) / (1024.0 * 1024.0));

    // Warmup
    for (int i = 0; i < 5; ++i) {
        Sovereign_Q4K_GEMV_AVX2(gate.data(), input.data(), output.data(),
                                 (unsigned int)numBlocks, (unsigned int)hidden);
    }

    // Benchmark: pure kernel calls
    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        Sovereign_Q4K_GEMV_AVX2(gate.data(), input.data(), output.data(),
                                 (unsigned int)numBlocks, (unsigned int)hidden);
    }
    auto t1 = std::chrono::high_resolution_clock::now();
    double ms = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() / 1e6;
    double gateMs = ms / iters;
    double gateGFLOP = (2.0 * hidden * expertDim) / 1e9;
    double gateTFLOPs = gateGFLOP / (gateMs / 1000.0);
    double gateGBps = (gateBytes / 1e9) / (gateMs / 1000.0);
    printf("Gate GEMV:  %.3f ms/call | %.2f TFLOPS | %.2f GB/s\n", gateMs, gateTFLOPs, gateGBps);

    t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        Sovereign_Q4K_GEMV_AVX2(down.data(), output.data(), input.data(),
                                 (unsigned int)numBlocksD, (unsigned int)expertDim);
    }
    t1 = std::chrono::high_resolution_clock::now();
    double downMs = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count() / 1e6 / iters;
    double downTFLOPs = (2.0 * hidden * expertDim / 1e9) / (downMs / 1000.0);
    double downGBps = (downBytes / 1e9) / (downMs / 1000.0);
    printf("Down GEMV:  %.3f ms/call | %.2f TFLOPS | %.2f GB/s\n", downMs, downTFLOPs, downGBps);

    // Full expert pass: gate + SwiGLU + down
    std::vector<float> swiglu(expertDim);
    auto t2 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iters; ++i) {
        Sovereign_Q4K_GEMV_AVX2(gate.data(), input.data(), output.data(),
                                 (unsigned int)numBlocks, (unsigned int)hidden);
        for (size_t e = 0; e < expertDim; ++e) {
            float g = output[e];
            float silu = g / (1.0f + std::exp(-g));
            swiglu[e] = silu * g;
        }
        Sovereign_Q4K_GEMV_AVX2(down.data(), swiglu.data(), output.data(),
                                 (unsigned int)numBlocksD, (unsigned int)expertDim);
    }
    auto t3 = std::chrono::high_resolution_clock::now();
    double expertMs = std::chrono::duration_cast<std::chrono::nanoseconds>(t3 - t2).count() / 1e6 / iters;
    double expertOps = 4.0 * hidden * expertDim;
    double expertTFLOPs = (expertOps / 1e12) / (expertMs / 1000.0);
    printf("\nFull expert pass: %.3f ms | %.2f TFLOPS\n", expertMs, expertTFLOPs);
    printf("Experts/sec @ top-1: %.0f\n", 1000.0 / expertMs);
    printf("Experts/sec @ top-4: %.0f\n", 250.0 / expertMs);
    printf("Tokens/sec @ top-4 single layer: %.0f\n", 1000.0 / (4.0 * expertMs));
    printf("Tokens/sec @ top-4 24 layers:     %.0f\n", 1000.0 / (24.0 * 4.0 * expertMs));

    return 0;
}

static int RunModelPath(const char* modelPath, int numTokens, int cacheMB, int topK) {
    size_t fileSize = GetFileSizeLocal(modelPath);
    if (fileSize == 0) {
        printf("Cannot open: %s\n", modelPath);
        return 1;
    }

    printf("File: %s (%.2f GB)\n", modelPath, (double)fileSize / (1024.0 * 1024.0 * 1024.0));
    printf("Tokens: %d, Cache: %d MB, TopK: %d\n", numTokens, cacheMB, topK);
    printf("Peak memory before: %zu MB\n\n", GetPeakMemoryMB());

    auto totalStart = std::chrono::high_resolution_clock::now();

    Deep2::MoEWeightsLoader loader;
    if (!loader.Open(modelPath)) {
        printf("Failed to open GGUF file\n");
        return 1;
    }
    loader.SetMaxCacheSize((size_t)cacheMB * 1024ULL * 1024ULL);

    Deep2::MoEWeightProxy proxy;
    proxy.Attach(&loader);

    const auto& projections = loader.GetExpertProjections();
    if (projections.empty()) {
        printf("No MoE expert tensors found in this file.\n");
        loader.Close();
        return 0;
    }

    size_t numLayers  = loader.GetNumExpertLayers();
    size_t numExperts = loader.GetExpertsPerLayer();
    if (numExperts == 0) numExperts = 256;
    if (numLayers == 0) numLayers = 1;
    if (topK > (int)numExperts) topK = (int)numExperts;
    if (topK < 1) topK = 1;

    int hidden = 0, expertDim = 0;
    Deep2::GGMLType expertType = Deep2::GGMLType::GGML_TYPE_F32;
    bool hasGate = false;
    bool isQ4K = false;
    bool isF16 = false;
    bool isF32 = false;

    // Look for ffn_gate_exps (SwiGLU) or ffn_up_exps (ReLU²)
    // GGUF dims are [hidden, expertDim, numExperts] (reverse of PyTorch)
    for (const auto& t : loader.GetAllTensors()) {
        if (t.name.find("ffn_gate_exps.weight") != std::string::npos) {
            hasGate = true;
            if (t.dimensions.size() >= 3) {
                hidden = (int)t.dimensions[0];
                expertDim = (int)t.dimensions[1];
            } else if (t.dimensions.size() == 2) {
                hidden = (int)t.dimensions[0];
                expertDim = (int)t.dimensions[1];
            }
            expertType = t.type;
            printf("Gate expert: %s dims=[", t.name.c_str());
            for (auto d : t.dimensions) printf("%llu,", (unsigned long long)d);
            printf("] type=%u\n", (unsigned int)t.type);
            break;
        }
    }
    if (!hasGate) {
        for (const auto& t : loader.GetAllTensors()) {
            if (t.name.find("ffn_up_exps.weight") != std::string::npos) {
                if (t.dimensions.size() >= 3) {
                    hidden = (int)t.dimensions[0];
                    expertDim = (int)t.dimensions[1];
                } else if (t.dimensions.size() == 2) {
                    hidden = (int)t.dimensions[0];
                    expertDim = (int)t.dimensions[1];
                }
                expertType = t.type;
                printf("Up expert (ReLU2): %s dims=[", t.name.c_str());
                for (auto d : t.dimensions) printf("%llu,", (unsigned long long)d);
                printf("] type=%u\n", (unsigned int)t.type);
                break;
            }
        }
    }
    if (hidden == 0 || expertDim == 0) {
        printf("Could not derive hidden/expert dim\n");
        loader.Close();
        return 1;
    }

    int wt = (int)expertType;
    if (wt == 12) isQ4K = true;
    else if (wt == 1) isF16 = true;
    else if (wt == 0) isF32 = true;
    else if (wt == 6) isF16 = true;  // F16
    else if (wt == 8) isF16 = true;  // F16 variant
    else {
        printf("Unsupported quantization type=%u (need Q4K=12, F16=1/6, F32=0)\n", wt);
        loader.Close();
        return 1;
    }

    printf("Architecture: %s\n", loader.GetArchitecture().c_str());
    printf("FFN type: %s\n", hasGate ? "SwiGLU (gate*up)" : "ReLU2 (up->relu2->down)");
    printf("Quant: %s (type=%d)\n", isQ4K ? "Q4_K" : isF16 ? "F16" : "F32", wt);
    printf("Layers: %zu, Experts/Layer: %zu, Hidden: %d, ExpertDim: %d\n\n",
           numLayers, numExperts, hidden, expertDim);

    const int gateBlocks = (expertDim + 255) / 256;
    const int downBlocks = (hidden + 255) / 256;

    // For F16/F32: per-expert byte sizes
    // ffn_up_exps: [numExperts, hidden, expertDim] → per-expert = hidden * expertDim * sizeof(f16)
    // ffn_down_exps: [numExperts, expertDim, hidden] → per-expert = expertDim * hidden * sizeof(f16)
    const size_t f16ElemSize = isF16 ? 2 : 4;
    const size_t upBytesPerExpert = (size_t)hidden * expertDim * f16ElemSize;
    const size_t downBytesPerExpert = (size_t)expertDim * hidden * f16ElemSize;
    const size_t gateBytesPerExpert = hasGate ? upBytesPerExpert : 0;

    std::mt19937 gen(0xDEADBEEF);
    std::uniform_int_distribution<int> expertPick(0, (int)numExperts - 1);

    std::vector<float> hiddenState(hidden);
    std::vector<float> gateOut(expertDim);
    std::vector<float> upOut(expertDim);
    std::vector<float> actOut(expertDim);
    std::vector<float> expertOut(hidden);
    std::vector<float> nextHidden(hidden);

    // Find the first layer that actually has MoE experts
    int firstMoELayer = -1;
    for (const auto& p : projections) {
        if (p.expertIdx == -1 && p.layerIdx >= 0) {
            firstMoELayer = p.layerIdx;
            break;
        }
    }
    if (firstMoELayer < 0) {
        printf("No stacked expert tensors found (only shared/router)\n");
        loader.Close();
        return 1;
    }
    printf("First MoE layer: %d\n", firstMoELayer);

    auto warmupStart = std::chrono::high_resolution_clock::now();
    for (int e = 0; e < topK; ++e) {
        int pick = expertPick(gen);
        fprintf(stderr, "Warmup: acquiring layer %d expert %d\n", firstMoELayer, pick);
        Deep2::MoEWeightHandle h = proxy.Acquire(firstMoELayer, pick);
        fprintf(stderr, "  valid=%d gate=%p up=%p down=%p bytes=%zu\n",
                h.valid, h.gateWeights, h.upWeights, h.downWeights, h.expertBytes);
        (void)h;
    }
    auto warmupEnd = std::chrono::high_resolution_clock::now();
    double warmupMs = std::chrono::duration_cast<std::chrono::microseconds>(warmupEnd - warmupStart).count() / 1000.0;

    auto inferStart = std::chrono::high_resolution_clock::now();
    int tokensDone = 0;
    int layersPerToken = (int)std::min<size_t>(numLayers, 4);

    for (int t = 0; t < numTokens; ++t) {
        std::normal_distribution<float> nd(0.0f, 0.02f);
        for (auto& x : hiddenState) x = nd(gen);

        for (int li = 0; li < layersPerToken; ++li) {
            int layer = firstMoELayer + li;
            std::fill(expertOut.begin(), expertOut.end(), 0.0f);

            for (int k = 0; k < topK; ++k) {
                Deep2::MoEWeightHandle h = proxy.Acquire(layer, expertPick(gen));
                if (!h.valid) continue;

                if (isQ4K) {
                    // Q4_K path: use MASM kernel
                    if (hasGate) {
                        // SwiGLU: gate * silu(up)
                        Sovereign_Q4K_GEMV_AVX2(h.gateWeights, hiddenState.data(),
                                                 gateOut.data(),
                                                 (unsigned int)gateBlocks,
                                                 (unsigned int)hidden);
                        Sovereign_Q4K_GEMV_AVX2(h.upWeights, hiddenState.data(),
                                                 upOut.data(),
                                                 (unsigned int)gateBlocks,
                                                 (unsigned int)hidden);
                        for (int e = 0; e < expertDim; ++e) {
                            float g = gateOut[e];
                            float silu = g / (1.0f + std::exp(-g));
                            actOut[e] = silu * upOut[e];
                        }
                    } else {
                        // ReLU²: up -> relu²
                        Sovereign_Q4K_GEMV_AVX2(h.gateWeights, hiddenState.data(),
                                                 upOut.data(),
                                                 (unsigned int)gateBlocks,
                                                 (unsigned int)hidden);
                        for (int e = 0; e < expertDim; ++e) {
                            float r = upOut[e];
                            actOut[e] = r * r * (r > 0.0f ? 1.0f : 0.0f);
                        }
                    }
                    Sovereign_Q4K_GEMV_AVX2(h.downWeights, actOut.data(),
                                             expertOut.data(),
                                             (unsigned int)downBlocks,
                                             (unsigned int)hidden);
                } else if (isF16 || isF32) {
                    // F16/F32 path: use C++ GEMV
                    const uint8_t* expertBuf = (const uint8_t*)h.gateWeights;
                    if (hasGate) {
                        // SwiGLU: gate * silu(up)
                        if (isF16) {
                            F16_GEMV((const uint16_t*)expertBuf, hiddenState.data(),
                                      gateOut.data(), expertDim, hidden);
                            F16_GEMV((const uint16_t*)(expertBuf + gateBytesPerExpert),
                                      hiddenState.data(), upOut.data(), expertDim, hidden);
                        } else {
                            F32_GEMV((const float*)expertBuf, hiddenState.data(),
                                      gateOut.data(), expertDim, hidden);
                            F32_GEMV((const float*)(expertBuf + gateBytesPerExpert),
                                      hiddenState.data(), upOut.data(), expertDim, hidden);
                        }
                        for (int e = 0; e < expertDim; ++e) {
                            float g = gateOut[e];
                            float silu = g / (1.0f + std::exp(-g));
                            actOut[e] = silu * upOut[e];
                        }
                    } else {
                        // ReLU²: up -> relu²
                        if (isF16) {
                            F16_GEMV((const uint16_t*)expertBuf, hiddenState.data(),
                                      upOut.data(), expertDim, hidden);
                        } else {
                            F32_GEMV((const float*)expertBuf, hiddenState.data(),
                                      upOut.data(), expertDim, hidden);
                        }
                        for (int e = 0; e < expertDim; ++e) {
                            float r = upOut[e];
                            actOut[e] = r * r * (r > 0.0f ? 1.0f : 0.0f);
                        }
                    }
                    // Down projection
                    const void* downPtr = (const uint8_t*)h.gateWeights +
                        (hasGate ? gateBytesPerExpert + upBytesPerExpert : upBytesPerExpert);
                    if (isF16) {
                        F16_GEMV((const uint16_t*)downPtr, actOut.data(),
                                  expertOut.data(), hidden, expertDim);
                    } else {
                        F32_GEMV((const float*)downPtr, actOut.data(),
                                  expertOut.data(), hidden, expertDim);
                    }
                }
            }

            for (int hh = 0; hh < hidden; ++hh) {
                nextHidden[hh] = hiddenState[hh] + expertOut[hh];
            }
            hiddenState.swap(nextHidden);
        }
        tokensDone++;
    }

    auto inferEnd = std::chrono::high_resolution_clock::now();
    double inferMs = std::chrono::duration_cast<std::chrono::microseconds>(inferEnd - inferStart).count() / 1000.0;

    auto stats = loader.GetStats();
    auto totalEnd = std::chrono::high_resolution_clock::now();
    double totalMs = std::chrono::duration_cast<std::chrono::microseconds>(totalEnd - totalStart).count() / 1000.0;

    printf("\n--- Results ---\n");
    printf("Tokens generated:  %d\n", tokensDone);
    printf("Layers/token:      %d (of %zu)\n", layersPerToken, numLayers);
    printf("Experts/token:     %d (top-K)\n", topK);
    printf("Bytes streamed:    %.2f MB\n", (double)stats.bytesStreamed / (1024.0 * 1024.0));
    printf("Cache hits:        %llu / %llu\n",
           (unsigned long long)stats.cacheHits, (unsigned long long)stats.totalLoads);
    printf("Warmup time:       %.2f ms\n", warmupMs);
    printf("Inference time:    %.2f ms\n", inferMs);
    printf("Tokens/second:     %.2f\n", tokensDone / (inferMs / 1000.0));
    printf("Peak memory:       %zu MB\n", GetPeakMemoryMB());
    printf("Total time:        %.2f ms\n", totalMs);

    loader.Close();
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  %s <path-to-gguf> [num-tokens] [cache-mb] [top-k]\n", argv[0]);
        printf("  %s --bench [iters]\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "--bench") == 0) {
        int iters = argc > 2 ? atoi(argv[2]) : 200;
        return RunKernelBenchmark(iters);
    }
    int numTokens = argc > 2 ? atoi(argv[2]) : 100;
    int cacheMB = argc > 3 ? atoi(argv[3]) : 4096;
    int topK = argc > 4 ? atoi(argv[4]) : 4;
    return RunModelPath(argv[1], numTokens, cacheMB, topK);
}
