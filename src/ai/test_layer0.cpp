// test_layer0.cpp
// Sovereign Phase 2 Smoke Test: Load ministral3_q4_0.gguf, execute one GEMV
// No llama.cpp, no snmalloc — just arena + kernel + GGUF parser
//
// Build via CMake:
//   ninja test_sovereign_layer0
//   .\bin\test_sovereign_layer0.exe

#include "streaming_gguf_loader.h"
#include "SovereignLayerExecutor.h"
#include "rawr_linear_allocator.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <math.h>
#include <windows.h>
#include <algorithm>
#include <vector>

using namespace RawrXD;

// ------------------------------------------------------------------------------
// Minimal aligned allocator for activation buffers
// ------------------------------------------------------------------------------
static float* aligned_alloc_f32(size_t count, size_t alignment) {
    void* ptr = _aligned_malloc(count * sizeof(float), alignment);
    if (!ptr) {
        fprintf(stderr, "FATAL: _aligned_malloc failed for %zu floats align=%zu\n", count, alignment);
        ExitProcess(1);
    }
    memset(ptr, 0, count * sizeof(float));
    return (float*)ptr;
}

// ------------------------------------------------------------------------------
// Fill vector with deterministic dummy data (sinusoidal pattern)
// ------------------------------------------------------------------------------
static void fill_dummy_input(float* vec, int n) {
    for (int i = 0; i < n; ++i) {
        vec[i] = (float)sin(i * 0.1) * 0.1f;
    }
}

// ------------------------------------------------------------------------------
// Print first N values of a float vector
// ------------------------------------------------------------------------------
static void print_vector(const char* label, const float* vec, int n, int max_print = 8) {
    printf("%s: [", label);
    int limit = (n < max_print) ? n : max_print;
    for (int i = 0; i < limit; ++i) {
        printf("%.6f%s", vec[i], (i + 1 < limit) ? ", " : "");
    }
    if (n > max_print) printf(", ... (%d more)", n - max_print);
    printf("]\n");
}

// ------------------------------------------------------------------------------
// Convert FP16 (IEEE 754 binary16 bits) to FP32
// ------------------------------------------------------------------------------
static float fp16_to_fp32(uint16_t h) {
    uint32_t sign = (uint32_t)(h & 0x8000u) << 16;
    uint32_t exp = (h >> 10) & 0x1Fu;
    uint32_t mant = h & 0x03FFu;

    uint32_t fbits;
    if (exp == 0) {
        if (mant == 0) {
            fbits = sign;
        } else {
            int e = -14;
            while ((mant & 0x0400u) == 0) {
                mant <<= 1;
                --e;
            }
            mant &= 0x03FFu;
            uint32_t fexp = (uint32_t)(e + 127);
            fbits = sign | (fexp << 23) | (mant << 13);
        }
    } else if (exp == 0x1Fu) {
        fbits = sign | 0x7F800000u | (mant << 13);
    } else {
        uint32_t fexp = exp + (127u - 15u);
        fbits = sign | (fexp << 23) | (mant << 13);
    }

    float out;
    memcpy(&out, &fbits, sizeof(out));
    return out;
}

// ------------------------------------------------------------------------------
// Scalar Q4_0 row dot-product reference. Layout matches kernel:
// bytes [0..1] = fp16 scale, bytes [2..17] = 16 packed q4 bytes
// elements 0..15 from low nibble, elements 16..31 from high nibble.
// ------------------------------------------------------------------------------
static float q4_0_row_dot_scalar(const uint8_t* row_ptr, const float* input, int n_cols) {
    const int blocks_per_row = n_cols / 32;
    float sum = 0.0f;

    for (int b = 0; b < blocks_per_row; ++b) {
        const uint8_t* block = row_ptr + b * 18;
        uint16_t h;
        memcpy(&h, block, sizeof(h));
        float d = fp16_to_fp32(h);

        const int base = b * 32;
        for (int j = 0; j < 16; ++j) {
            const uint8_t q = block[2 + j];
            const int w_lo = (int)(q & 0x0F) - 8;
            const int w_hi = (int)((q >> 4) & 0x0F) - 8;
            sum += (float)w_lo * d * input[base + j];
            sum += (float)w_hi * d * input[base + 16 + j];
        }
    }

    return sum;
}

// ------------------------------------------------------------------------------
// Main smoke test
// ------------------------------------------------------------------------------
int main(int argc, char** argv) {
    const char* model_path = (argc > 1) ? argv[1] : "D:\\ministral3_q4_0.gguf";
    const int requested_check_rows = (argc > 2) ? std::max(1, atoi(argv[2])) : 64;
    const float requested_abs_tol = (argc > 3) ? (float)atof(argv[3]) : 0.04f;
    const int requested_iterations = (argc > 4) ? std::max(1, atoi(argv[4])) : 10;
    const int requested_check_start_row = (argc > 5) ? std::max(0, atoi(argv[5])) : 0;
    const int requested_check_sweep_count = (argc > 6) ? std::max(1, atoi(argv[6])) : 1;
    const int requested_check_sweep_stride = (argc > 7) ? std::max(0, atoi(argv[7])) : 0;
    printf("=== Sovereign Phase 2 Smoke Test ===\n");
    printf("Model: %s\n", model_path);
    printf("Config: check_rows=%d abs_tol=%.6f iterations=%d check_start_row=%d sweep_count=%d sweep_stride=%d\n",
           requested_check_rows,
           requested_abs_tol,
           requested_iterations,
           requested_check_start_row,
           requested_check_sweep_count,
           requested_check_sweep_stride);

    // 1. Init sovereign allocator (enable large pages)
    printf("[1/6] Initializing sovereign allocator...\n");
    if (!RawrLinearAlloc_Init(0)) {
        fprintf(stderr, "WARN: RawrLinearAlloc_Init returned 0 (large pages may be unavailable)\n");
    }

    // 2. Open GGUF and parse header/metadata/tensor index
    printf("[2/6] Loading GGUF header...\n");
    StreamingGGUFLoader loader;
    if (!loader.Open(model_path)) {
        fprintf(stderr, "FATAL: Failed to open %s\n", model_path);
        return 1;
    }
    if (!loader.ParseHeader()) {
        fprintf(stderr, "FATAL: ParseHeader failed\n");
        return 1;
    }
    if (!loader.ParseMetadata()) {
        fprintf(stderr, "FATAL: ParseMetadata failed\n");
        return 1;
    }
    if (!loader.BuildTensorIndex()) {
        fprintf(stderr, "FATAL: BuildTensorIndex failed\n");
        return 1;
    }

    auto tensors = loader.GetTensorIndex();
    printf("      Tensors: %zu\n", tensors.size());

    // 3. Find target tensor: blk.0.attn_q.weight (should be Q4_0)
    printf("[3/6] Resolving tensor 'blk.0.attn_q.weight'...\n");
    const TensorRef* tq = nullptr;
    for (const auto& t : tensors) {
        if (t.name == "blk.0.attn_q.weight") {
            tq = &t;
            break;
        }
    }
    if (!tq) {
        fprintf(stderr, "FATAL: Tensor blk.0.attn_q.weight not found\n");
        return 1;
    }
    printf("      Found: type=%u shape=(%llu, %llu) offset=%llu size=%llu\n",
           (unsigned)tq->type,
           tq->shape.size() > 0 ? tq->shape[0] : 0,
           tq->shape.size() > 1 ? tq->shape[1] : 0,
           tq->offset, tq->size);

    // 4. Load tensor bytes directly from file into sovereign-allocated buffer
    printf("[4/6] Loading tensor data into sovereign buffer...\n");
    FILE* fp = fopen(model_path, "rb");
    if (!fp) {
        fprintf(stderr, "FATAL: fopen failed for %s\n", model_path);
        return 1;
    }
    uint64_t data_section_start = 8416768; // From audit script
    uint64_t abs_offset = data_section_start + tq->offset;

    std::vector<uint8_t> tensor_bytes(tq->size);
    fseek(fp, (long)abs_offset, SEEK_SET);
    size_t read = fread(tensor_bytes.data(), 1, tq->size, fp);
    fclose(fp);
    if (read != tq->size) {
        fprintf(stderr, "FATAL: fread returned %zu, expected %llu\n", read, tq->size);
        return 1;
    }

    // 5. Allocate activation buffers (512-byte aligned)
    printf("[5/6] Allocating activation buffers...\n");
    int n_cols = (int)(tq->shape.size() > 0 ? tq->shape[0] : 0); // dot-product length
    int n_rows = (int)(tq->shape.size() > 1 ? tq->shape[1] : 0); // output vector length
    if (n_cols == 0 || n_rows == 0) {
        fprintf(stderr, "FATAL: Invalid tensor shape\n");
        return 1;
    }
    float* input  = aligned_alloc_f32(n_cols, 512);
    float* output = aligned_alloc_f32(n_rows, 512);
    fill_dummy_input(input, n_cols);
    print_vector("Input", input, n_cols);

    // Compute CORRECT Q4_0 size BEFORE allocating buffer
    int blocks_per_row = n_cols / 32;
    int row_stride     = blocks_per_row * 18;
    int expected_size  = row_stride * n_rows;
    printf("      DIAG: n_rows=%d n_cols=%d blocks_per_row=%d row_stride=%d expected_size=%d loader_size=%llu\n",
           n_rows, n_cols, blocks_per_row, row_stride, expected_size, tq->size);

    // Allocate sovereign buffer with CORRECT size (not loader-reported size)
    void* sovereign_buf = RawrLinearAlloc_Alloc(expected_size);
    if (!sovereign_buf) {
        fprintf(stderr, "FATAL: RawrLinearAlloc_Alloc failed\n");
        return 1;
    }
    memcpy(sovereign_buf, tensor_bytes.data(), (size_t)std::min(expected_size, (int)tq->size));
    printf("      Sovereign buffer: %p  Size: %d\n", sovereign_buf, expected_size);

    // 6. Execute one GEMV via SovereignLayerExecutor
    printf("[6/6] Executing GEMV (blk.0.attn_q.weight * input)...\n");
    SovereignTensorRef wq;
    wq.name        = "blk.0.attn_q.weight";
    wq.ggml_type   = (uint32_t)tq->type;
    wq.n_dims      = (uint32_t)tq->shape.size();
    wq.dims[0]     = tq->shape.size() > 0 ? tq->shape[0] : 0;
    wq.dims[1]     = tq->shape.size() > 1 ? tq->shape[1] : 0;
    wq.dims[2]     = 0;
    wq.dims[3]     = 0;
    wq.file_offset = 0;  // buffer starts at sovereign_buf
    wq.size_bytes  = expected_size;

    printf("      DIAG: last_row_end=%p  buffer_end=%p\n",
           (uint8_t*)sovereign_buf + expected_size,
           (uint8_t*)sovereign_buf + expected_size);

    // Warmup: one call to prime caches
    SovereignLayerExecutor::ExecuteAttentionQProj(wq, (uint8_t*)sovereign_buf, input, output);

    // Timed run
    LARGE_INTEGER freq, t0, t1;
    QueryPerformanceFrequency(&freq);
    const int iterations = requested_iterations;
    QueryPerformanceCounter(&t0);
    for (int i = 0; i < iterations; ++i) {
        SovereignLayerExecutor::ExecuteAttentionQProj(wq, (uint8_t*)sovereign_buf, input, output);
    }
    QueryPerformanceCounter(&t1);
    double elapsed_ms = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / (double)freq.QuadPart;
    double avg_ms = elapsed_ms / iterations;
    double ops = 2.0 * (double)n_rows * (double)n_cols; // MACs per GEMV
    double gflops = (ops * iterations) / (elapsed_ms * 1e-3) / 1e9;

    printf("\n=== Results ===\n");
    print_vector("Output", output, n_rows);
    printf("Iterations: %d  Total: %.3f ms  Avg: %.3f ms\n", iterations, elapsed_ms, avg_ms);
    printf("Throughput: %.2f GFLOPS\n", gflops);

    // 7. Strict numeric correctness gate against scalar reference.
    const int check_sweep_count = requested_check_sweep_count;
    const float kAbsTol = requested_abs_tol;
    float max_abs_err = 0.0f;
    int worst_row = -1;
    float worst_ref = 0.0f;
    float worst_out = 0.0f;
    int total_checked_rows = 0;

    for (int sweep = 0; sweep < check_sweep_count; ++sweep) {
        int requested_start = requested_check_start_row + sweep * requested_check_sweep_stride;
        if (requested_start < 0) {
            requested_start = 0;
        }
        const int check_start_row = std::min(requested_start, n_rows - 1);
        const int check_rows = std::min(requested_check_rows, n_rows - check_start_row);
        total_checked_rows += check_rows;

        for (int i = 0; i < check_rows; ++i) {
            const int r = check_start_row + i;
            if (!isfinite(output[r])) {
                fprintf(stderr, "FATAL: Non-finite output at row %d\n", r);
                _aligned_free(input);
                _aligned_free(output);
                RawrLinearAlloc_Free(sovereign_buf);
                return 1;
            }

            const uint8_t* row_ptr = (const uint8_t*)sovereign_buf + (size_t)r * (size_t)row_stride;
            const float ref = q4_0_row_dot_scalar(row_ptr, input, n_cols);
            const float abs_err = fabsf(output[r] - ref);
            if (abs_err > max_abs_err) {
                max_abs_err = abs_err;
                worst_row = r;
                worst_ref = ref;
                worst_out = output[r];
            }
        }
    }

    printf("Reference sweep: start_row=%d rows=%d windows=%d stride=%d total_rows=%d max_abs_err=%.6f tol=%.6f\n",
           requested_check_start_row,
           requested_check_rows,
           check_sweep_count,
           requested_check_sweep_stride,
           total_checked_rows,
           max_abs_err,
           kAbsTol);
    if (max_abs_err > kAbsTol) {
        fprintf(stderr,
                "FATAL: Reference mismatch at row %d: out=%.6f ref=%.6f abs_err=%.6f (tol=%.6f)\n",
                worst_row, worst_out, worst_ref, max_abs_err, kAbsTol);
        _aligned_free(input);
        _aligned_free(output);
        RawrLinearAlloc_Free(sovereign_buf);
        return 1;
    }

    // Cleanup
    _aligned_free(input);
    _aligned_free(output);
    RawrLinearAlloc_Free(sovereign_buf);
    printf("\n=== Smoke test PASSED ===\n");
    return 0;
}
