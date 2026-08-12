// Softmax_AVX512 validation test — compare against reference scalar implementation
// Build: cl /O2 /arch:AVX512 /EHsc softmax_validate.cpp /Fesoftmax_validate.exe
// Or:    g++ -O2 -mavx512f -o softmax_validate softmax_validate.cpp

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <random>
#include <algorithm>
#include <limits>

// Copy the implementations from rawrxd_transformer.cpp for standalone testing
// (Simplified versions for validation)

void reference_softmax(float* x, int size)
{
    if (!x || size <= 0) return;
    if (size == 1) { x[0] = 1.0f; return; }

    // Replace non-finite with -1e9f (matches production path)
    for (int i = 0; i < size; ++i)
        if (!std::isfinite(x[i])) x[i] = -1e9f;

    float max_val = x[0];
    for (int i = 1; i < size; ++i)
        if (x[i] > max_val) max_val = x[i];

    float sum = 0.0f;
    for (int i = 0; i < size; ++i)
    {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }

    if (!std::isfinite(sum) || sum <= 0.0f)
    {
        const float uni = 1.0f / static_cast<float>(size);
        for (int j = 0; j < size; ++j) x[j] = uni;
        return;
    }

    const float inv = 1.0f / sum;
    for (int i = 0; i < size; ++i) x[i] *= inv;
}

// Forward declarations for AVX-512 versions (will be linked or copied)
void Softmax_AVX512(float* x, int size);

static bool approx_equal(float a, float b, float tol = 1e-4f)
{
    if (!std::isfinite(a) || !std::isfinite(b)) return false;
    float diff = std::fabs(a - b);
    float scale = std::max(1.0f, std::max(std::fabs(a), std::fabs(b)));
    return diff < tol * scale;
}

static bool test_size(int size, const char* label)
{
    std::vector<float> ref_input(size);
    std::vector<float> avx_input(size);

    // Random finite values
    std::mt19937 rng(42);
    std::uniform_real_distribution<float> dist(-5.0f, 5.0f);
    for (int i = 0; i < size; ++i)
        ref_input[i] = avx_input[i] = dist(rng);

    reference_softmax(ref_input.data(), size);
    Softmax_AVX512(avx_input.data(), size);

    bool ok = true;
    for (int i = 0; i < size; ++i)
    {
        if (!approx_equal(ref_input[i], avx_input[i], 1e-3f))
        {
            printf("  MISMATCH at %d: ref=%.8f avx=%.8f (diff=%.2e)\n",
                   i, ref_input[i], avx_input[i], std::fabs(ref_input[i] - avx_input[i]));
            ok = false;
        }
    }
    printf("[%s] size=%d %s\n", ok ? "PASS" : "FAIL", size, label);
    return ok;
}

static bool test_pathological(const std::vector<float>& input, const char* label)
{
    int size = static_cast<int>(input.size());
    std::vector<float> ref_input = input;
    std::vector<float> avx_input = input;

    reference_softmax(ref_input.data(), size);
    Softmax_AVX512(avx_input.data(), size);

    bool ok = true;
    for (int i = 0; i < size; ++i)
    {
        if (!approx_equal(ref_input[i], avx_input[i], 1e-3f))
        {
            printf("  MISMATCH at %d: ref=%.8f avx=%.8f (input=%.8f)\n",
                   i, ref_input[i], avx_input[i], input[i]);
            ok = false;
        }
    }
    printf("[%s] size=%d %s\n", ok ? "PASS" : "FAIL", size, label);
    return ok;
}

int main()
{
    printf("=== Softmax_AVX512 Validation ===\n\n");

    bool all_ok = true;

    // Test various sizes
    int sizes[] = {1, 2, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000};
    for (int sz : sizes)
        all_ok &= test_size(sz, "random");

    printf("\n--- Pathological cases ---\n");

    // All zeros
    all_ok &= test_pathological(std::vector<float>(16, 0.0f), "all_zeros");

    // All large positive
    all_ok &= test_pathological(std::vector<float>(16, 80.0f), "all_large_pos");

    // All large negative
    all_ok &= test_pathological(std::vector<float>(16, -80.0f), "all_large_neg");

    // Mixed with +inf (should be clamped to -1e9f in production)
    {
        std::vector<float> v(16, 1.0f);
        v[5] = std::numeric_limits<float>::infinity();
        all_ok &= test_pathological(v, "mixed_with_inf");
    }

    // Mixed with -inf
    {
        std::vector<float> v(16, 1.0f);
        v[5] = -std::numeric_limits<float>::infinity();
        all_ok &= test_pathological(v, "mixed_with_neginf");
    }

    // Mixed with NaN
    {
        std::vector<float> v(16, 1.0f);
        v[5] = std::numeric_limits<float>::quiet_NaN();
        all_ok &= test_pathological(v, "mixed_with_nan");
    }

    // One dominant element
    {
        std::vector<float> v(16, 0.0f);
        v[0] = 100.0f;
        all_ok &= test_pathological(v, "one_dominant");
    }

    // Very small values
    {
        std::vector<float> v(16, 1e-7f);
        all_ok &= test_pathological(v, "very_small");
    }

    printf("\n=== %s ===\n", all_ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return all_ok ? 0 : 1;
}
