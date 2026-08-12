// Standalone Softmax_AVX512 validation test
// Build: cl /O2 /arch:AVX512 /EHsc softmax_standalone_test.cpp /Fesoftmax_standalone_test.exe
// Or:    g++ -O2 -mavx512f -o softmax_standalone_test softmax_standalone_test.cpp

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <random>
#include <algorithm>
#include <limits>

#ifdef __AVX512F__
#include <immintrin.h>
#endif

// =============================================================================
// Reference scalar softmax (exactly matches the non-AVX512 path in production)
// =============================================================================
void reference_softmax(float* x, int size)
{
    if (!x || size <= 0) return;
    if (size == 1) { x[0] = 1.0f; return; }

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

// =============================================================================
// Portable AVX-512 exp approximation (copied from rawrxd_transformer.cpp)
// =============================================================================
#ifdef __AVX512F__
static inline __m512 _rawrxd_exp_ps_avx512(__m512 x)
{
    const __m512 hi = _mm512_set1_ps(88.3762626647949f);
    const __m512 lo = _mm512_set1_ps(-87.3365447504f);
    x = _mm512_min_ps(x, hi);
    x = _mm512_max_ps(x, lo);

    const __m512 log2e = _mm512_set1_ps(1.44269504088896341f);
    const __m512 half = _mm512_set1_ps(0.5f);
    __m512 t = _mm512_fmadd_ps(x, log2e, half);

    __m512 n = _mm512_roundscale_ps(t, _MM_FROUND_TO_NEG_INF | _MM_FROUND_NO_EXC);

    const __m512 c1 = _mm512_set1_ps(0.693359375f);
    const __m512 c2 = _mm512_set1_ps(-2.12194440e-4f);
    __m512 f = _mm512_fnmadd_ps(n, c1, x);
    f = _mm512_fnmadd_ps(n, c2, f);

    const __m512 p0 = _mm512_set1_ps(1.0f);
    const __m512 p1 = _mm512_set1_ps(1.0f);
    const __m512 p2 = _mm512_set1_ps(0.5f);
    const __m512 p3 = _mm512_set1_ps(0.1666666666666f);
    const __m512 p4 = _mm512_set1_ps(0.0416666666666f);
    const __m512 p5 = _mm512_set1_ps(0.0083333333333f);
    const __m512 p6 = _mm512_set1_ps(0.0013888888888f);

    __m512 y = _mm512_fmadd_ps(p6, f, p5);
    y = _mm512_fmadd_ps(y, f, p4);
    y = _mm512_fmadd_ps(y, f, p3);
    y = _mm512_fmadd_ps(y, f, p2);
    y = _mm512_fmadd_ps(y, f, p1);
    y = _mm512_fmadd_ps(y, f, p0);

    __m512i ni = _mm512_cvtps_epi32(n);
    ni = _mm512_slli_epi32(ni, 23);
    __m512 pow2n = _mm512_castsi512_ps(_mm512_add_epi32(ni, _mm512_set1_epi32(0x3F800000)));

    return _mm512_mul_ps(y, pow2n);
}

// =============================================================================
// AVX-512 Softmax (copied from rawrxd_transformer.cpp)
// =============================================================================
void Softmax_AVX512(float* x, int size)
{
    if (!x || size <= 0)
        return;
    if (size == 1)
    {
        x[0] = 1.0f;
        return;
    }
    for (int i = 0; i < size; ++i)
    {
        if (!std::isfinite(x[i]))
            x[i] = -1e9f;
    }

    float max_val = x[0];
    int i = 1;
    if (size >= 16)
    {
        __m512 max_vec = _mm512_loadu_ps(x);
        i = 16;
        for (; i + 15 < size; i += 16)
        {
            __m512 curr_vec = _mm512_loadu_ps(x + i);
            max_vec = _mm512_max_ps(max_vec, curr_vec);
        }
        max_val = _mm512_reduce_max_ps(max_vec);
    }
    for (; i < size; i++)
    {
        if (x[i] > max_val)
            max_val = x[i];
    }

    __m512 max_val_vec = _mm512_set1_ps(max_val);
    __m512 sum_vec = _mm512_setzero_ps();
    i = 0;
    for (; i + 15 < size; i += 16)
    {
        __m512 curr_vec = _mm512_loadu_ps(x + i);
        curr_vec = _mm512_sub_ps(curr_vec, max_val_vec);
        curr_vec = _rawrxd_exp_ps_avx512(curr_vec);
        _mm512_storeu_ps(x + i, curr_vec);
        sum_vec = _mm512_add_ps(sum_vec, curr_vec);
    }
    float sum = _mm512_reduce_add_ps(sum_vec);
    for (; i < size; i++)
    {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    if (!std::isfinite(sum) || sum <= 0.0f)
    {
        const float uni = 1.0f / static_cast<float>(size);
        for (int j = 0; j < size; ++j)
            x[j] = uni;
        return;
    }

    __m512 sum_inv_vec = _mm512_set1_ps(1.0f / sum);
    i = 0;
    for (; i + 15 < size; i += 16)
    {
        __m512 curr_vec = _mm512_loadu_ps(x + i);
        curr_vec = _mm512_mul_ps(curr_vec, sum_inv_vec);
        _mm512_storeu_ps(x + i, curr_vec);
    }
    for (; i < size; i++)
    {
        x[i] /= sum;
    }
}
#else
void Softmax_AVX512(float* x, int size)
{
    reference_softmax(x, size);
}
#endif

// =============================================================================
// Validation helpers
// =============================================================================
static bool approx_equal(float a, float b, float tol = 1e-3f)
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

    // Test various sizes including boundary conditions
    int sizes[] = {1, 2, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1000};
    for (int sz : sizes)
        all_ok &= test_size(sz, "random_finite");

    printf("\n--- Pathological cases ---\n");

    // All zeros
    all_ok &= test_pathological(std::vector<float>(16, 0.0f), "all_zeros");

    // All large positive
    all_ok &= test_pathological(std::vector<float>(16, 80.0f), "all_large_pos");

    // All large negative
    all_ok &= test_pathological(std::vector<float>(16, -80.0f), "all_large_neg");

    // Mixed with +inf
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

    // Size exactly at AVX-512 boundary (16)
    {
        std::vector<float> v(16);
        for (int i = 0; i < 16; ++i) v[i] = static_cast<float>(i);
        all_ok &= test_pathological(v, "size_16_ramp");
    }

    // Size just above boundary (17)
    {
        std::vector<float> v(17);
        for (int i = 0; i < 17; ++i) v[i] = static_cast<float>(i);
        all_ok &= test_pathological(v, "size_17_ramp");
    }

    printf("\n=== %s ===\n", all_ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return all_ok ? 0 : 1;
}
