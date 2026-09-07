#include <immintrin.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <atomic>

#pragma pack(push, 1)
struct block_q4_K_layout {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[128];
};
#pragma pack(pop)

static inline float fp16_to_fp32(uint16_t h) {
    uint32_t sign = (h & 0x8000) << 16;
    uint32_t exp  = (h & 0x7C00) >> 10;
    uint32_t mant = (h & 0x03FF) << 13;
    if (exp == 0) return 0.0f;
    if (exp == 31) {
        uint32_t f = sign | 0x7F800000 | mant;
        float res; std::memcpy(&res, &f, sizeof(res)); return res;
    }
    exp = exp + (127 - 15);
    uint32_t f = sign | (exp << 23) | mant;
    float res; std::memcpy(&res, &f, sizeof(res)); return res;
}

static inline float quantize_activations_avx2(
    const float* __restrict src_fp32,
    int8_t* __restrict dst_int8,
    size_t length)
{
    const __m256 v_sign_mask = _mm256_castsi256_ps(_mm256_set1_epi32(0x7FFFFFFF));
    __m256 v_max_abs = _mm256_setzero_ps();

    for (size_t i = 0; i < length; i += 32) {
        __m256 v0 = _mm256_and_ps(_mm256_loadu_ps(src_fp32 + i), v_sign_mask);
        __m256 v1 = _mm256_and_ps(_mm256_loadu_ps(src_fp32 + i + 8), v_sign_mask);
        __m256 v2 = _mm256_and_ps(_mm256_loadu_ps(src_fp32 + i + 16), v_sign_mask);
        __m256 v3 = _mm256_and_ps(_mm256_loadu_ps(src_fp32 + i + 24), v_sign_mask);
        __m256 max01 = _mm256_max_ps(v0, v1);
        __m256 max23 = _mm256_max_ps(v2, v3);
        v_max_abs = _mm256_max_ps(v_max_abs, _mm256_max_ps(max01, max23));
    }

    alignas(32) float max_arr[8];
    _mm256_store_ps(max_arr, v_max_abs);
    float max_val = max_arr[0];
    for (int i = 1; i < 8; ++i) if (max_arr[i] > max_val) max_val = max_arr[i];
    if (max_val < 1.0e-10f) max_val = 1.0e-10f;

    float scale = max_val / 127.0f;
    float inv_scale = 127.0f / max_val;
    __m256 v_inv_scale = _mm256_set1_ps(inv_scale);
    const __m256i perm_mask = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);

    for (size_t i = 0; i < length; i += 32) {
        __m256 v0 = _mm256_mul_ps(_mm256_loadu_ps(src_fp32 + i), v_inv_scale);
        __m256 v1 = _mm256_mul_ps(_mm256_loadu_ps(src_fp32 + i + 8), v_inv_scale);
        __m256 v2 = _mm256_mul_ps(_mm256_loadu_ps(src_fp32 + i + 16), v_inv_scale);
        __m256 v3 = _mm256_mul_ps(_mm256_loadu_ps(src_fp32 + i + 24), v_inv_scale);
        __m256i i0 = _mm256_cvtps_epi32(v0);
        __m256i i1 = _mm256_cvtps_epi32(v1);
        __m256i i2 = _mm256_cvtps_epi32(v2);
        __m256i i3 = _mm256_cvtps_epi32(v3);
        __m256i p01 = _mm256_packs_epi32(i0, i1);
        __m256i p23 = _mm256_packs_epi32(i2, i3);
        __m256i p8 = _mm256_packs_epi16(p01, p23);
        __m256i ordered = _mm256_permutevar8x32_epi32(p8, perm_mask);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(dst_int8 + i), ordered);
    }
    return scale;
}

static inline int32_t reduce_sum_epi32_avx2(__m256i v) {
    __m128i v_low = _mm256_castsi256_si128(v);
    __m128i v_high = _mm256_extracti128_si256(v, 1);
    __m128i v128 = _mm_add_epi32(v_low, v_high);
    v128 = _mm_hadd_epi32(v128, v128);
    v128 = _mm_hadd_epi32(v128, v128);
    return _mm_cvtsi128_si32(v128);
}

class ThreadPool {
public:
    explicit ThreadPool(size_t threads) : stop(false) {
        for (size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });
                        if (this->stop && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            });
        }
    }
    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }
    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread &worker : workers) if (worker.joinable()) worker.join();
    }
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

static ThreadPool& GetThreadPool() {
    size_t num_cores = std::thread::hardware_concurrency();
    if (num_cores == 0) num_cores = 4;
    static ThreadPool pool(num_cores);
    return pool;
}

extern "C" void gemv_q4_k_avx2(
    const block_q4_K_layout* __restrict weights,
    const float* __restrict x_fp32,
    float* __restrict y_out,
    uint32_t num_blocks,
    uint32_t vocab_size)
{
    const size_t total_elements = num_blocks * 256;
    std::vector<int8_t> x_int8(total_elements);
    float act_scale = quantize_activations_avx2(x_fp32, x_int8.data(), total_elements);

    const __m256i v_nibble_mask = _mm256_set1_epi8(0x0F);
    const __m256i v_one_16 = _mm256_set1_epi16(1);
    const __m256i v_one_8 = _mm256_set1_epi8(1);

    ThreadPool& pool = GetThreadPool();
    size_t num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) num_threads = 4;

    size_t rows_per_thread = (vocab_size + num_threads - 1) / num_threads;
    std::atomic<size_t> completed_tasks{0};

    for (size_t t = 0; t < num_threads; ++t) {
        size_t row_start = t * rows_per_thread;
        size_t row_end = std::min(row_start + rows_per_thread, static_cast<size_t>(vocab_size));
        if (row_start >= row_end) continue;

        pool.enqueue([=, &weights, &x_int8, &y_out, &completed_tasks]() {
            for (size_t row = row_start; row < row_end; ++row) {
                const block_q4_K_layout* row_blocks = weights + (row * num_blocks);
                const int8_t* row_act = x_int8.data();
                float row_accumulator = 0.0f;

                for (uint32_t b = 0; b < num_blocks; ++b) {
                    const block_q4_K_layout& block = row_blocks[b];
                    float d = fp16_to_fp32(block.d);
                    float dmin = fp16_to_fp32(block.dmin);
                    __m256i v_sum_dp = _mm256_setzero_si256();
                    __m256i v_act_sum = _mm256_setzero_si256();

                    for (int chunk = 0; chunk < 4; ++chunk) {
                        __m256i v_packed = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(block.qs + (chunk * 32)));
                        __m256i v_q_low = _mm256_and_si256(v_packed, v_nibble_mask);
                        __m256i v_q_high = _mm256_and_si256(_mm256_srli_epi16(v_packed, 4), v_nibble_mask);
                        const int8_t* act_ptr = row_act + (b * 256) + (chunk * 64);
                        __m256i v_act_0 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(act_ptr));
                        __m256i v_act_1 = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(act_ptr + 32));
                        __m256i dp_0 = _mm256_maddubs_epi16(v_q_low, v_act_0);
                        __m256i dp_1 = _mm256_maddubs_epi16(v_q_high, v_act_1);
                        v_sum_dp = _mm256_add_epi32(v_sum_dp, _mm256_madd_epi16(dp_0, v_one_16));
                        v_sum_dp = _mm256_add_epi32(v_sum_dp, _mm256_madd_epi16(dp_1, v_one_16));
                        __m256i as_0 = _mm256_maddubs_epi16(v_one_8, v_act_0);
                        __m256i as_1 = _mm256_maddubs_epi16(v_one_8, v_act_1);
                        v_act_sum = _mm256_add_epi32(v_act_sum, _mm256_madd_epi16(as_0, v_one_16));
                        v_act_sum = _mm256_add_epi32(v_act_sum, _mm256_madd_epi16(as_1, v_one_16));
                    }

                    int32_t dot_sum_scalar = reduce_sum_epi32_avx2(v_sum_dp);
                    int32_t act_sum_scalar = reduce_sum_epi32_avx2(v_act_sum);
                    float block_sum = (d * act_scale * static_cast<float>(dot_sum_scalar)) -
                                      (dmin * act_scale * static_cast<float>(act_sum_scalar));
                    row_accumulator += block_sum;
                }
                y_out[row] = row_accumulator;
            }
            completed_tasks.fetch_add(1, std::memory_order_relaxed);
        });
    }

    while (completed_tasks.load(std::memory_order_relaxed) < num_threads) {
        std::this_thread::yield();
    }
}
