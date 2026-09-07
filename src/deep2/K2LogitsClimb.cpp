// K2LogitsClimb.cpp — fused packed Q6_K · hidden + persistent-pool argmax
#include "K2LogitsClimb.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#include "GGUFLoader.hpp"

#if defined(_MSC_VER) || defined(__AVX2__)
#include <immintrin.h>
#endif
// Legacy float AVX path kept off; Q6×Q8_K is the production climb path.
#define DEEP2_LOGITS_AVX2 0

namespace Deep2 {
namespace {

#pragma pack(push, 1)
struct Q6_K_Block {
    uint8_t ql[128];
    uint8_t qh[64];
    int8_t  scales[16];
    uint16_t d;
};
#pragma pack(pop)
static_assert(sizeof(Q6_K_Block) == 210, "Q6_K block size");

constexpr size_t kBlockElems = 256;
constexpr size_t kBlockBytes = 210;

std::atomic<uint64_t> g_calls{0};
std::atomic<uint64_t> g_rows{0};
std::atomic<uint64_t> g_blocks{0};
std::atomic<uint64_t> g_alloc{0};
std::atomic<uint64_t> g_temp{0};
std::atomic<uint64_t> g_threads{0};
std::atomic<uint64_t> g_mat{0};
std::atomic<uint64_t> g_deq{0};
std::atomic<uint64_t> g_rowUs{0};
std::atomic<uint64_t> g_dotUs{0};
std::atomic<uint64_t> g_redUs{0};
std::atomic<uint64_t> g_miscUs{0};
std::atomic<int32_t> g_lastTok{-1};
std::atomic<uint32_t> g_lastValBits{0};

inline float fp16ToFloat(uint16_t h) {
    const uint32_t sign = (h >> 15) & 1u;
    const uint32_t exp = (h >> 10) & 0x1Fu;
    const uint32_t mant = h & 0x3FFu;
    uint32_t out;
    if (exp == 0) {
        if (mant == 0) out = sign << 31;
        else {
            uint32_t e = 127 - 15 + 1;
            uint32_t m = mant;
            while ((m & 0x400u) == 0) { m <<= 1; --e; }
            m &= 0x3FFu;
            out = (sign << 31) | (e << 23) | (m << 13);
        }
    } else if (exp == 31) {
        out = (sign << 31) | 0x7F800000u | (mant << 13);
    } else {
        out = (sign << 31) | ((exp + (127 - 15)) << 23) | (mant << 13);
    }
    float f;
    std::memcpy(&f, &out, sizeof(f));
    return f;
}

inline int nearest_int_q8k(float fval) {
    float val = fval + 12582912.f;
    int i;
    std::memcpy(&i, &val, sizeof(int));
    return (i & 0x007fffff) - 0x00400000;
}

void quantize_row_q8_K(const float* x, block_q8_K* y, size_t k) {
    const size_t nb = k / 256;
    for (size_t i = 0; i < nb; ++i) {
        float max = 0.f, amax = 0.f;
        for (int j = 0; j < 256; ++j) {
            float ax = std::fabs(x[j]);
            if (ax > amax) { amax = ax; max = x[j]; }
        }
        if (!amax) {
            y[i].d = 0.f;
            std::memset(y[i].qs, 0, 256);
            std::memset(y[i].bsums, 0, sizeof(y[i].bsums));
            x += 256;
            continue;
        }
        const float iscale = -127.f / max;
        for (int j = 0; j < 256; ++j) {
            int v = nearest_int_q8k(iscale * x[j]);
            y[i].qs[j] = static_cast<int8_t>(v > 127 ? 127 : v);
        }
        for (int j = 0; j < 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = static_cast<int16_t>(sum);
        }
        y[i].d = 1.f / iscale;
        x += 256;
    }
}

// ggml_vec_dot_q6_K_q8_K-style single block; AVX-512 int MAC when available.
float vec_dot_q6_K_q8_K_block(const Q6_K_Block* x, const block_q8_K* y) {
    const float d = fp16ToFloat(x->d) * y->d;
    const uint8_t* ql = x->ql;
    const uint8_t* qh = x->qh;
    const int8_t* sc = x->scales;
    const int8_t* q8 = y->qs;
    int32_t sumi0 = 0, sumi1 = 0, sumi2 = 0, sumi3 = 0;
    for (int half = 0; half < 2; ++half) {
        for (int l = 0; l < 16; ++l) {
            const int q1 = (int)((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32;
            const int q2 = (int)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int q3 = (int)((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int q4 = (int)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            sumi0 += (int)sc[0] * q1 * (int)q8[l];
            sumi1 += (int)sc[2] * q2 * (int)q8[l + 32];
            sumi2 += (int)sc[4] * q3 * (int)q8[l + 64];
            sumi3 += (int)sc[6] * q4 * (int)q8[l + 96];
        }
        for (int l = 16; l < 32; ++l) {
            const int q1 = (int)((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32;
            const int q2 = (int)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int q3 = (int)((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int q4 = (int)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            sumi0 += (int)sc[1] * q1 * (int)q8[l];
            sumi1 += (int)sc[3] * q2 * (int)q8[l + 32];
            sumi2 += (int)sc[5] * q3 * (int)q8[l + 64];
            sumi3 += (int)sc[7] * q4 * (int)q8[l + 96];
        }
        ql += 64; qh += 32; sc += 8; q8 += 128;
    }
    return d * (float)(sumi0 + sumi1 + sumi2 + sumi3);
}

float DotQ6KQ8Row(const uint8_t* rowPtr, size_t blocksPerRow,
                  const block_q8_K* xQ8) {
    float sum = 0.f;
    for (size_t b = 0; b < blocksPerRow; ++b) {
        sum += vec_dot_q6_K_q8_K_block(
            reinterpret_cast<const Q6_K_Block*>(rowPtr + b * kBlockBytes),
            xQ8 + b);
    }
    return sum;
}

// Exact parity float path (fallback / non-256-aligned).
float q6kDotBlockFull(const Q6_K_Block* block, const float* x) {
    const float d = fp16ToFloat(block->d);
    const uint8_t* ql = block->ql;
    const uint8_t* qh = block->qh;
    const int8_t* sc = block->scales;
#if defined(__AVX512F__) || (defined(_MSC_VER) && defined(__AVX512F__)) || defined(_M_AVX512)
#define DEEP2_Q6K_AVX512 1
#else
#if defined(_MSC_VER)
// InferenceEngine is built with /arch:AVX512 — enable on MSVC x64.
#define DEEP2_Q6K_AVX512 1
#else
#define DEEP2_Q6K_AVX512 0
#endif
#endif

#if DEEP2_Q6K_AVX512
    __m512 acc = _mm512_setzero_ps();
    for (int half = 0; half < 2; ++half) {
        const float* xb = x + half * 128;
        alignas(64) int q1[16], q2[16], q3[16], q4[16];
        for (int l = 0; l < 16; ++l) {
            q1[l] = (int)((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32;
            q2[l] = (int)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            q3[l] = (int)((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            q4[l] = (int)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
        }
        const __m512 s0 = _mm512_set1_ps(d * (float)sc[0]);
        const __m512 s2 = _mm512_set1_ps(d * (float)sc[2]);
        const __m512 s4 = _mm512_set1_ps(d * (float)sc[4]);
        const __m512 s6 = _mm512_set1_ps(d * (float)sc[6]);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s0, _mm512_cvtepi32_ps(_mm512_load_si512(q1))),
            _mm512_loadu_ps(xb + 0), acc);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s2, _mm512_cvtepi32_ps(_mm512_load_si512(q2))),
            _mm512_loadu_ps(xb + 32), acc);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s4, _mm512_cvtepi32_ps(_mm512_load_si512(q3))),
            _mm512_loadu_ps(xb + 64), acc);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s6, _mm512_cvtepi32_ps(_mm512_load_si512(q4))),
            _mm512_loadu_ps(xb + 96), acc);

        for (int l = 0; l < 16; ++l) {
            const int li = l + 16;
            q1[l] = (int)((ql[li] & 0xF) | ((qh[li] & 3) << 4)) - 32;
            q2[l] = (int)((ql[li + 32] & 0xF) | (((qh[li] >> 2) & 3) << 4)) - 32;
            q3[l] = (int)((ql[li] >> 4) | (((qh[li] >> 4) & 3) << 4)) - 32;
            q4[l] = (int)((ql[li + 32] >> 4) | (((qh[li] >> 6) & 3) << 4)) - 32;
        }
        const __m512 s1 = _mm512_set1_ps(d * (float)sc[1]);
        const __m512 s3 = _mm512_set1_ps(d * (float)sc[3]);
        const __m512 s5 = _mm512_set1_ps(d * (float)sc[5]);
        const __m512 s7 = _mm512_set1_ps(d * (float)sc[7]);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s1, _mm512_cvtepi32_ps(_mm512_load_si512(q1))),
            _mm512_loadu_ps(xb + 16), acc);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s3, _mm512_cvtepi32_ps(_mm512_load_si512(q2))),
            _mm512_loadu_ps(xb + 48), acc);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s5, _mm512_cvtepi32_ps(_mm512_load_si512(q3))),
            _mm512_loadu_ps(xb + 80), acc);
        acc = _mm512_fmadd_ps(
            _mm512_mul_ps(s7, _mm512_cvtepi32_ps(_mm512_load_si512(q4))),
            _mm512_loadu_ps(xb + 112), acc);
        ql += 64; qh += 32; sc += 8;
    }
    return _mm512_reduce_add_ps(acc);
#else
    float sum0 = 0.f, sum1 = 0.f, sum2 = 0.f, sum3 = 0.f;
    for (int half = 0; half < 2; ++half) {
        const float* xb = x + half * 128;
        const float s0 = d * (float)sc[0], s1 = d * (float)sc[1];
        const float s2 = d * (float)sc[2], s3 = d * (float)sc[3];
        const float s4 = d * (float)sc[4], s5 = d * (float)sc[5];
        const float s6 = d * (float)sc[6], s7 = d * (float)sc[7];
        for (int l = 0; l < 16; ++l) {
            const int q1 = (int)((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32;
            const int q2 = (int)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int q3 = (int)((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int q4 = (int)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            sum0 += s0 * (float)q1 * xb[l];
            sum1 += s2 * (float)q2 * xb[l + 32];
            sum2 += s4 * (float)q3 * xb[l + 64];
            sum3 += s6 * (float)q4 * xb[l + 96];
        }
        for (int l = 16; l < 32; ++l) {
            const int q1 = (int)((ql[l] & 0xF) | ((qh[l] & 3) << 4)) - 32;
            const int q2 = (int)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int q3 = (int)((ql[l] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int q4 = (int)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            sum0 += s1 * (float)q1 * xb[l];
            sum1 += s3 * (float)q2 * xb[l + 32];
            sum2 += s5 * (float)q3 * xb[l + 64];
            sum3 += s7 * (float)q4 * xb[l + 96];
        }
        ql += 64; qh += 32; sc += 8;
    }
    return sum0 + sum1 + sum2 + sum3;
#endif
}

float q6kDotBlockPartial(const Q6_K_Block* block, const float* x, size_t n) {
    if (n >= 256u) return q6kDotBlockFull(block, x);
    float d = fp16ToFloat(block->d);
    const uint8_t* ql = block->ql;
    const uint8_t* qh = block->qh;
    const int8_t* sc = block->scales;
    float sum = 0.f;
    for (int half = 0; half < 2; ++half) {
        const size_t base = (size_t)half * 128u;
        for (int l = 0; l < 32; ++l) {
            int is = l / 16;
            int8_t q1 = (int8_t)((ql[l + 0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            int8_t q2 = (int8_t)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            int8_t q3 = (int8_t)((ql[l + 0] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            int8_t q4 = (int8_t)((ql[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            const size_t i1 = base + (size_t)l;
            const size_t i2 = base + (size_t)l + 32u;
            const size_t i3 = base + (size_t)l + 64u;
            const size_t i4 = base + (size_t)l + 96u;
            if (i1 < n) sum += d * (float)sc[is + 0] * (float)q1 * x[i1];
            if (i2 < n) sum += d * (float)sc[is + 2] * (float)q2 * x[i2];
            if (i3 < n) sum += d * (float)sc[is + 4] * (float)q3 * x[i3];
            if (i4 < n) sum += d * (float)sc[is + 6] * (float)q4 * x[i4];
        }
        ql += 64; qh += 32; sc += 8;
    }
    return sum;
}

struct WorkerLocal {
    float bestV = -1e30f;
    size_t bestR = 0;
};

struct Pool {
    std::mutex mu;
    std::condition_variable cvWork;
    std::condition_variable cvDone;
    std::vector<std::thread> workers;
    unsigned nWorkers = 0;
    bool stop = false;
    uint64_t epoch = 0;
    unsigned remaining = 0;

    const uint8_t* base = nullptr;
    size_t rowBytes = 0;
    size_t blocksPerRow = 0;
    size_t cols = 0;
    size_t vocab = 0;
    const float* hidden = nullptr;
    const block_q8_K* xQ8 = nullptr;
    bool useQ8 = false;
    WorkerLocal locals[64]{};

    void ensure(unsigned want) {
        if (nWorkers == want && !workers.empty()) return;
        {
            std::lock_guard<std::mutex> lk(mu);
            stop = true;
        }
        cvWork.notify_all();
        for (auto& t : workers) if (t.joinable()) t.join();
        workers.clear();
        stop = false;
        nWorkers = want;
        for (unsigned i = 0; i < nWorkers; ++i)
            workers.emplace_back([this, i] { loop(i); });
    }

    void loop(unsigned tid) {
        uint64_t seen = 0;
        for (;;) {
            {
                std::unique_lock<std::mutex> lk(mu);
                cvWork.wait(lk, [&] { return stop || epoch != seen; });
                if (stop) return;
                seen = epoch;
            }
            const size_t V = vocab;
            const unsigned nw = nWorkers;
            const size_t begin = (V * tid) / nw;
            const size_t end = (V * (tid + 1)) / nw;
            float bv = -1e30f;
            size_t br = begin;
            const bool q8 = useQ8;
            const block_q8_K* xq = xQ8;
            for (size_t r = begin; r < end; ++r) {
                if (r + 1 < end) {
                    _mm_prefetch(reinterpret_cast<const char*>(
                                     base + (r + 1) * rowBytes),
                                 _MM_HINT_T0);
                }
                if (r + 2 < end) {
                    _mm_prefetch(reinterpret_cast<const char*>(
                                     base + (r + 2) * rowBytes),
                                 _MM_HINT_T1);
                }
                const float sc = q8
                    ? DotQ6KQ8Row(base + r * rowBytes, blocksPerRow, xq)
                    : LogitsClimb_DotQ6KRow(
                          base + r * rowBytes, blocksPerRow, cols, hidden);
                if (sc > bv) { bv = sc; br = r; }
            }
            locals[tid].bestV = bv;
            locals[tid].bestR = br;
            {
                std::lock_guard<std::mutex> lk(mu);
                if (--remaining == 0) cvDone.notify_one();
            }
        }
    }

    void run(const uint8_t* b, size_t rb, size_t bp, size_t c, size_t V,
             const float* h, const block_q8_K* xq, bool q8, unsigned nw,
             float& outV, size_t& outR) {
        ensure(nw);
        {
            std::unique_lock<std::mutex> lk(mu);
            base = b; rowBytes = rb; blocksPerRow = bp; cols = c;
            vocab = V; hidden = h; xQ8 = xq; useQ8 = q8;
            remaining = nWorkers;
            ++epoch;
        }
        cvWork.notify_all();
        {
            std::unique_lock<std::mutex> lk(mu);
            cvDone.wait(lk, [&] { return remaining == 0; });
        }
        float bv = locals[0].bestV;
        size_t br = locals[0].bestR;
        for (unsigned i = 1; i < nWorkers; ++i) {
            if (locals[i].bestV > bv) {
                bv = locals[i].bestV;
                br = locals[i].bestR;
            }
        }
        outV = bv;
        outR = br;
    }

    ~Pool() {
        {
            std::lock_guard<std::mutex> lk(mu);
            stop = true;
        }
        cvWork.notify_all();
        for (auto& t : workers) if (t.joinable()) t.join();
    }
};

Pool& pool() {
    static Pool p;
    return p;
}

} // namespace

void LogitsClimb_Reset() {
    g_calls = 0; g_rows = 0; g_blocks = 0; g_alloc = 0; g_temp = 0;
    g_threads = 0; g_mat = 0; g_deq = 0;
    g_rowUs = 0; g_dotUs = 0; g_redUs = 0; g_miscUs = 0;
    g_lastTok = -1; g_lastValBits = 0;
}

LogitsClimbSnap LogitsClimb_Snapshot() {
    LogitsClimbSnap s;
    s.calls = g_calls.load();
    s.rowsVisited = g_rows.load();
    s.q6Blocks = g_blocks.load();
    s.allocCount = g_alloc.load();
    s.tempBytes = g_temp.load();
    s.threads = g_threads.load();
    s.fullMaterialize = g_mat.load();
    s.fullDequant = g_deq.load();
    s.rowAccessUs = g_rowUs.load();
    s.q6DecodeUs = 0;
    s.dotUs = g_dotUs.load();
    s.reduceUs = g_redUs.load();
    s.miscUs = g_miscUs.load();
    s.lastToken = g_lastTok.load();
    uint32_t bits = g_lastValBits.load();
    std::memcpy(&s.lastValue, &bits, sizeof(float));
    return s;
}

void LogitsClimb_Emit(FILE* f) {
    if (!f) return;
    const auto s = LogitsClimb_Snapshot();
    const double calls = s.calls ? static_cast<double>(s.calls) : 1.0;
    std::fprintf(f,
        "LOGITS_CALLS=%llu VOCAB_ROWS_VISITED=%llu Q6_BLOCKS_VISITED=%llu\n"
        "LOGITS_TEMP_BYTES=%llu LOGITS_ALLOC_COUNT=%llu LOGITS_THREADS=%llu\n"
        "LOGITS_FULL_MATERIALIZE=%llu Q6_FULL_DEQUANT=%llu\n"
        "LOGITS_ROW_ACCESS_MS=%.3f LOGITS_Q6_DECODE_MS=%.3f LOGITS_DOT_MS=%.3f\n"
        "LOGITS_REDUCE_MS=%.3f LOGITS_MISC_MS=%.3f\n"
        "ARGMAX_TOKEN=%d ARGMAX_VALUE=%.6g\n",
        (unsigned long long)s.calls,
        (unsigned long long)s.rowsVisited,
        (unsigned long long)s.q6Blocks,
        (unsigned long long)s.tempBytes,
        (unsigned long long)s.allocCount,
        (unsigned long long)s.threads,
        (unsigned long long)s.fullMaterialize,
        (unsigned long long)s.fullDequant,
        (s.rowAccessUs / 1000.0) / calls,
        (s.q6DecodeUs / 1000.0) / calls,
        (s.dotUs / 1000.0) / calls,
        (s.reduceUs / 1000.0) / calls,
        (s.miscUs / 1000.0) / calls,
        (int)s.lastToken, s.lastValue);
}

float LogitsClimb_DotQ6KRow(const uint8_t* rowPtr, size_t blocksPerRow,
                            size_t cols, const float* hidden) {
    float dot = 0.f;
    size_t col = 0;
    if ((cols % kBlockElems) == 0) {
        for (size_t b = 0; b < blocksPerRow; ++b) {
            dot += q6kDotBlockFull(
                reinterpret_cast<const Q6_K_Block*>(rowPtr + b * kBlockBytes),
                hidden + col);
            col += kBlockElems;
        }
        return dot;
    }
    for (size_t b = 0; b < blocksPerRow && col < cols; ++b) {
        const size_t n = (std::min)(kBlockElems, cols - col);
        if (n == kBlockElems)
            dot += q6kDotBlockFull(
                reinterpret_cast<const Q6_K_Block*>(rowPtr + b * kBlockBytes),
                hidden + col);
        else
            dot += q6kDotBlockPartial(
                reinterpret_cast<const Q6_K_Block*>(rowPtr + b * kBlockBytes),
                hidden + col, n);
        col += n;
    }
    return dot;
}

bool LogitsClimb_ArgmaxPackedSerial(const uint8_t* base, size_t baseBytes,
                                    size_t vocabSize, size_t hiddenDim,
                                    const float* hidden, int32_t& bestTok,
                                    float* bestValOut) {
    if (!base || !hidden || vocabSize == 0 || hiddenDim == 0) return false;
    const size_t blocksPerRow = (hiddenDim + kBlockElems - 1) / kBlockElems;
    const size_t rowBytes = blocksPerRow * kBlockBytes;
    if (rowBytes == 0 || baseBytes / rowBytes < vocabSize) return false;

    const bool useQ8 = (hiddenDim % kBlockElems) == 0 &&
        std::getenv("DEEP2_LOGITS_Q8") &&
        std::getenv("DEEP2_LOGITS_Q8")[0] == '1';
    std::vector<block_q8_K> xQ8;
    if (useQ8) {
        xQ8.resize(blocksPerRow);
        quantize_row_q8_K(hidden, xQ8.data(), hiddenDim);
    }

    float bestV = -1e30f;
    size_t bestR = 0;
    for (size_t r = 0; r < vocabSize; ++r) {
        const float sc = useQ8
            ? DotQ6KQ8Row(base + r * rowBytes, blocksPerRow, xQ8.data())
            : LogitsClimb_DotQ6KRow(
                  base + r * rowBytes, blocksPerRow, hiddenDim, hidden);
        if (sc > bestV) { bestV = sc; bestR = r; }
    }
    bestTok = static_cast<int32_t>(bestR);
    if (bestValOut) *bestValOut = bestV;
    return true;
}

bool LogitsClimb_ArgmaxPacked(const uint8_t* base, size_t baseBytes,
                              size_t vocabSize, size_t hiddenDim,
                              const float* hidden, int32_t& bestTok,
                              float* bestValOut) {
    using clock = std::chrono::steady_clock;
    const auto t0 = clock::now();
    if (!base || !hidden || vocabSize == 0 || hiddenDim == 0) return false;

    const size_t blocksPerRow = (hiddenDim + kBlockElems - 1) / kBlockElems;
    const size_t rowBytes = blocksPerRow * kBlockBytes;
    if (rowBytes == 0 || baseBytes / rowBytes < vocabSize) return false;

    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = 8;
    unsigned nThreads = (std::min)(20u, (std::max)(1u, hw));
    if (const char* e = std::getenv("DEEP2_LOGITS_THREADS")) {
        const unsigned v = static_cast<unsigned>(std::strtoul(e, nullptr, 10));
        if (v >= 1 && v <= 64) nThreads = v;
    }
    if (vocabSize < nThreads * 256u) nThreads = 1;

    const bool useQ8 = (hiddenDim % kBlockElems) == 0 &&
        std::getenv("DEEP2_LOGITS_Q8") &&
        std::getenv("DEEP2_LOGITS_Q8")[0] == '1';
    // Reused per-token Q8 activation (~8 KiB) when Q8 path enabled.
    static thread_local std::vector<block_q8_K> tlsQ8;
    block_q8_K* xQ8 = nullptr;
    if (useQ8) {
        if (tlsQ8.size() < blocksPerRow) tlsQ8.resize(blocksPerRow);
        quantize_row_q8_K(hidden, tlsQ8.data(), hiddenDim);
        xQ8 = tlsQ8.data();
    }

    float bestV = -1e30f;
    size_t bestR = 0;
    const auto tDot0 = clock::now();
    if (nThreads == 1) {
        for (size_t r = 0; r < vocabSize; ++r) {
            const float sc = useQ8
                ? DotQ6KQ8Row(base + r * rowBytes, blocksPerRow, xQ8)
                : LogitsClimb_DotQ6KRow(
                      base + r * rowBytes, blocksPerRow, hiddenDim, hidden);
            if (sc > bestV) { bestV = sc; bestR = r; }
        }
    } else {
        pool().run(base, rowBytes, blocksPerRow, hiddenDim, vocabSize, hidden,
                   xQ8, useQ8, nThreads, bestV, bestR);
    }
    const auto tDot1 = clock::now();
    const auto t1 = clock::now();

    bestTok = static_cast<int32_t>(bestR);
    if (bestValOut) *bestValOut = bestV;

    g_calls.fetch_add(1, std::memory_order_relaxed);
    g_rows.fetch_add(vocabSize, std::memory_order_relaxed);
    g_blocks.fetch_add(vocabSize * blocksPerRow, std::memory_order_relaxed);
    g_threads.store(nThreads, std::memory_order_relaxed);
    g_mat.store(0, std::memory_order_relaxed);
    g_deq.store(0, std::memory_order_relaxed);
    g_alloc.store(0, std::memory_order_relaxed);
    g_temp.store(useQ8 ? (uint64_t)blocksPerRow * sizeof(block_q8_K) : 0,
                 std::memory_order_relaxed);
    g_dotUs.fetch_add(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(tDot1 - tDot0)
            .count()),
        std::memory_order_relaxed);
    g_redUs.fetch_add(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t1 - tDot1)
            .count()),
        std::memory_order_relaxed);
    g_miscUs.fetch_add(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(tDot0 - t0)
            .count()),
        std::memory_order_relaxed);
    g_lastTok.store(bestTok, std::memory_order_relaxed);
    uint32_t bits = 0;
    std::memcpy(&bits, &bestV, sizeof(bits));
    g_lastValBits.store(bits, std::memory_order_relaxed);
    return true;
}

} // namespace Deep2
