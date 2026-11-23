#include "NativeTensorCompression.hpp"
#include "TensorResidencyCache.hpp"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "transformer E2E check failed at line %d: %s\\n", __LINE__, #expr); \
    return __LINE__; \
} } while (0)

using Storage = Deep2::TensorResidencyCache::Storage;

struct Tensor {
    std::size_t rows = 0;
    std::size_t cols = 0;
    std::vector<float> reference;
    std::shared_ptr<const Storage> compressed;
    Deep2::TensorResidencyCache::Lease lease;
};

static Tensor makeTensor(std::size_t rows, std::size_t cols, int seed,
                         Deep2::TensorResidencyCache& cache,
                         std::vector<std::shared_ptr<const Storage>>& owners,
                         bool norm = false) {
    Tensor t;
    t.rows = rows;
    t.cols = cols;
    t.reference.resize(rows * cols);
    for (std::size_t i = 0; i < t.reference.size(); ++i) {
        if (norm) {
            t.reference[i] = 1.0f + static_cast<float>((i + seed) % 3) * 0.125f;
        } else {
            const int q = static_cast<int>((i * 7 + seed * 11) % 17) - 8;
            t.reference[i] = static_cast<float>(q) * 0.03125f;
        }
    }
    auto packed = Storage::Build(t.reference.data(), t.reference.size(), 0.0f, 64);
    if (packed.storedBytes() != t.reference.size() * sizeof(std::uint16_t) ||
        packed.residentBytes() >= packed.originalBytes())
        throw std::runtime_error("synthetic model tensor did not compact");
    t.compressed = std::make_shared<const Storage>(std::move(packed));
    const std::string key = "tiny-transformer." + std::to_string(seed);
    if (!cache.Insert(key, t.compressed))
        throw std::runtime_error("synthetic model cache admission failed");
    t.lease = cache.Acquire(key);
    if (!t.lease)
        throw std::runtime_error("synthetic model cache lease failed");
    owners.push_back(t.compressed);
    return t;
}

static void readRow(const Tensor& t, std::size_t row, bool compressed,
                    std::vector<float>& scratch, const float*& values) {
    if (row >= t.rows) throw std::out_of_range("synthetic tensor row");
    if (compressed) {
        t.lease->ReadRange(row * t.cols, t.cols, scratch.data());
        values = scratch.data();
    } else {
        values = t.reference.data() + row * t.cols;
    }
}

static std::vector<float> matvec(const Tensor& w, const std::vector<float>& x,
                                 bool compressed) {
    if (x.size() != w.cols) throw std::runtime_error("synthetic GEMV shape mismatch");
    std::vector<float> y(w.rows, 0.0f), row(w.cols);
    const float* values = nullptr;
    for (std::size_t r = 0; r < w.rows; ++r) {
        readRow(w, r, compressed, row, values);
        for (std::size_t c = 0; c < w.cols; ++c)
            y[r] += values[c] * x[c];
    }
    return y;
}

static std::vector<float> rmsNorm(const std::vector<float>& x,
                                  const Tensor& scale, bool compressed) {
    std::vector<float> scratch(scale.cols);
    const float* w = nullptr;
    readRow(scale, 0, compressed, scratch, w);
    float sum = 0.0f;
    for (float v : x) sum += v * v;
    const float inv = 1.0f / std::sqrt(sum / static_cast<float>(x.size()) + 1.0e-5f);
    std::vector<float> out(x.size());
    for (std::size_t i = 0; i < x.size(); ++i) out[i] = x[i] * inv * w[i];
    return out;
}

struct TinyModel {
    Tensor embedding, attnNorm, wq, wk, wv, wo;
    Tensor ffnNorm, wGate, wUp, wDown, finalNorm, lmHead;
};

static std::vector<float> forward(const TinyModel& m,
                                  const std::vector<int>& tokens,
                                  bool compressed) {
    constexpr std::size_t H = 8, Heads = 2, HeadDim = H / Heads, Inter = 12;
    const std::size_t seq = tokens.size();
    std::vector<std::vector<float>> hidden(seq, std::vector<float>(H));
    std::vector<float> row(H);
    const float* values = nullptr;
    for (std::size_t t = 0; t < seq; ++t) {
        readRow(m.embedding, static_cast<std::size_t>(tokens[t]), compressed, row, values);
        std::copy(values, values + H, hidden[t].begin());
    }

    std::vector<std::vector<float>> q(seq), k(seq), v(seq);
    for (std::size_t t = 0; t < seq; ++t) {
        const auto n = rmsNorm(hidden[t], m.attnNorm, compressed);
        q[t] = matvec(m.wq, n, compressed);
        k[t] = matvec(m.wk, n, compressed);
        v[t] = matvec(m.wv, n, compressed);
    }

    std::vector<std::vector<float>> attended(seq, std::vector<float>(H, 0.0f));
    for (std::size_t t = 0; t < seq; ++t) {
        for (std::size_t h = 0; h < Heads; ++h) {
            std::vector<float> scores(t + 1, 0.0f);
            for (std::size_t s = 0; s <= t; ++s) {
                for (std::size_t d = 0; d < HeadDim; ++d)
                    scores[s] += q[t][h * HeadDim + d] * k[s][h * HeadDim + d];
                scores[s] /= std::sqrt(static_cast<float>(HeadDim));
            }
            const float maxScore = *std::max_element(scores.begin(), scores.end());
            float denom = 0.0f;
            for (float& score : scores) { score = std::exp(score - maxScore); denom += score; }
            for (float& score : scores) score /= denom;
            for (std::size_t d = 0; d < HeadDim; ++d)
                for (std::size_t s = 0; s <= t; ++s)
                    attended[t][h * HeadDim + d] +=
                        scores[s] * v[s][h * HeadDim + d];
        }
    }

    for (std::size_t t = 0; t < seq; ++t) {
        auto projected = matvec(m.wo, attended[t], compressed);
        for (std::size_t i = 0; i < H; ++i) hidden[t][i] += projected[i];

        const auto n = rmsNorm(hidden[t], m.ffnNorm, compressed);
        const auto gate = matvec(m.wGate, n, compressed);
        const auto up = matvec(m.wUp, n, compressed);
        std::vector<float> activated(Inter);
        for (std::size_t i = 0; i < Inter; ++i)
            activated[i] = (gate[i] / (1.0f + std::exp(-gate[i]))) * up[i];
        const auto down = matvec(m.wDown, activated, compressed);
        for (std::size_t i = 0; i < H; ++i) hidden[t][i] += down[i];
    }

    const auto finalHidden = rmsNorm(hidden.back(), m.finalNorm, compressed);
    return matvec(m.lmHead, finalHidden, compressed);
}

int main() {
    constexpr std::size_t Vocab = 11, H = 8, Inter = 12;
    constexpr std::size_t TensorCount = 12;
    Deep2::TensorResidencyCache cache(2u * 1024u * 1024u);
    std::vector<std::shared_ptr<const Storage>> owners;
    TinyModel m;
    int seed = 1;
    m.embedding = makeTensor(Vocab, H, seed++, cache, owners);
    m.attnNorm = makeTensor(1, H, seed++, cache, owners, true);
    m.wq = makeTensor(H, H, seed++, cache, owners);
    m.wk = makeTensor(H, H, seed++, cache, owners);
    m.wv = makeTensor(H, H, seed++, cache, owners);
    m.wo = makeTensor(H, H, seed++, cache, owners);
    m.ffnNorm = makeTensor(1, H, seed++, cache, owners, true);
    m.wGate = makeTensor(Inter, H, seed++, cache, owners);
    m.wUp = makeTensor(Inter, H, seed++, cache, owners);
    m.wDown = makeTensor(H, Inter, seed++, cache, owners);
    m.finalNorm = makeTensor(1, H, seed++, cache, owners, true);
    m.lmHead = makeTensor(Vocab, H, seed++, cache, owners);

    const std::vector<int> tokens{1, 4, 2};
    const auto reference = forward(m, tokens, false);
    const auto candidate = forward(m, tokens, true);
    CHECK(reference.size() == Vocab && candidate.size() == Vocab);
    int referenceToken = 0, compressedToken = 0;
    for (std::size_t i = 0; i < Vocab; ++i) {
        CHECK(std::isfinite(reference[i]) && std::isfinite(candidate[i]));
        CHECK(std::fabs(reference[i] - candidate[i]) <= 1.0e-5f);
        if (reference[i] > reference[referenceToken]) referenceToken = static_cast<int>(i);
        if (candidate[i] > candidate[compressedToken]) compressedToken = static_cast<int>(i);
    }
    CHECK(referenceToken == compressedToken);
    const auto stats = cache.GetStats();
    CHECK(stats.entries == TensorCount);
    CHECK(stats.hits == TensorCount);
    CHECK(stats.residentBytes < stats.entries * 1024u * sizeof(float));
    owners.clear();
    m = TinyModel{}; // release model-owned leases before asserting reclamation
    CHECK(cache.Trim(0) == stats.residentBytes);
    CHECK(cache.GetStats().residentBytes == 0);
    std::puts("SYNTHETIC_TRANSFORMER_COMPRESSED_E2E=PASS");
    return 0;
}
