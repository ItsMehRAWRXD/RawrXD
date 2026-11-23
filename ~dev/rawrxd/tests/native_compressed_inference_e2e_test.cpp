#include "NativeTensorCompression.hpp"
#include "TensorResidencyCache.hpp"

#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#define CHECK(expr) do { if (!(expr)) { \
    std::fprintf(stderr, "E2E check failed at line %d: %s\\n", __LINE__, #expr); \
    return __LINE__; \
} } while (0)

// Synthetic three-layer linear model. The reference path reads ordinary F32
// weights; the candidate path retains encoded weights and decodes one row at
// a time, matching the CPU kernel's bounded working-set contract.
int main() {
    constexpr std::size_t kLayers = 3;
    constexpr std::size_t kRows = 96;
    constexpr std::size_t kCols = 64;
    constexpr std::size_t kElements = kRows * kCols;

    std::vector<float> input(kCols);
    for (std::size_t c = 0; c < kCols; ++c)
        input[c] = static_cast<float>(static_cast<int>(c % 17) - 8) * 0.125f;

    std::vector<std::vector<float>> model(kLayers, std::vector<float>(kElements));
    std::vector<std::shared_ptr<const Deep2::TensorResidencyCache::Storage>> encoded;
    Deep2::TensorResidencyCache cache(kLayers * kElements * sizeof(float));

    for (std::size_t layer = 0; layer < kLayers; ++layer) {
        for (std::size_t i = 0; i < kElements; ++i) {
            const int q = static_cast<int>((i * 13 + layer * 7) % 31) - 15;
            // Binary fractions are exactly representable in IEEE F16.
            model[layer][i] = static_cast<float>(q) * 0.125f;
        }
        auto storage = Deep2::TensorResidencyCache::Storage::Build(
            model[layer].data(), model[layer].size(), 0.0f, 256);
        CHECK(storage.storedBytes() == kElements * sizeof(std::uint16_t));
        CHECK(storage.residentBytes() < storage.originalBytes());
        auto shared = std::make_shared<const Deep2::TensorResidencyCache::Storage>(
            std::move(storage));
        CHECK(cache.Insert("synthetic.layer." + std::to_string(layer), shared));
        encoded.push_back(std::move(shared));
    }

    std::vector<float> reference = input;
    std::vector<float> candidate = input;
    std::vector<float> row(kCols);
    for (std::size_t layer = 0; layer < kLayers; ++layer) {
        std::vector<float> expected(kRows, 0.0f);
        std::vector<float> actual(kRows, 0.0f);
        for (std::size_t r = 0; r < kRows; ++r) {
            for (std::size_t c = 0; c < kCols; ++c)
                expected[r] += model[layer][r * kCols + c] * reference[c];
        }

        auto lease = cache.Acquire("synthetic.layer." + std::to_string(layer));
        CHECK(static_cast<bool>(lease));
        CHECK(lease->elements() == kElements);
        for (std::size_t r = 0; r < kRows; ++r) {
            lease->ReadRange(r * kCols, kCols, row.data());
            for (std::size_t c = 0; c < kCols; ++c)
                actual[r] += row[c] * candidate[c];
        }
        for (std::size_t r = 0; r < kRows; ++r)
            CHECK(std::fabs(actual[r] - expected[r]) <= 1.0e-6f);
        reference.swap(expected);
        candidate.swap(actual);
    }

    CHECK(reference.size() == candidate.size());
    for (std::size_t i = 0; i < reference.size(); ++i)
        CHECK(std::fabs(reference[i] - candidate[i]) <= 1.0e-6f);

    const auto stats = cache.GetStats();
    CHECK(stats.entries == kLayers);
    CHECK(stats.hits == kLayers);
    CHECK(stats.residentBytes < kLayers * kElements * sizeof(float));
    CHECK(cache.Trim(0) == 0); // shared owners/leases still pin encoded payloads
    encoded.clear();
    CHECK(cache.Trim(0) == stats.residentBytes);
    CHECK(cache.GetStats().residentBytes == 0);

    std::puts("SYNTHETIC_COMPRESSED_INFERENCE_E2E=PASS");
    return 0;
}
