#include "../../src/deep2/compression/StoredTensorMatvec.hpp"
#include <algorithm>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

using namespace rawrxd::compression;
int main() {
    // Two F16 rows, repeated 4096 times to ensure the encoded representation
    // actually saves RAM. The decoder cache is disabled: every matvec reads
    // from compressed resident blocks, with only bounded staging scratch.
    CompressedWeightStore store(0, 64);
    constexpr std::size_t cols = 32, rows = 256;
    std::vector<std::uint8_t> weights(rows * cols * 2, 0);
    for (std::size_t row = 0; row < rows; ++row) {
        for (std::size_t col = 0; col < cols; ++col) {
            const std::uint16_t half = col == 0 ? 0x3c00 : 0;
            const std::size_t offset = (row * cols + col) * 2;
            weights[offset] = std::uint8_t(half);
            weights[offset + 1] = std::uint8_t(half >> 8);
        }
    }
    std::string error;
    if (!store.addTensor("f16", weights.data(), weights.size(), &error,
                         GGML_TYPE_F16, true)) {
        std::cerr << "F16 compression failed: " << error << "\n";
        return EXIT_FAILURE;
    }
    const auto before = store.stats();
    assert(before.compressed_bytes < before.raw_bytes);
    std::vector<float> input(cols, 0.f), output(rows, 0.f);
    input[0] = 3.f;
    StoredTensorMatvec(store, "f16", ResidentWeightType::F16,
                       input.data(), output.data(), rows, cols, 3);
    for (float v : output) assert(v == 3.f);
    const auto after = store.stats();
    assert(after.cache_misses > 0);
    assert(after.cached_decoded_bytes == 0);
    assert(after.compressed_bytes < after.raw_bytes);
    // A second pass must remain numerically identical with no decoded cache.
    std::fill(output.begin(), output.end(), 0.f);
    StoredTensorMatvec(store, "f16", ResidentWeightType::F16,
                       input.data(), output.data(), rows, cols, 1024);
    for (float v : output) assert(v == 3.f);
    bool rejected = false;
    try {
        StoredTensorMatvec(store, "missing", ResidentWeightType::F16,
                           input.data(), output.data(), rows, cols);
    } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    // F32 storage is byte-exact (no implicit F32-to-F16 conversion).
    std::vector<std::uint8_t> f32(rows * cols * sizeof(float), 0);
    for (std::size_t row = 0; row < rows; ++row) {
        const float value = 1.25f;
        std::memcpy(f32.data() + row * cols * sizeof(float), &value, sizeof(value));
    }
    if (!store.addTensor("f32", f32.data(), f32.size(), &error,
                         GGML_TYPE_F32, true)) {
        std::cerr << "F32 compression failed: " << error << "\n";
        return EXIT_FAILURE;
    }
    StoredTensorMatvec(store, "f32", ResidentWeightType::F32,
                       input.data(), output.data(), rows, cols, 1);
    for (float v : output) assert(v == 3.75f);
    // A correctly sized tensor with the wrong GGML encoding must fail closed.
    rejected = false;
    try {
        StoredTensorMatvec(store, "f16", ResidentWeightType::F32,
                           input.data(), output.data(), rows, cols);
    } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);

    // Streaming F32->F16 conversion halves the tensor payload without
    // allocating a full converted tensor. The stored GGML type changes to F16
    // explicitly; this is opt-in lossy conversion, not byte-preserving codec.
    std::vector<float> f32Source(rows * cols, 1.25f);
    CompressedWeightStore convertedStore(0, 63); // odd block size tests byte-split reader callbacks
    assert(convertedStore.addTensorF32AsF16FromReader(
        "f32_as_f16", f32Source.data(), f32Source.size(), &error));
    assert(convertedStore.tensorType("f32_as_f16") == GGML_TYPE_F16);
    assert(convertedStore.tensorBytes("f32_as_f16") == f32Source.size() * 2);
    assert(convertedStore.tensorBytes("f32_as_f16") < f32Source.size() * sizeof(float));
    std::vector<float> convertedOutput(rows, 0.0f);
    StoredTensorMatvec(convertedStore, "f32_as_f16", ResidentWeightType::F16,
                       input.data(), convertedOutput.data(), rows, cols, 7);
    for (float v : convertedOutput) assert(v == 3.75f);

    // Q8_0 block layout: little-endian FP16 scale, then 32 signed bytes.
    // Zero-filled blocks compress well; a nonzero first value proves decoding.
    std::vector<std::uint8_t> q8(rows * 34, 0);
    for (std::size_t row = 0; row < rows; ++row) {
        q8[row * 34 + 1] = 0x3c; // FP16 scale 1.0
        q8[row * 34 + 2] = 2;    // first signed Q8 weight
    }
    if (!store.addTensor("q8", q8.data(), q8.size(), &error, 8u, true)) {
        std::cerr << "Q8_0 compression failed: " << error << "\n";
        return EXIT_FAILURE;
    }
    std::fill(output.begin(), output.end(), 0.f);
    StoredTensorMatvec(store, "q8", ResidentWeightType::Q8_0,
                       input.data(), output.data(), rows, cols, 1);
    for (float v : output) assert(v == 6.f);
    // Differential parity: the compressed store and direct GGUF byte reader
    // must produce identical outputs for both supported resident formats.
    struct DirectReader {
        const std::vector<std::uint8_t>& bytes;
        std::size_t size() const { return bytes.size(); }
        void read(std::size_t offset, std::uint8_t* out, std::size_t count) const {
            if (offset > bytes.size() || count > bytes.size() - offset)
                throw std::out_of_range("direct tensor bounds");
            std::memcpy(out, bytes.data() + offset, count);
        }
    };
    for (std::size_t scratch : {std::size_t(1), std::size_t(34), std::size_t(65536)}) {
        std::vector<float> expected(rows);
        ResidentMatvec(DirectReader{weights}, ResidentWeightType::F16,
                       input.data(), expected.data(), rows, cols, scratch);
        StoredTensorMatvec(store, "f16", ResidentWeightType::F16,
                           input.data(), output.data(), rows, cols, scratch);
        assert(output == expected);
        ResidentMatvec(DirectReader{q8}, ResidentWeightType::Q8_0,
                       input.data(), expected.data(), rows, cols, scratch);
        StoredTensorMatvec(store, "q8", ResidentWeightType::Q8_0,
                           input.data(), output.data(), rows, cols, scratch);
        assert(output == expected);
    }
    // Cross-block reads must match the uncompressed source exactly. This
    // checks offsets crossing the store's 64-byte encoded block boundaries.
    for (const auto& item : {std::pair<const char*, const std::vector<std::uint8_t>*>{"f16", &weights},
                             {"q8", &q8}}) {
        const auto& raw = *item.second;
        for (std::size_t offset : {std::size_t(0), std::size_t(1), std::size_t(63),
                                   std::size_t(64), std::size_t(65), std::size_t(127)}) {
            const std::size_t count = std::min(std::size_t(129), raw.size() - offset);
            std::vector<std::uint8_t> got(count);
            std::string readError;
            if (!store.readRange(item.first, offset, got.data(), count, &readError))
                throw std::runtime_error(readError);
            assert(std::equal(got.begin(), got.end(), raw.begin() + offset));
        }
    }
    // One decoded lease per 64-byte block, not one decode per scalar.
    CompressedWeightStore leaseStore(0, 64);
    if (!leaseStore.addTensor("lease", weights.data(), weights.size(), &error,
                              GGML_TYPE_F16, true))
        throw std::runtime_error("lease fixture compression failed: " + error);
    const auto missBefore = leaseStore.stats().cache_misses;
    StoredTensorMatvec(leaseStore, "lease", ResidentWeightType::F16,
                       input.data(), output.data(), rows, cols, 1);
    const auto missAfter = leaseStore.stats().cache_misses;
    assert(missAfter - missBefore == leaseStore.tensorBlocks("lease"));
    assert(leaseStore.stats().cached_decoded_bytes == 0);

    // Failed admission must not partially publish a tensor or alter counters.
    const auto admissionBefore = leaseStore.stats();
    std::string budgetError;
    assert(!leaseStore.addTensor("over_budget", weights.data(), weights.size(),
                                 &budgetError, GGML_TYPE_F16, false, 1));
    assert(!leaseStore.contains("over_budget"));
    const auto admissionAfter = leaseStore.stats();
    assert(admissionAfter.tensors == admissionBefore.tensors);
    assert(admissionAfter.blocks == admissionBefore.blocks);
    assert(admissionAfter.compressed_bytes == admissionBefore.compressed_bytes);
    assert(!budgetError.empty());

    // Reader-backed ingestion compresses one bounded block at a time; it never
    // asks the source to materialize the complete tensor.
    struct ReaderFixture { const std::vector<std::uint8_t>* bytes; std::size_t calls=0; };
    ReaderFixture readerFixture{&weights};
    CompressedWeightStore readerStore(0, 64);
    assert(readerStore.addTensorFromReader("reader", weights.size(),
        [](void* opaque, std::size_t offset, void* destination, std::size_t length) -> bool {
            auto* fixture = static_cast<ReaderFixture*>(opaque);
            ++fixture->calls;
            if (offset > fixture->bytes->size() || length > fixture->bytes->size() - offset) return false;
            std::memcpy(destination, fixture->bytes->data() + offset, length);
            return true;
        }, &readerFixture, &error, GGML_TYPE_F16, true));
    assert(readerFixture.calls == (weights.size() + 63) / 64);
    std::vector<std::uint8_t> readerRoundtrip(weights.size());
    assert(readerStore.readRange("reader", 0, readerRoundtrip.data(), readerRoundtrip.size(), &error));
    assert(readerRoundtrip == weights);
    ReaderFixture failingFixture{&weights};
    assert(!readerStore.addTensorFromReader("failed_reader", weights.size(),
        [](void* opaque, std::size_t offset, void* destination, std::size_t length) -> bool {
            auto* fixture = static_cast<ReaderFixture*>(opaque);
            if (offset >= 128) return false;
            std::memcpy(destination, fixture->bytes->data() + offset, length);
            return true;
        }, &failingFixture, &error, GGML_TYPE_F16, false));
    assert(!readerStore.contains("failed_reader"));

    // The store-wide encoded residency cap is shared across tensors and
    // enforced under the same lock as publication, including concurrent
    // admission attempts.
    CompressedWeightStore cappedStore(0, 64, 4096);
    assert(cappedStore.addTensor("first", weights.data(), weights.size(), &error,
                                 GGML_TYPE_F16, false, 1024));
    assert(cappedStore.stats().compressed_bytes <= 4096);
    assert(!cappedStore.addTensor("second", weights.data(), weights.size(), &budgetError,
                                  GGML_TYPE_F16, false, 1024));
    assert(!cappedStore.contains("second"));
    assert(cappedStore.stats().compressed_bytes <= 32);

    const auto finalStats = store.stats();
    assert(finalStats.compressed_bytes < finalStats.raw_bytes);
    assert(finalStats.cached_decoded_bytes == 0);
    return 0;
}
