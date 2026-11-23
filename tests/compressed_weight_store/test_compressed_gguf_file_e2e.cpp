#include "../../src/deep2/compression/CompressedGGUFModel.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <vector>

namespace {
void appendU32(std::vector<std::uint8_t>& out, std::uint32_t value) {
    for (unsigned i = 0; i != 4; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
void appendU64(std::vector<std::uint8_t>& out, std::uint64_t value) {
    for (unsigned i = 0; i != 8; ++i)
        out.push_back(static_cast<std::uint8_t>(value >> (i * 8)));
}
void appendString(std::vector<std::uint8_t>& out, const std::string& value) {
    appendU64(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}
std::vector<std::uint8_t> makeSyntheticGGUF() {
    constexpr std::uint32_t kGGUFMagic = 0x46554747u; // "GGUF" on disk
    constexpr std::size_t kRows = 32;
    constexpr std::size_t kCols = 32;
    std::vector<std::uint8_t> bytes;
    appendU32(bytes, kGGUFMagic);
    appendU32(bytes, 3); // GGUF v3
    appendU64(bytes, 1); // tensor count
    appendU64(bytes, 0); // metadata count
    appendString(bytes, "synthetic.weight");
    appendU32(bytes, 2); // dimensions
    appendU64(bytes, kCols);
    appendU64(bytes, kRows);
    appendU32(bytes, 1); // GGML_TYPE_F16
    appendU64(bytes, 0); // tensor-relative offset

    // GGUF tensor data starts at a 32-byte boundary by default.
    while ((bytes.size() & 31u) != 0) bytes.push_back(0);
    for (std::size_t i = 0; i < kRows * kCols; ++i) {
        bytes.push_back(0x00); // little-endian IEEE F16 1.0
        bytes.push_back(0x3c);
    }
    return bytes;
}
struct TempFile {
    std::filesystem::path path;
    explicit TempFile(const char* suffix) {
        const auto stamp = std::chrono::high_resolution_clock::now()
                               .time_since_epoch().count();
        path = std::filesystem::temp_directory_path() /
            (std::string("rawrxd_synthetic_gguf_") + std::to_string(stamp) + suffix);
    }
    ~TempFile() {
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
    void write(const std::vector<std::uint8_t>& bytes) const {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        assert(file.good());
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        assert(file.good());
    }
};
} // namespace

int main() {
    constexpr std::size_t rows = 32;
    constexpr std::size_t cols = 32;
    constexpr const char* tensorName = "synthetic.weight";

    // Exercise the real file parser and mmap lifetime, not only a fabricated
    // GGUFTensor descriptor. The loader owns the mapping during synchronous
    // compressed admission; the published model must then own encoded blocks.
    auto fixture = makeSyntheticGGUF();
    TempFile good(".gguf");
    good.write(fixture);

    Deep2::GGUFLoader loader;
    assert(loader.load(good.path.string()));
    assert(loader.loaded());
    assert(loader.version() == 3);
    assert(loader.tensorCount() == 1);
    const auto* mapped = loader.getTensor(tensorName);
    assert(mapped && mapped->mapped && mapped->sizeBytes == rows * cols * 2);

    rawrxd::compression::CompressedGGUFModel::Options options;
    options.decoded_cache_bytes = 0; // prove inference can run without a decoded cache
    options.encoded_residency_bytes = 64 * 1024;
    options.block_bytes = cols * 2;  // one independently decoded block per row
    options.require_savings = true;
    rawrxd::compression::CompressedGGUFModel model(options);
    std::string error;
    std::string failedTensor;
    assert(model.load(loader, &error, &failedTensor));
    assert(error.empty());
    assert(failedTensor.empty());
    assert(model.loaded() && model.tensorCount() == 1);
    assert(model.contains(tensorName));

    const auto admitted = model.stats();
    assert(admitted.tensors == 1);
    assert(admitted.raw_bytes == rows * cols * 2);
    assert(admitted.compressed_bytes < admitted.raw_bytes);
    assert(admitted.cached_decoded_bytes == 0);

    // A token-embedding style access decodes exactly one row, not the matrix.
    std::vector<std::uint8_t> row(cols * 2);
    assert(model.readTensorRange(tensorName, 7 * row.size(), row.data(), row.size(), &error));
    for (std::size_t i = 0; i < row.size(); i += 2)
        assert(row[i] == 0x00 && row[i + 1] == 0x3c);
    const auto afterRow = model.stats();
    assert(afterRow.cache_misses == 1);
    assert(afterRow.cached_decoded_bytes == 0);

    // Run the model-owned CPU inference entry point from the actual GGUF file.
    // The synthetic matrix is all ones, so each output is sum(input).
    std::vector<float> input(cols, 1.0f);
    std::vector<float> output(rows, -1.0f);
    assert(model.matvec(tensorName, input.data(), output.data(), 17, &error));
    assert(error.empty());
    for (float value : output) assert(value == static_cast<float>(cols));
    const auto afterInference = model.stats();
    assert(afterInference.compressed_bytes == admitted.compressed_bytes);
    assert(afterInference.cached_decoded_bytes == 0);
    assert(afterInference.cache_misses >= afterRow.cache_misses + rows);

    // Failed inference is transactional: invalid activations cannot publish a
    // partially written output vector to the caller.
    input[0] = std::numeric_limits<float>::quiet_NaN();
    std::fill(output.begin(), output.end(), 123.0f);
    assert(!model.matvec(tensorName, input.data(), output.data(), 31, &error));
    assert(!error.empty());
    for (float value : output) assert(value == 123.0f);
    input[0] = 1.0f;

    // Once the source mapping is closed, the compressed model remains usable:
    // this proves it did not retain a dangling pointer into GGUFLoader memory.
    loader.close();
    assert(!loader.loaded());
    std::fill(output.begin(), output.end(), 0.0f);
    assert(model.matvec(tensorName, input.data(), output.data(), 31, &error));
    for (float value : output) assert(value == static_cast<float>(cols));

    // A truncated GGUF must fail closed before a replacement is published.
    TempFile truncated(".gguf");
    fixture.pop_back();
    truncated.write(fixture);
    Deep2::GGUFLoader broken;
    assert(!broken.load(truncated.path.string()));
    assert(!broken.loaded());
    assert(model.loaded() && model.contains(tensorName));
    return 0;
}
