#include "native_resident_typed_matvec.hpp"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "E2E CHECK failed at %d: %s\\n", __LINE__, #x); return 1; } } while (false)

using rawrxd::compression::ResidentCompressedTensor;

static std::uint16_t to_half(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const std::uint32_t sign = (bits >> 16) & 0x8000u;
    const std::uint32_t exp = (bits >> 23) & 0xffu;
    const std::uint32_t mantissa = bits & 0x7fffffu;
    if (exp == 0xffu) return static_cast<std::uint16_t>(sign | 0x7c00u | (mantissa ? 0x0200u : 0u));
    const int halfExp = static_cast<int>(exp) - 127 + 15;
    if (halfExp >= 31) return static_cast<std::uint16_t>(sign | 0x7c00u);
    if (halfExp <= 0) {
        if (halfExp < -10) return static_cast<std::uint16_t>(sign);
        const std::uint32_t m = mantissa | 0x800000u;
        const unsigned shift = static_cast<unsigned>(14 - halfExp);
        return static_cast<std::uint16_t>(sign | ((m + (1u << (shift - 1))) >> shift));
    }
    return static_cast<std::uint16_t>(sign |
        (static_cast<std::uint32_t>(halfExp) << 10) |
        ((mantissa + 0x1000u) >> 13));
}

static void append_half(std::vector<std::uint8_t>& out, float value) {
    const auto h = to_half(value);
    out.push_back(static_cast<std::uint8_t>(h & 0xffu));
    out.push_back(static_cast<std::uint8_t>(h >> 8));
}

static ResidentCompressedTensor load_resident(
    const std::vector<std::uint8_t>& bytes, const std::string& name,
    std::size_t rangeOffset = 0,
    std::size_t rangeBytes = (std::numeric_limits<std::size_t>::max)()) {
    const auto path = name + ".synthetic.gguf.tensor";
    {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file) throw std::runtime_error("cannot create synthetic tensor fixture");
        file.write(reinterpret_cast<const char*>(bytes.data()),
                   static_cast<std::streamsize>(bytes.size()));
        if (!file) throw std::runtime_error("cannot write synthetic tensor fixture");
    }
    if (rangeBytes == (std::numeric_limits<std::size_t>::max)()) {
        if (rangeOffset > bytes.size()) throw std::out_of_range("synthetic tensor range offset");
        rangeBytes = bytes.size() - rangeOffset;
    }
    ResidentCompressedTensor resident(64);
    {
        rawrxd::compression::FileTensorReader source(path, rangeOffset, rangeBytes);
        resident.load(source);
    }
    // Close the file before removal; required by Windows sharing semantics.
    std::remove(path.c_str());
    return resident;
}

int main() {
    constexpr std::size_t hidden = 32;
    // Synthetic model: token embedding -> F16 identity projection -> Q4_0
    // output projection. The expected logits are independently computed below.
    std::vector<std::uint8_t> embeddingBytes;
    // Token 0 is all zeros; token 1 is [1, 0.5, 0, ...].
    for (std::size_t i = 0; i < hidden; ++i) append_half(embeddingBytes, 0.0f);
    for (std::size_t i = 0; i < hidden; ++i)
        append_half(embeddingBytes, i == 0 ? 1.0f : (i == 1 ? 0.5f : 0.0f));

    std::vector<std::uint8_t> identityBytes;
    identityBytes.reserve(hidden * hidden * 2);
    for (std::size_t row = 0; row < hidden; ++row)
        for (std::size_t col = 0; col < hidden; ++col)
            append_half(identityBytes, row == col ? 1.0f : 0.0f);

    std::vector<std::uint8_t> outputBytes(2 * 18, 0);
    for (std::size_t row = 0; row < 2; ++row) {
        const std::size_t base = row * 18;
        outputBytes[base] = 0x00; outputBytes[base + 1] = 0x3c; // scale = 1
        const std::uint8_t packed = static_cast<std::uint8_t>(row == 0 ? 0x99u : 0x77u);
        std::fill(outputBytes.begin() + static_cast<std::ptrdiff_t>(base + 2),
                  outputBytes.begin() + static_cast<std::ptrdiff_t>(base + 18), packed);
    }

    // Stream each selected token row independently from the two-row
    // embedding tensor. No full vocabulary matrix is retained by either view.
    const auto embeddingToken0 = load_resident(
        embeddingBytes, "embedding_token0", 0, hidden * 2);
    const auto embeddingToken1 = load_resident(
        embeddingBytes, "embedding_token1", hidden * 2, hidden * 2);
    const auto projection = load_resident(identityBytes, "projection");
    const auto output = load_resident(outputBytes, "output");
    CHECK(embeddingToken0.size() == hidden * 2);
    CHECK(embeddingToken1.size() == hidden * 2);
    CHECK(projection.size() == hidden * hidden * 2);
    CHECK(output.size() == 2 * 18);
    CHECK(embeddingToken0.compressed_bytes() < embeddingToken0.size());
    CHECK(embeddingToken1.compressed_bytes() < embeddingToken1.size());
    CHECK(projection.compressed_bytes() < projection.size());

    // The runtime fetches the requested token row, not the first prompt row
    // repeatedly. Token 0 is all zeros; token 1 is [1, 0.5, 0, ...].
    const auto token0Hidden = rawrxd::compression::resident_f16_row(
        embeddingToken0, 0, 1, hidden, 16);
    CHECK(token0Hidden.size() == hidden);
    for (float value : token0Hidden) CHECK(value == 0.0f);
    const auto hidden0 = rawrxd::compression::resident_f16_row(
        embeddingToken1, 0, 1, hidden, 16);
    CHECK(hidden0.size() == hidden);
    CHECK(hidden0[0] == 1.0f && hidden0[1] == 0.5f);
    for (std::size_t i = 2; i < hidden; ++i) CHECK(hidden0[i] == 0.0f);

    // First model operator: F16 projection from compressed resident weights.
    const auto hidden1 = rawrxd::compression::resident_f16_matvec(
        projection, hidden0.data(), hidden, hidden, 64);
    CHECK(hidden1.size() == hidden);
    for (std::size_t i = 0; i < hidden; ++i)
        CHECK(std::fabs(hidden1[i] - hidden0[i]) < 1e-7f);

    // Second model operator: Q4_0 output projection from compressed resident weights.
    const auto logits = rawrxd::compression::resident_q4_0_matvec(
        output, hidden1.data(), 2, hidden, 18);
    CHECK(logits.size() == 2);

    // Independent scalar reference: row0 has +1 weights; row1 has -1 weights.
    double sum = 0.0;
    for (float value : hidden0) sum += static_cast<double>(value);
    const float expected[] = {static_cast<float>(sum), static_cast<float>(-sum)};
    CHECK(std::fabs(logits[0] - expected[0]) < 1e-6f);
    CHECK(std::fabs(logits[1] - expected[1]) < 1e-6f);

    // Concurrent inference over immutable resident tensors must be deterministic.
    std::vector<std::thread> workers;
    std::vector<int> workerResults(8, 0);
    for (std::size_t worker = 0; worker < workerResults.size(); ++worker) {
        workers.emplace_back([&, worker] {
            try {
                const auto h = rawrxd::compression::resident_f16_matvec(
                    projection, hidden0.data(), hidden, hidden, 64);
                const auto y = rawrxd::compression::resident_q4_0_matvec(
                    output, h.data(), 2, hidden, 18);
                workerResults[worker] =
                    (std::fabs(y[0] - expected[0]) < 1e-6f &&
                     std::fabs(y[1] - expected[1]) < 1e-6f) ? 1 : -1;
            } catch (...) { workerResults[worker] = -1; }
        });
    }
    for (auto& worker : workers) worker.join();
    for (int result : workerResults) CHECK(result == 1);

    // A bounded staging budget smaller than one Q4_0 block must fail closed.
    bool rejected = false;
    try {
        (void)rawrxd::compression::resident_q4_0_matvec(
            output, hidden1.data(), 2, hidden, 17);
    } catch (const std::invalid_argument&) { rejected = true; }
    CHECK(rejected);

    std::puts("SYNTHETIC_MODEL_E2E=PASS");
    std::puts("OPERATORS=range_backed_embedding_f16,f16_projection,q4_0_logits");
    std::puts("CONCURRENT_REQUESTS=8");
    return 0;
}
