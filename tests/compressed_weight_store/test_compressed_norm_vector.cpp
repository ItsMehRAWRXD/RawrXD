#include "../../src/deep2/compression/CompressedWeightStore.hpp"
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#define REQUIRE(x) do { if (!(x)) return __LINE__; } while (false)

int main() {
    using rawrxd::compression::CompressedWeightStore;
    // A repeated F32 RMSNorm vector should remain byte-exact and be readable
    // from compressed backing without retaining a decoded tensor cache.
    std::vector<float> f32(4096, 1.0f);
    CompressedWeightStore store(0, 64, 1u << 20);
    std::string error;
    REQUIRE(store.addTensor("output_norm.weight", f32.data(),
                            f32.size() * sizeof(float), &error, 0u, true));
    REQUIRE(store.tensorType("output_norm.weight") == 0u);
    std::vector<std::uint8_t> f32Prefix(128 * sizeof(float));
    REQUIRE(store.readRange("output_norm.weight", 0, f32Prefix.data(),
                            f32Prefix.size(), &error));
    REQUIRE(std::memcmp(f32Prefix.data(), f32.data(), f32Prefix.size()) == 0);

    // F16 norm vector follows the same byte-preserving path.
    std::vector<std::uint16_t> f16(2048, 0x3c00u); // IEEE binary16 1.0
    REQUIRE(store.addTensor("blk.0.attn_norm.weight", f16.data(),
                            f16.size() * sizeof(std::uint16_t), &error, 1u, true));
    REQUIRE(store.tensorType("blk.0.attn_norm.weight") == 1u);
    std::vector<std::uint8_t> f16Prefix(64 * sizeof(std::uint16_t));
    REQUIRE(store.readRange("blk.0.attn_norm.weight", 0, f16Prefix.data(),
                            f16Prefix.size(), &error));
    REQUIRE(std::memcmp(f16Prefix.data(), f16.data(), f16Prefix.size()) == 0);

    // Mamba-2's custom selective-scan consumers use F32 vectors. They
    // retain the same exact-range contract while their consumer-side adapter
    // materializes only the current invocation's working vector.
    std::vector<float> ssmNorm(1024, 0.75f);
    REQUIRE(store.addTensor("blk.0.ssm_norm", ssmNorm.data(),
                            ssmNorm.size() * sizeof(float), &error, 0u, true));
    std::vector<std::uint8_t> ssmPrefix(128 * sizeof(float));
    REQUIRE(store.readRange("blk.0.ssm_norm", 64 * sizeof(float),
                            ssmPrefix.data(), ssmPrefix.size(), &error));
    REQUIRE(std::memcmp(ssmPrefix.data(),
                        reinterpret_cast<const std::uint8_t*>(ssmNorm.data()) + 64 * sizeof(float),
                        ssmPrefix.size()) == 0);

    // Attention projection biases are also range-consumed by Q/K/V
    // dispatch after the consumer migration.
    std::vector<float> qBias(512, 0.125f);
    REQUIRE(store.addTensor("blk.0.attn_q.bias", qBias.data(),
                            qBias.size() * sizeof(float), &error, 0u, true));
    std::vector<std::uint8_t> biasPrefix(32 * sizeof(float));
    REQUIRE(store.readRange("blk.0.attn_q.bias", 16 * sizeof(float),
                            biasPrefix.data(), biasPrefix.size(), &error));
    REQUIRE(std::memcmp(biasPrefix.data(),
                        reinterpret_cast<const std::uint8_t*>(qBias.data()) + 16 * sizeof(float),
                        biasPrefix.size()) == 0);

    // Read a nonzero range to ensure offset-based lazy access works for norm
    // vectors, not just their first block.
    std::vector<std::uint8_t> tail(32 * sizeof(float));
    const std::size_t tailOffset = (f32.size() - 32) * sizeof(float);
    REQUIRE(store.readRange("output_norm.weight", tailOffset, tail.data(),
                            tail.size(), &error));
    REQUIRE(std::memcmp(tail.data(), reinterpret_cast<const std::uint8_t*>(f32.data()) +
                        tailOffset, tail.size()) == 0);

    const auto stats = store.stats();
    REQUIRE(stats.tensors == 4);
    REQUIRE(stats.compressed_bytes < stats.raw_bytes);
    REQUIRE(stats.cached_decoded_bytes == 0);
    return 0;
}
