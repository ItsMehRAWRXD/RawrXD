#include "rawrxd/compressed_block_codec_adapters.hpp"
#include "CompressedWeightStore.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <vector>

int main() {
    constexpr std::size_t bytes = 256 * 1024;
    std::vector<std::uint8_t> source(bytes);
    for (std::size_t i = 0; i < bytes; ++i)
        source[i] = static_cast<std::uint8_t>((i / 97) % 7);

    auto native = rawrxd::compression::makeNativeLzBlockStore(
        source.data(), source.size(), 16 * 1024, 32 * 1024);
    if (!native || native->logical_size() != source.size() ||
        native->compressed_size() >= source.size()) {
        std::cerr << "native LZ block-store admission failed or did not compress\n";
        return 1;
    }

    std::vector<std::uint8_t> range(37 * 1024);
    if (!native->read(11 * 1024, range.size(), range.data()) ||
        !std::equal(range.begin(), range.end(), source.begin() + 11 * 1024)) {
        std::cerr << "native LZ range roundtrip failed\n";
        return 2;
    }
    if (native->cached_decoded_bytes() > 32 * 1024) {
        std::cerr << "native LZ decoded cache exceeded budget\n";
        return 3;
    }

    auto zlib = rawrxd::compression::makeZlibBlockStore(
        source.data(), source.size(), 16 * 1024, 32 * 1024);
#if defined(RAWRXD_HAVE_ZLIB) && RAWRXD_HAVE_ZLIB
    if (!zlib || !zlib->read(11 * 1024, range.size(), range.data()) ||
        !std::equal(range.begin(), range.end(), source.begin() + 11 * 1024)) {
        std::cerr << "zlib block-store range roundtrip failed\n";
        return 4;
    }
    if (zlib->cached_decoded_bytes() > 32 * 1024) {
        std::cerr << "zlib decoded cache exceeded budget\n";
        return 5;
    }
#else
    if (zlib) {
        std::cerr << "zlib adapter must not claim support without a provider\n";
        return 6;
    }
#endif

    // The production Deep2 CompressedWeightStore now uses the same extracted
    // native LZ wire codec. This guards compatibility across the refactor.
    rawrxd::compression::CompressedWeightStore productionStore(
        32 * 1024, 16 * 1024, std::numeric_limits<std::size_t>::max());
    std::string storeError;
    if (!productionStore.addTensor("adapter-regression", source.data(),
            source.size(), &storeError, rawrxd::compression::GGML_TYPE_F32)) {
        std::cerr << "Deep2 CompressedWeightStore admission failed: " << storeError << "\\n";
        return 8;
    }
    std::vector<std::uint8_t> productionRange(8192);
    if (!productionStore.readRange("adapter-regression", 7000,
            productionRange.data(), productionRange.size(), &storeError) ||
        !std::equal(productionRange.begin(), productionRange.end(),
                    source.begin() + 7000)) {
        std::cerr << "Deep2 CompressedWeightStore native codec compatibility failed\\n";
        return 9;
    }

    // Incompressible data must be stored raw per block, never expanded.
    std::uint32_t state = 0x12345678u;
    for (auto& value : source) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        value = static_cast<std::uint8_t>(state);
    }
    auto rawFallback = rawrxd::compression::makeNativeLzBlockStore(
        source.data(), source.size(), 4096, 8192);
    if (!rawFallback || !rawFallback->read(4091, range.size(), range.data()) ||
        !std::equal(range.begin(), range.end(), source.begin() + 4091)) {
        std::cerr << "native raw-fallback range roundtrip failed\n";
        return 7;
    }

    std::cout << "compressed block codec adapters: PASS; native encoded bytes="
              << native->compressed_size()
              << "; decoded cache=" << native->cached_decoded_bytes() << "\n";
    return 0;
}
