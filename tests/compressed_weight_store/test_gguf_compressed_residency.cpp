#include "../../src/deep2/compression/GGUFCompressedResidency.hpp"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

int main() {
    std::vector<std::uint8_t> source(8192, 0);
    for (std::size_t i = 0; i < source.size(); i += 64) {
        source[i] = 0x3c;
        source[i + 1] = 0x00;
    }
    Deep2::GGUFTensor tensor;
    tensor.name = "blk.0.attn.weight";
    tensor.type = static_cast<Deep2::GGMLType>(1); // GGML_TYPE_F16
    tensor.data = source.data();
    tensor.sizeBytes = source.size();
    tensor.mapped = true;

    rawrxd::compression::CompressedWeightStore store(0, 256);
    std::string error;
    assert(rawrxd::compression::StoreMappedGGUFTensor(store, tensor, &error, true));
    assert(store.tensorType(tensor.name) == 1u);
    assert(store.stats().compressed_bytes < source.size());

    std::vector<std::uint8_t> restored(source.size());
    assert(store.readRange(tensor.name, 0, restored.data(), restored.size(), &error));
    assert(restored == source);
    return 0;
}
