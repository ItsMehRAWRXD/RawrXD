#include "../../src/deep2/compression/CompressedGGUFModel.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cmath>
#include <cstdint>
#include <string>
#include <vector>

using rawrxd::compression::CompressedGGUFModel;
using rawrxd::compression::floatToHalfRNE;

static std::vector<std::uint8_t> pack_f16(const std::vector<float>& values) {
    std::vector<std::uint8_t> bytes(values.size() * sizeof(std::uint16_t));
    for (std::size_t i = 0; i < values.size(); ++i) {
        const auto half = floatToHalfRNE(values[i]);
        bytes[2 * i] = static_cast<std::uint8_t>(half & 0xffu);
        bytes[2 * i + 1] = static_cast<std::uint8_t>(half >> 8);
    }
    return bytes;
}

static Deep2::GGUFTensor tensor(const char* name, std::vector<std::uint8_t>& bytes,
                                std::int64_t columns, std::int64_t rows) {
    Deep2::GGUFTensor result;
    result.name = name;
    result.type = static_cast<Deep2::GGMLType>(1); // GGML_TYPE_F16
    result.shape = {columns, rows};
    result.data = bytes.data();
    result.sizeBytes = bytes.size();
    result.mapped = true;
    return result;
}

int main() {
    // A deterministic two-layer model:
    //   h = ReLU([[1,0],[0,1],[1,1]] * [2,3]) = [2,3,5]
    //   y = [[1,1,0],[0,1,1]] * h = [5,8]
    // All weights enter as GGUF F16 descriptors, are compressed into the
    // resident store, and are consumed in bounded matvec staging windows.
    auto layer0 = pack_f16({1.f, 0.f, 0.f, 1.f, 1.f, 1.f});
    auto layer1 = pack_f16({1.f, 1.f, 0.f, 0.f, 1.f, 1.f});
    auto first = tensor("blk.0.ffn_up.weight", layer0, 2, 3);
    auto second = tensor("blk.0.ffn_down.weight", layer1, 3, 2);

    CompressedGGUFModel::Options options;
    options.decoded_cache_bytes = 0;
    options.block_bytes = 8; // force inference to cross compressed block boundaries
    options.require_savings = false;
    CompressedGGUFModel model(options);
    std::string error, failed;
    assert(model.loadMappedTensors({first, second}, &error, &failed));
    assert(model.loaded() && model.tensorCount() == 2);
    assert(model.contains(first.name) && model.contains(second.name));
    assert(model.stats().cached_decoded_bytes == 0);

    const float input[2] = {2.f, 3.f};
    float hidden[3] = {};
    float output[2] = {};
    assert(model.matvec(first.name, input, hidden, 8, &error));
    for (float& value : hidden) if (value < 0.f) value = 0.f;
    assert(model.matvec(second.name, hidden, output, 8, &error));
    assert(std::fabs(hidden[0] - 2.f) < 1e-6f);
    assert(std::fabs(hidden[1] - 3.f) < 1e-6f);
    assert(std::fabs(hidden[2] - 5.f) < 1e-6f);
    assert(std::fabs(output[0] - 5.f) < 1e-6f);
    assert(std::fabs(output[1] - 8.f) < 1e-6f);

    // No full decoded model is retained between operations.
    assert(model.stats().cached_decoded_bytes == 0);
    model.unload();
    assert(!model.loaded() && model.tensorCount() == 0);
    assert(!model.matvec(first.name, input, hidden, 8, &error));
    return 0;
}
