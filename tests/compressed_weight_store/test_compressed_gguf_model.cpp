#include "../../src/deep2/compression/CompressedGGUFModel.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using rawrxd::compression::CompressedGGUFModel;

static Deep2::GGUFTensor make_f16(const std::string& name,
                                  std::vector<std::uint8_t>& bytes) {
    Deep2::GGUFTensor tensor;
    tensor.name = name;
    tensor.type = static_cast<Deep2::GGMLType>(1);
    tensor.shape = {2, 2};
    tensor.data = bytes.data();
    tensor.sizeBytes = bytes.size();
    tensor.mapped = true;
    return tensor;
}

int main() {
    std::vector<std::uint8_t> weights = {
        0x00, 0x3c, 0x00, 0xc0,
        0x00, 0x38, 0x00, 0x40
    }; // [[1,-2],[0.5,2]] in F16
    CompressedGGUFModel::Options options;
    options.decoded_cache_bytes = 0; // exercise request-held block leases
    options.block_bytes = 4;
    CompressedGGUFModel model(options);
    std::string error, failed;

    auto tensor = make_f16("blk.0.attn.weight", weights);
    assert(model.loadMappedTensors({tensor}, &error, &failed));
    assert(model.loaded() && model.tensorCount() == 1);
    assert(model.contains(tensor.name));
    assert(model.stats().tensors == 1);
    assert(model.stats().cached_decoded_bytes == 0);

    std::uint8_t roundtrip[8]{};
    assert(model.readTensorRange(tensor.name, 0, roundtrip, sizeof(roundtrip), &error));
    assert(std::memcmp(roundtrip, weights.data(), sizeof(roundtrip)) == 0);

    const float input[] = {1.f, 2.f};
    float output[] = {-99.f, -99.f};
    assert(model.matvec(tensor.name, input, output, 2, &error));
    assert(output[0] == -3.f && output[1] == 4.5f);

    // A failed replacement must not destroy the previously published model.
    Deep2::GGUFTensor invalid;
    invalid.name = "blk.1.bad.weight";
    invalid.type = static_cast<Deep2::GGMLType>(1);
    invalid.shape = {2, 2};
    invalid.data = nullptr;
    invalid.sizeBytes = 8;
    assert(!model.loadMappedTensors({tensor, invalid}, &error, &failed));
    assert(failed == invalid.name);
    assert(model.loaded() && model.tensorCount() == 1);
    std::fill(std::begin(output), std::end(output), -99.f);
    assert(model.matvec(tensor.name, input, output, 2, &error));
    assert(output[0] == -3.f && output[1] == 4.5f);

    // Unsupported quantization is readable byte-for-byte but not silently
    // interpreted by a mismatched scalar kernel.
    auto unsupported = tensor;
    unsupported.name = "blk.0.unsupported";
    unsupported.type = static_cast<Deep2::GGMLType>(2);
    assert(model.loadMappedTensors({unsupported}, &error, &failed));
    assert(!model.matvec(unsupported.name, input, output, 2, &error));
    assert(error.find("no resident matvec kernel") != std::string::npos);

    // Unload publishes an empty state; in-flight readers can retain snapshots.
    model.unload();
    assert(!model.loaded() && model.tensorCount() == 0);
    assert(!model.readTensorRange(tensor.name, 0, roundtrip, 1, &error));
}
