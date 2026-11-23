#include "../../src/deep2/compression/CompressedGGUFModel.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <algorithm>
#include <cassert>
#include <iterator>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <atomic>
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

    // Concurrent reload publishes whole immutable states. Every inference
    // observes either the old tensor or the replacement, never a mixed store.
    std::vector<std::uint8_t> alternate_weights = {
        0x00, 0x40, 0x00, 0xc4,
        0x00, 0x3c, 0x00, 0x44
    }; // [[2,-4],[1,4]] in F16
    auto alternate = make_f16(tensor.name, alternate_weights);
    std::atomic<bool> inference_failed{false};
    std::vector<std::thread> readers;
    for (int worker = 0; worker < 3; ++worker) {
        readers.emplace_back([&] {
            for (int i = 0; i < 300; ++i) {
                float observed[2] = {};
                std::string read_error;
                if (!model.matvec(tensor.name, input, observed, 2, &read_error)) {
                    inference_failed.store(true, std::memory_order_relaxed);
                    continue;
                }
                const bool old_state = observed[0] == -3.f && observed[1] == 4.5f;
                const bool new_state = observed[0] == -6.f && observed[1] == 9.f;
                if (!old_state && !new_state)
                    inference_failed.store(true, std::memory_order_relaxed);
            }
        });
    }
    for (int i = 0; i < 40; ++i) {
        const auto& next = (i & 1) ? tensor : alternate;
        if (!model.loadMappedTensors({next}, &error, &failed))
            inference_failed.store(true, std::memory_order_relaxed);
    }
    for (auto& reader : readers) reader.join();
    assert(!inference_failed.load(std::memory_order_relaxed));
    assert(model.loadMappedTensors({tensor}, &error, &failed));

    // A store-wide encoded budget rejects a complete replacement atomically.
    CompressedGGUFModel::Options bounded_options;
    bounded_options.decoded_cache_bytes = 0;
    bounded_options.block_bytes = 4;
    bounded_options.encoded_residency_bytes = 8;
    CompressedGGUFModel bounded_model(bounded_options);
    assert(bounded_model.loadMappedTensors({tensor}, &error, &failed));
    auto second_tensor = make_f16("blk.1.attn.weight", weights);
    assert(!bounded_model.loadMappedTensors({tensor, second_tensor}, &error, &failed));
    assert(failed == second_tensor.name);
    assert(bounded_model.tensorCount() == 1 && bounded_model.contains(tensor.name));

    // The model owner exposes only the resident kernels it can execute;
    // verify the F32 and native Q8_0 paths in addition to F16 above.
    std::vector<float> f32_values = {1.f, -2.f, 0.5f, 2.f};
    Deep2::GGUFTensor f32_tensor;
    f32_tensor.name = "blk.0.f32.weight";
    f32_tensor.type = static_cast<Deep2::GGMLType>(0);
    f32_tensor.shape = {2, 2};
    f32_tensor.data = f32_values.data();
    f32_tensor.sizeBytes = f32_values.size() * sizeof(float);
    assert(model.loadMappedTensors({f32_tensor}, &error, &failed));
    float f32_output[2] = {};
    assert(model.matvec(f32_tensor.name, input, f32_output, 8, &error));
    assert(f32_output[0] == -3.f && f32_output[1] == 4.5f);

    std::vector<std::uint8_t> q8_bytes(68, 0);
    q8_bytes[0] = 0x00; q8_bytes[1] = 0x3c; // row 0 scale = 1
    for (std::size_t i = 0; i < 32; ++i) q8_bytes[2 + i] = 1;
    q8_bytes[34] = 0x00; q8_bytes[35] = 0x3c; // row 1 scale = 1
    for (std::size_t i = 0; i < 32; ++i) q8_bytes[36 + i] = 0xff;
    Deep2::GGUFTensor q8_tensor;
    q8_tensor.name = "blk.0.q8.weight";
    q8_tensor.type = static_cast<Deep2::GGMLType>(8);
    q8_tensor.shape = {32, 2};
    q8_tensor.data = q8_bytes.data();
    q8_tensor.sizeBytes = q8_bytes.size();
    std::vector<float> q8_input(32, 1.f);
    float q8_output[2] = {};
    assert(model.loadMappedTensors({q8_tensor}, &error, &failed));
    assert(model.matvec(q8_tensor.name, q8_input.data(), q8_output, 34, &error));
    assert(q8_output[0] == 32.f && q8_output[1] == -32.f);

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
