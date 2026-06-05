#include "rxqf_converter.h"

#include "model_loader.h"
#include "../core/rawrxd_quant_container_writer.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD::Inference {
namespace {

static uint32_t quantModeFromTensorType(TensorType t) {
    switch (t) {
        case TensorType::Q4_0:
        case TensorType::Q4_1:
            return RAWRXD_QUANT_FILE_INT4;
        case TensorType::Q8_0:
        case TensorType::Q8_1:
            return RAWRXD_QUANT_FILE_INT8;
        case TensorType::F16:
            return RAWRXD_QUANT_FILE_FP16;
        case TensorType::F32:
        default:
            return RAWRXD_QUANT_FILE_FP16;
    }
}

static uint32_t blockSizeFromTensorType(TensorType t) {
    switch (t) {
        case TensorType::Q4_0:
        case TensorType::Q4_1:
        case TensorType::Q8_0:
        case TensorType::Q8_1:
            return 32;
        default:
            return 0;
    }
}

static uint64_t elementCountFromDims(const std::vector<uint64_t>& dims) {
    if (dims.empty()) {
        return 0;
    }
    uint64_t n = 1;
    for (uint64_t d : dims) {
        if (d == 0) {
            return 0;
        }
        n *= d;
    }
    return n;
}

} // namespace

PatchResult ConvertModelToRXQF(const std::string& input_model_path,
                               const std::string& output_rxqf_path,
                               bool emit_name_table,
                               uint64_t global_alignment) {
    LoaderConfig cfg{};
    cfg.useMemoryMapping = true;
    cfg.verifyChecksum = false;

    ModelLoader loader(cfg);
    Model model{};
    if (!loader.loadModel(input_model_path, model)) {
        return PatchResult::error("RXQF convert: failed to load input model", -1);
    }

    if (model.tensors.empty()) {
        return PatchResult::error("RXQF convert: input model has no tensors", -2);
    }

    std::vector<RawrXD::Core::RawrXDQuantTensorWriteSpec> specs;
    specs.reserve(model.tensors.size());

    for (const auto& [name, tensor] : model.tensors) {
        RawrXD::Core::RawrXDQuantTensorWriteSpec s{};
        s.name = name;
        s.quant_mode = quantModeFromTensorType(tensor.type);
        s.block_size = blockSizeFromTensorType(tensor.type);
        s.flags = (s.block_size > 0) ? RAWRXD_QUANT_FLAG_BLOCK_BASED : RAWRXD_QUANT_FLAG_NONE;
        s.alignment = static_cast<uint32_t>(std::min<uint64_t>(global_alignment, 64));
        s.dims = tensor.dimensions;
        s.element_count = elementCountFromDims(s.dims);
        s.payload = tensor.data;
        specs.push_back(std::move(s));
    }

    RawrXD::Core::RawrXDQuantWriteOptions opts{};
    opts.global_alignment = global_alignment;
    opts.emit_name_table = emit_name_table;
    opts.model_crc64 = 0;

    return RawrXD::Core::WriteRawrXDQuantContainer(output_rxqf_path, specs, opts);
}

} // namespace RawrXD::Inference
