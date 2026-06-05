#pragma once

#include "patch_result.hpp"
#include "rawrxd_quant_container.h"

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace Core {

struct RawrXDQuantTensorWriteSpec {
    std::string name;
    uint64_t name_hash = 0;

    uint32_t tensor_kind = 0;
    uint32_t quant_mode = RAWRXD_QUANT_FILE_FP16;
    uint32_t block_size = 0;
    uint32_t flags = RAWRXD_QUANT_FLAG_NONE;
    uint64_t element_count = 0;
    uint32_t alignment = 64;

    std::vector<uint64_t> dims;

    std::vector<uint8_t> payload;
    std::vector<uint8_t> scales;
    std::vector<uint8_t> zero_points;
};

struct RawrXDQuantWriteOptions {
    uint64_t global_alignment = 64;
    bool emit_name_table = true;
    uint64_t model_crc64 = 0;
};

PatchResult WriteRawrXDQuantContainer(const std::string& output_path,
                                      const std::vector<RawrXDQuantTensorWriteSpec>& tensors,
                                      const RawrXDQuantWriteOptions& options = {});

} // namespace Core
} // namespace RawrXD
