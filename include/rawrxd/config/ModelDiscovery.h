#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::config {

struct ModelInfo {
    std::string path;
    std::string fileName;
    std::uint64_t sizeBytes = 0;
    std::string architecture;
    std::string quantization;
    std::uint32_t contextLength = 0;
    std::uint64_t tensorCount = 0;
    bool valid = false;
    std::string error;
};

// Dynamic GGUF discovery with header metadata extraction (M-CFG-02 / M-CFG-04).
std::vector<ModelInfo> discoverModels(const std::string& directory);
ModelInfo inspectModel(const std::string& path);

} // namespace rawrxd::config