#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace rawrxd {
namespace runtime {

struct ModelManifest {
    std::string name;
    std::string path;
    std::string architecture;
    std::string quantization;

    uint64_t parameter_count;
    uint64_t context_length;
    uint64_t file_size;
    uint64_t required_vram;

    bool supports_gpu;
    bool supports_vulkan;
    bool supports_hip;

    // Constructor
    ModelManifest();

    // Constructor with parameters
    ModelManifest(
        const std::string& name,
        const std::string& path,
        const std::string& architecture,
        const std::string& quantization,
        uint64_t parameter_count,
        uint64_t context_length,
        uint64_t file_size,
        uint64_t required_vram,
        bool supports_gpu,
        bool supports_vulkan,
        bool supports_hip
    );
};

} // namespace runtime
} // namespace rawrxd