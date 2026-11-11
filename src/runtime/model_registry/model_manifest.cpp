#include "model_manifest.hpp"

namespace rawrxd {
namespace runtime {

// Default constructor implementation
ModelManifest::ModelManifest() : 
    parameter_count(0), 
    context_length(0), 
    file_size(0), 
    required_vram(0),
    supports_gpu(false),
    supports_vulkan(false),
    supports_hip(false) {}

// Parameterized constructor implementation
ModelManifest::ModelManifest(
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
) : name(name),
    path(path),
    architecture(architecture),
    quantization(quantization),
    parameter_count(parameter_count),
    context_length(context_length),
    file_size(file_size),
    required_vram(required_vram),
    supports_gpu(supports_gpu),
    supports_vulkan(supports_vulkan),
    supports_hip(supports_hip) {}

} // namespace runtime
} // namespace rawrxd
