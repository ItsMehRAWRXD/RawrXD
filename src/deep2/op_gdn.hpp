#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2::Qwen4Exp {

enum class GDNStatus : uint8_t {
    Unsupported,
    GeometryValidated,
    PipelineCreated,
    DispatchVerified,
    ReferenceParityPassed,
};

struct GDNDescriptor {
    uint32_t channels = 0;
    uint32_t state_size = 0;
    uint32_t groups = 0;
    uint32_t tokens = 0;
    uint32_t stride = 0;
};

struct GDNExecutionReceipt {
    GDNStatus status = GDNStatus::Unsupported;
    uint32_t layers_executed = 0;
    uint64_t gpu_dispatches = 0;
    uint64_t cpu_fallbacks = 0;
    bool state_continuity_passed = false;
    bool independent_parity_passed = false;
    std::string failure;
};

bool ValidateGDNDescriptor(const GDNDescriptor& descriptor,
                          std::string& failure);

void GDNReferenceStep(const GDNDescriptor& descriptor,
                      const std::vector<float>& input,
                      const std::vector<float>& decay,
                      const std::vector<float>& beta,
                      const std::vector<float>& key,
                      const std::vector<float>& value,
                      std::vector<float>& state,
                      std::vector<float>& output);

} // namespace Deep2::Qwen4Exp
