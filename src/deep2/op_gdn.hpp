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

// Qwen4Exp Flash-Next GDN geometry recovered from the GGUF metadata and the
// independent r9700 reference implementation. The tensor names map as:
// attn_qkv -> [q | k | v], attn_gate -> z, ssm_alpha -> a, ssm_beta -> b.
struct GDNDescriptor {
    uint32_t key_heads = 16;
    uint32_t value_heads = 48;
    uint32_t head_dim = 128;
    uint32_t conv_kernel = 4;
    uint32_t tokens = 0;
    uint32_t qkv_stride = 0;
    uint32_t gate_stride = 0;
    float epsilon = 1.0e-6f;
    float scale = 0.08838834764831843f;
    bool gate_sigmoid = true;
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

uint32_t GDNQkvWidth(const GDNDescriptor& descriptor);
uint32_t GDNOutputWidth(const GDNDescriptor& descriptor);
uint64_t GDNStateElements(const GDNDescriptor& descriptor);

bool ValidateGDNDescriptor(const GDNDescriptor& descriptor,
                           std::string& failure);

// One token of the post-convolution GDN core. qkv is laid out as
// [q(key_heads*head_dim), k(key_heads*head_dim), v(value_heads*head_dim)].
// state is [value_heads, head_dim, head_dim].
bool GDNReferenceStep(const GDNDescriptor& descriptor,
                      const std::vector<float>& qkv,
                      const std::vector<float>& b,
                      const std::vector<float>& a,
                      const std::vector<float>& z,
                      const std::vector<float>& a_log,
                      const std::vector<float>& dt_bias,
                      const std::vector<float>& norm,
                      std::vector<float>& state,
                      std::vector<float>& output,
                      std::string& failure);

bool GDNReferenceDecode(const GDNDescriptor& descriptor,
                        const std::vector<float>& qkv,
                        const std::vector<float>& b,
                        const std::vector<float>& a,
                        const std::vector<float>& z,
                        const std::vector<float>& a_log,
                        const std::vector<float>& dt_bias,
                        const std::vector<float>& norm,
                        std::vector<float>& state,
                        std::vector<float>& output,
                        std::string& failure);

} // namespace Deep2::Qwen4Exp
