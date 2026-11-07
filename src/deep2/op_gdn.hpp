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
    uint32_t key_heads = 0;
    uint32_t value_heads = 0;
    uint32_t head_dim = 0;
    uint32_t qkv_stride = 0;
    uint32_t gate_stride = 0;
    uint32_t conv_kernel = 0;
    float epsilon = 1e-5f;
    float scale = 1.0f;
    uint32_t gate_sigmoid = 0;
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

// GDN state element count: total floats in the per-channel recurrence state
// for a GDN descriptor. Equivalent to channels * state_size * groups.
size_t GDNStateElements(const GDNDescriptor& descriptor);

// GDN reference step: evaluates the recurrent gate/delta-net layer.
// Returns false and fills `failure` on error.
bool GDNReferenceStep(const GDNDescriptor& descriptor,
                      const std::vector<float>& input,
                      const std::vector<float>& decay,
                      const std::vector<float>& beta,
                      const std::vector<float>& key,
                      const std::vector<float>& value,
                      std::vector<float>& state,
                      std::vector<float>& output,
                      std::string& failure);

size_t GDNQkvWidth(const GDNDescriptor& d);
size_t GDNOutputWidth(const GDNDescriptor& d);

// Qwen3.6/Qwen4Exp gated-delta recurrence. This layout is distinct from
// the generic per-channel GDNReferenceStep contract above: Q/K/V are packed
// by heads, alpha/beta are per-value-head projections, and the recurrent
// state is [value_heads, head_dim, head_dim].
size_t GDNQwenStateElements(const GDNDescriptor& d);

bool GDNQwenReferenceStep(const GDNDescriptor& descriptor,
                          const std::vector<float>& mixed_qkv,
                          const std::vector<float>& beta_logits,
                          const std::vector<float>& alpha_logits,
                          const std::vector<float>& a_log,
                          const std::vector<float>& dt_bias,
                          const std::vector<float>& norm,
                          const std::vector<float>& gate,
                          std::vector<float>& state,
                          std::vector<float>& output,
                          std::string& failure);

bool GDNReferenceDecode(const GDNDescriptor& descriptor,
                        const std::vector<float>& qkv,
                        const std::vector<float>& beta,
                        const std::vector<float>& alpha,
                        const std::vector<float>& gate,
                        const std::vector<float>& a_log,
                        const std::vector<float>& dt_bias,
                        const std::vector<float>& norm,
                        std::vector<float>& state,
                        std::vector<float>& output,
                        std::string& failure);

} // namespace Deep2::Qwen4Exp
