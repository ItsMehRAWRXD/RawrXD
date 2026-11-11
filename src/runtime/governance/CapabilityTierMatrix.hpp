#pragma once
#include "HardwareCapabilityProbe.hpp"
#include <cstdint>
#include <string>
namespace RawrXD::Governance {
enum class CapabilityTier:uint8_t{Emergency=0,Minimal=1,Compact=2,Standard=3,High=4,Maximum=5};
struct TierPolicy{CapabilityTier tier;uint32_t max_context_tokens;uint8_t kv_bits;bool allow_gpu;bool allow_avx512;bool allow_ensemble;uint32_t max_parallel_submodels;uint32_t target_model_params_b;const char*name;};
struct TierDecision{TierPolicy policy;double score;std::string reason;};
class CapabilityTierMatrix{public:TierDecision resolve(const HardwareSnapshot&)const noexcept;static const TierPolicy&policy(CapabilityTier)noexcept;};
}
