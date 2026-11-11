#pragma once
#include "CapabilityTierMatrix.hpp"
#include <cstdint>
#include <mutex>
namespace RawrXD::Governance {struct GovernorTelemetry{double ram_headroom=0,vram_headroom=0,thermal_headroom=1;uint64_t transitions=0;};class HardwareGovernor{public:void update(const HardwareSnapshot&,CapabilityTier);CapabilityTier effective_tier()const noexcept;GovernorTelemetry telemetry()const noexcept;bool emergency()const noexcept;private:mutable std::mutex mu_;CapabilityTier tier_=CapabilityTier::Emergency;GovernorTelemetry tel_{};bool emergency_=true;};}
