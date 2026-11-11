#pragma once
#include "HardwareCapabilityProbe.hpp"
#include <cstdint>
namespace RawrXD::Governance {enum class InstructionPath:uint8_t{Scalar,AVX2,AVX512,AVX512VNNI};class TLSInstructionGate{public:static void install(const CpuCapabilities&)noexcept;static void refresh(const CpuCapabilities&)noexcept;static InstructionPath path()noexcept;static bool allows(InstructionPath)noexcept;static const char*name()noexcept;private:static thread_local InstructionPath tls_path_;};}
