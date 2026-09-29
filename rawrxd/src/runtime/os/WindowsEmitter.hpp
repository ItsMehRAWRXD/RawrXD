// ============================================================================
// WindowsEmitter.hpp — PE/COFF artifact emission for Windows
// ============================================================================
#pragma once
#include "PlatformEmitter.hpp"

namespace rawrxd::runtime {

class WindowsEmitter final : public PlatformEmitter {
public:
    ArtifactFormat format() const noexcept override { return ArtifactFormat::PE; }
    bool emit(const Artifact& input, std::vector<uint8_t>& output) override;
};

} // namespace rawrxd::runtime