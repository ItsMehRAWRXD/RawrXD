// ============================================================================
// PlatformEmitter.hpp — Interface for platform-specific artifact emission
// ============================================================================
#pragma once
#include "Artifact.hpp"

namespace rawrxd::runtime {

class PlatformEmitter {
public:
    virtual ~PlatformEmitter() = default;
    virtual ArtifactFormat format() const noexcept = 0;
    virtual bool emit(const Artifact& input, std::vector<uint8_t>& output) = 0;
};

} // namespace rawrxd::runtime