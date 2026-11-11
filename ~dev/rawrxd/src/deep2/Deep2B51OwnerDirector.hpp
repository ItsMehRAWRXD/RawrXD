#pragma once
#include <cstdint>

namespace Deep2 {

enum class B51Owner : uint8_t {
    Unknown,
    Memory,
    Compute,
    Sync,
    Transfer
};

struct B51Telemetry {
    double bandwidthFraction = 0.0;
    double computeFraction = 0.0;
    double overlap = 0.0;
    double hostSyncFraction = 1.0;
    double queueIdleFraction = 1.0;
    uint64_t reloadBytes = 0;
    uint64_t hostMaterializations = 0;
    uint64_t hostTokenCopies = 0;
    uint64_t peerCopyBytes = 0;
};

struct B51Plan {
    B51Owner owner = B51Owner::Unknown;
    bool enableMemoryPath = false;
    bool enableComputePath = false;
    bool enableSyncPath = false;
    bool enableTransferPath = false;
    bool freezeUnrelatedTuners = true;
};

class B51OwnerDirector {
public:
    static B51Plan choose(const B51Telemetry&) noexcept;
    static const char* name(B51Owner) noexcept;
};

}
