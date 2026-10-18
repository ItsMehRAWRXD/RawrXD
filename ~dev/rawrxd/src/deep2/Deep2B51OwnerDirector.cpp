#include "Deep2B51OwnerDirector.hpp"

namespace Deep2 {

const char* B51OwnerDirector::name(B51Owner o) noexcept {
    switch (o) {
        case B51Owner::Memory: return "MEMORY";
        case B51Owner::Compute: return "COMPUTE";
        case B51Owner::Sync: return "SYNC";
        case B51Owner::Transfer: return "TRANSFER";
        default: return "UNKNOWN";
    }
}

B51Plan B51OwnerDirector::choose(const B51Telemetry& t) noexcept {
    B51Plan p{};

    if (t.reloadBytes || t.hostMaterializations || t.hostTokenCopies || t.peerCopyBytes) {
        p.owner = B51Owner::Transfer;
        p.enableTransferPath = true;
        return p;
    }

    if (t.hostSyncFraction > 0.02 || t.queueIdleFraction > 0.05 || t.overlap < 0.90) {
        p.owner = B51Owner::Sync;
        p.enableSyncPath = true;
        return p;
    }

    // Whichever physical engine is farther from saturation owns the remaining gap.
    if (t.bandwidthFraction + 0.03 < t.computeFraction) {
        p.owner = B51Owner::Memory;
        p.enableMemoryPath = true;
    } else if (t.computeFraction + 0.03 < t.bandwidthFraction) {
        p.owner = B51Owner::Compute;
        p.enableComputePath = true;
    } else {
        // Near balanced: choose the lower utilization as the marginal owner.
        if (t.bandwidthFraction <= t.computeFraction) {
            p.owner = B51Owner::Memory;
            p.enableMemoryPath = true;
        } else {
            p.owner = B51Owner::Compute;
            p.enableComputePath = true;
        }
    }
    return p;
}

}
