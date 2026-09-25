#include "DraftPolicy.hpp"

namespace rawrxd::deep2::spec {

DraftRoute chooseDraftRoute(
    const DraftRoutePolicy& policy,
    const DraftRouteMetrics& metrics) noexcept {

    if (!metrics.secondaryAvailable) return DraftRoute::SameModelEarlyExit;
    if (metrics.acceptanceEma < policy.minimumAcceptance) {
        return DraftRoute::SameModelEarlyExit;
    }

    if (metrics.sameModelMilliseconds > 0.0f &&
        metrics.secondaryMilliseconds > 0.0f) {
        const bool materiallyFaster =
            metrics.secondaryMilliseconds <=
            metrics.sameModelMilliseconds * policy.secondarySwitchRatio;
        return materiallyFaster
            ? DraftRoute::SecondaryModel
            : DraftRoute::SameModelEarlyExit;
    }

    return policy.preferred;
}

const char* toString(DraftRoute route) noexcept {
    switch (route) {
        case DraftRoute::SameModelEarlyExit: return "SameModelEarlyExit";
        case DraftRoute::SecondaryModel: return "SecondaryModel";
    }
    return "Unknown";
}

} // namespace rawrxd::deep2::spec
