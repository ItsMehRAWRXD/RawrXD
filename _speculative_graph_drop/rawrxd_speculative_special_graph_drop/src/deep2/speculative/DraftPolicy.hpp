#pragma once
#include <cstdint>

namespace rawrxd::deep2::spec {

enum class DraftRoute : std::uint8_t {
    SameModelEarlyExit,
    SecondaryModel
};

struct DraftRouteMetrics final {
    float acceptanceEma{1.0f};
    float sameModelMilliseconds{0.0f};
    float secondaryMilliseconds{0.0f};
    bool secondaryAvailable{false};
};

struct DraftRoutePolicy final {
    float minimumAcceptance{0.45f};
    float secondarySwitchRatio{0.85f}; // secondary must be <= same * ratio
    DraftRoute preferred{DraftRoute::SecondaryModel};
};

[[nodiscard]] DraftRoute chooseDraftRoute(
    const DraftRoutePolicy& policy,
    const DraftRouteMetrics& metrics) noexcept;

[[nodiscard]] const char* toString(DraftRoute route) noexcept;

} // namespace rawrxd::deep2::spec
