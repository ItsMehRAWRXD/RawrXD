#include "ExpertScheduler.h"
#include <limits>

namespace rawrxd {
double ExpertScheduler::score(const ExpertPlacementRequest& r, const ExpertDeviceState& d) noexcept {
    if (!d.available) return -std::numeric_limits<double>::infinity();
    const uint64_t used = d.residentBytes + d.inflightBytes;
    if (used > d.budgetBytes || r.bytes > (d.budgetBytes - used)) return -std::numeric_limits<double>::infinity();
    const double freeFrac = d.budgetBytes ? double(d.budgetBytes - used) / double(d.budgetBytes) : 0.0;
    const double loadPenalty = double(d.recentComputeUs + d.recentTransferUs) / 1000.0;
    const double locality = (r.currentDevice == int32_t(d.deviceId)) ? 200.0 : 0.0;
    const double hotness = double(r.routerProbability) * 100.0;
    return locality + hotness + freeFrac * 100.0 - loadPenalty;
}

ExpertPlacementDecision ExpertScheduler::choose(const ExpertPlacementRequest& req,
                                                 const std::vector<ExpertDeviceState>& devices) const noexcept {
    ExpertPlacementDecision out{};
    out.score = -std::numeric_limits<double>::infinity();
    for (const auto& d : devices) {
        const double s = score(req, d);
        if (s > out.score) { out.score = s; out.device = int32_t(d.deviceId); }
    }
    out.migrate = out.device >= 0 && req.currentDevice >= 0 && out.device != req.currentDevice;
    return out;
}
} // namespace rawrxd
