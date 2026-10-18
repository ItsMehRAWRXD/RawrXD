#include "Deep2B27MoESuperkernel.hpp"

namespace Deep2 {

B27MoEPlan B27MoESuperkernel::make(std::vector<B27ExpertTask> tasks,
                                   uint32_t cu0, uint32_t cu1) noexcept {
    B27MoEPlan p{};
    std::stable_sort(tasks.begin(), tasks.end(),
        [](const B27ExpertTask& a, const B27ExpertTask& b) {
            if (a.resident != b.resident) return a.resident > b.resident;
            if (a.lastNs != b.lastNs) return a.lastNs > b.lastNs;
            if (a.routeWeight != b.routeWeight) return a.routeWeight > b.routeWeight;
            return a.expert < b.expert;
        });
    for (const auto& t : tasks) {
        if (t.device == 0) ++p.gpu0Tasks;
        else if (t.device == 1) ++p.gpu1Tasks;
    }
    const uint32_t totalCU = cu0 + cu1;
    p.maxConcurrentExperts = totalCU >= 120 ? 8u : (totalCU >= 64 ? 4u : 2u);
    p.ordered = std::move(tasks);
    return p;
}

uint64_t B27MoESuperkernel::avoidableActivationTraffic(uint32_t activeExperts,
                                                       uint32_t intermediate,
                                                       uint32_t scalarBytes) noexcept {
    // gate, up, silu(gate), product intermediates: conservative 4 arrays,
    // each normally written then read.
    return uint64_t(activeExperts) * uint64_t(intermediate) *
           uint64_t(scalarBytes) * 8ull;
}

} // namespace Deep2
