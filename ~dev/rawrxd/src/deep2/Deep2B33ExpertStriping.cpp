#include "Deep2B33ExpertStriping.hpp"

namespace Deep2 {

B33StripePlan B33ExpertStriping::make(std::vector<B33ExpertDesc> e,
                                      const B33DeviceRate& d0,
                                      const B33DeviceRate& d1) noexcept {
    B33StripePlan p{};
    std::stable_sort(e.begin(), e.end(),
        [](const B33ExpertDesc& a, const B33ExpertDesc& b) {
            if (a.hot != b.hot) return a.hot > b.hot;
            if (a.recentNs != b.recentNs) return a.recentNs > b.recentNs;
            if (a.bytes != b.bytes) return a.bytes > b.bytes;
            return a.expert < b.expert;
        });

    double rate0 = d0.bytesPerNs > 0.0 ? d0.bytesPerNs : 1.0;
    double rate1 = d1.bytesPerNs > 0.0 ? d1.bytesPerNs : 1.0;
    double load0 = 0.0, load1 = 0.0;

    for (const auto& x : e) {
        const bool can0 = p.gpu0Bytes + x.bytes <= d0.freeVramBytes;
        const bool can1 = p.gpu1Bytes + x.bytes <= d1.freeVramBytes;

        uint32_t dev = 0;
        if (!can0 && can1) dev = 1;
        else if (can0 && !can1) dev = 0;
        else if (!can0 && !can1) {
            // fail-closed placement: leave it on the lower projected time side;
            // live binder must reject if residency budget cannot be honored.
            dev = (load0 <= load1) ? 0u : 1u;
        } else {
            const double t0 = load0 + double(x.bytes) / rate0;
            const double t1 = load1 + double(x.bytes) / rate1;
            dev = t0 <= t1 ? 0u : 1u;
        }

        p.placement.push_back({x.expert, dev, x.bytes});
        if (dev == 0) {
            p.gpu0Bytes += x.bytes;
            ++p.gpu0Experts;
            load0 += double(x.bytes) / rate0;
        } else {
            p.gpu1Bytes += x.bytes;
            ++p.gpu1Experts;
            load1 += double(x.bytes) / rate1;
        }
    }
    return p;
}

} // namespace Deep2
