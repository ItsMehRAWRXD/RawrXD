#include "Deep2B53ComputeTail.hpp"

namespace Deep2 {

std::vector<B53Variant> B53ComputeTail::enumerate(const B53ComputeShape& s) {
    std::vector<B53Variant> out;
    const uint32_t accs[] = {4,8,12};
    const uint32_t unrolls[] = {2,4,8};
    const uint32_t rows[] = {2,4,8};
    const uint32_t split[] = {1,2,4};

    for (auto a:accs) for (auto u:unrolls) for (auto r:rows) for (auto k:split) {
        B53Variant v{};
        v.workgroup = s.cols >= 4096 ? 256u : 128u;
        v.accumulators = a;
        v.unroll = u;
        v.rowsPerGroup = r;
        v.splitK = k;
        v.estimatedRegs = 24u + a*2u + u + r*2u + k;
        if (v.estimatedRegs <= 112u) out.push_back(v);
    }
    return out;
}

B53Decision B53ComputeTail::choose(const std::vector<B53Measured>& m,
                                   double minCompute,
                                   double minOcc) noexcept {
    B53Decision d{};
    double bestScore=-1.0;
    for (size_t i=0;i<m.size();++i) {
        const auto& x=m[i];
        if (!x.parity || x.kernelNs<=0.0) continue;
        if (x.computeFraction<minCompute || x.occupancyFraction<minOcc) continue;
        const double score=(x.computeFraction*x.occupancyFraction)/x.kernelNs;
        if (score>bestScore) {
            bestScore=score; d.pass=true; d.best=i;
        }
    }
    return d;
}

}
