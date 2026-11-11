#include "Deep2B44MlaComputeBalance.hpp"
#include <algorithm>

namespace Deep2 {

B44MlaPlan B44MlaComputeBalance::make(const B44MlaShape& s,
                                      const B44DeviceProfile& d) noexcept {
    B44MlaPlan p{};
    p.tokenTile = s.context >= 131072 ? 256u :
                  (s.context >= 32768 ? 128u : 64u);
    p.headTile = s.heads >= 64 ? 4u : 2u;
    p.rankTile = s.kvRank >= 512 ? 128u : 64u;
    p.valueTile = s.vDim >= 128 ? 128u : 64u;

    const double flops =
        2.0 * double(p.tokenTile) * double(p.headTile) *
        double(s.kvRank + s.vDim);
    const double bytes =
        2.0 * double(p.tokenTile) * double(s.kvRank + s.ropeDim) +
        4.0 * double(p.headTile) * double(s.kvRank + s.vDim);

    p.estimatedArithmeticIntensity = bytes > 0.0 ? flops/bytes : 0.0;

    const double machineBalance =
        d.bandwidthGBs > 0.0 ? (d.computeTFLOPs*1000.0)/d.bandwidthGBs : 0.0;
    p.computeBoundTarget =
        machineBalance > 0.0 && p.estimatedArithmeticIntensity >= machineBalance*0.5;
    return p;
}

}
