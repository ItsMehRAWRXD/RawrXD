// TpsScaleHotpatch.cpp — emit reversed TPS witnesses
#include "TpsScaleHotpatch.hpp"

namespace Deep2 {

void TpsScale_Emit(FILE* f, uint32_t tokens, double wallMs, double tpb) {
    if (!f) f = stdout;
    const double raw = TpsScale_WallRaw(tokens, wallMs);
    const double disp = TpsScale_Display(raw);
    const double bptRev = TpsScale_ReverseTpb(tpb);
    fprintf(f, "TPS_RAW=%.6f\n", raw);
    fprintf(f, "TPS_DISPLAY=%.1f\n", disp);
    fprintf(f, "TPS_SCALE=%.0f\n",
            (raw > 0.0) ? (disp / raw) : 1000.0);
    fprintf(f, "TPB_RAW=%.9e\n", tpb);
    fprintf(f, "TPB_REVERSE_BPT=%.1f\n", bptRev);
    // work identity: display * wall / (scale*1000) == tokens
    fprintf(f, "TPS_WORK=%.3f\n", disp * wallMs / 1.0e6);
    fflush(f);
}

} // namespace Deep2
