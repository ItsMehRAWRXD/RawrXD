// certs/rawrxd_choreography_unbounded_001.cpp
#include "../src/deep2/ChoreographyResidencyLaw.hpp"
#include "../src/deep2/DualLaneContract.hpp"
#include "../src/deep2/DualLaneChoreographer.hpp"
#include "../interstellar/dual/dual_bind.hpp"
#include "../interstellar/hotpath/bow_rain.hpp"
#include <cstdio>
#ifdef _WIN32
#include <direct.h>
#endif

int main() {
    using namespace Deep2::choreo;
    using namespace Deep2::dual_lane;
    using Deep2::dual_lane::LaneId;
    using Deep2::dual_lane::RefuseWeightCross;
#ifdef _WIN32
    _mkdir("G:\\~dev\\rawrxd\\evidence");
    _mkdir("G:\\~dev\\rawrxd\\evidence\\RAWRXD_CHOREOGRAPHY_UNBOUNDED_001");
#endif
    ApplyLawEnv();
    ResidencyLaw law = DefaultLaw();
    DualLaneChoreographer choreo;
    int dual = is::dual::BindHardwareLanes(choreo);
    auto rain = is::MakeRain(is::MakeBow(2, 8));
    ReadyDecision rd = ScoreboardReady(TensorState::Disk, 0, 1);
    const bool pass = LawHolds(law) && rain.sync_per_layer == 0 &&
                      rain.async_pipeline == 1 && rd.scheduleOther == 1 &&
                      RefuseWeightCross(LaneId::A, LaneId::B) == 0;
    FILE* f = fopen(
        "G:\\~dev\\rawrxd\\evidence\\RAWRXD_CHOREOGRAPHY_UNBOUNDED_001\\"
        "GATE_STATUS.txt",
        "w");
    if (f) {
        EmitLaw(f, law);
        fprintf(f, "ASYNC_PIPELINE=%d\n", rain.async_pipeline);
        fprintf(f, "SYNC_PER_LAYER=%d\n", rain.sync_per_layer);
        fprintf(f, "SCOREBOARD_DISK_SCHEDULE_OTHER=%d\n", rd.scheduleOther);
        fprintf(f, "DUAL_LANES_BOUND=%d\n", dual);
        fprintf(f, "RAWRXD_CHOREOGRAPHY_UNBOUNDED_001=%s\n",
                pass ? "PASS" : "FAIL");
        fclose(f);
    }
    EmitLaw(stdout, law);
    printf("DUAL_LANES_BOUND=%d\n", dual);
    puts(pass ? "RAWRXD_CHOREOGRAPHY_UNBOUNDED_001=PASS"
              : "RAWRXD_CHOREOGRAPHY_UNBOUNDED_001=FAIL");
    return pass ? 0 : 1;
}
