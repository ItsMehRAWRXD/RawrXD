// Logic test for RAWRXD_ADAPTIVE_BLACKBOARD_INTELLIGENCE_V4.
// Uses a DETERMINISTIC TEST DOUBLE as the executor to verify the learning loop
// (prediction-error correction, bounded memory, validated retention). This is a
// unit test of the intelligence, NOT a hardware measurement.
#include "AdaptiveBlackboardIntelligenceV4.hpp"
#include <cstdio>
#include <cmath>

using namespace rawrxd::blackboard_v4;

// Test double: a fixed unknown "hardware" response surface.
static bool TestExec(const Controls& c, Measured& m) {
    m.decodeTps  = 200.0 + 0.05 * c.batch - 0.02 * c.threads;
    m.prefillTps = 600.0 + 0.5 * c.batch;
    m.tokens = 256;
    m.consistent = true;
    m.valid = true;
    return true;
}

int main() {
    V4Blackboard bb;
    bb.rng.seed(12345); // deterministic test
    double firstErr = 0.0, lastErr = 0.0;
    for (int i = 0; i < 400; ++i) {
        ExploreCycleV4(bb, TestExec);
        if (i == 0 && !bb.obs.empty()) firstErr = std::fabs(bb.obs.back().error);
        if (i == 399 && !bb.obs.empty()) lastErr = std::fabs(bb.obs.back().error);
    }
    std::printf("ITERS=%llu OBS=%zu FRONT_OBS=%zu FRONT_VAL=%zu\n",
        (unsigned long long)bb.iterations, bb.obs.size(),
        bb.frontObserved.size(), bb.frontValidated.size());
    std::printf("MODEL a=%.3f b=%.5f c=%.5f residVar=%.4f\n", bb.a, bb.b, bb.c, bb.residualVar);
    std::printf("FIRST_ERR=%.3f LAST_ERR=%.3f\n", firstErr, lastErr);
    std::printf("BEST_VALIDATED batch=%d threads=%d\n", bb.bestValidated.batch, bb.bestValidated.threads);

    int fails = 0;
    auto ck=[&](bool ok,const char*n){ std::printf("%s %s\n",ok?"OK":"FAIL",n); if(!ok)++fails; };
    ck(bb.obs.size() <= bb.cap, "bounded_obs");
    ck(bb.iterations == 400, "iters_400");
    ck(!bb.frontValidated.empty(), "validated_nonempty");
    ck(bb.haveBest, "have_best_validated");
    ck(bb.b > 0.0, "learned_positive_batch_slope"); // learned the true +0.05 slope
    ck(lastErr < firstErr, "prediction_error_decreased"); // learning works
    std::printf("FAILS=%d\n", fails);
    return fails ? 1 : 0;
}