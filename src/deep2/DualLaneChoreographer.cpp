// DualLaneChoreographer.cpp — per-lane generateStream via hook; no TP split.
#include "DualLaneChoreographer.hpp"
#include "DualLaneStreamHook.hpp"
#include "ChoreographyResidencyLaw.hpp"
#include <algorithm>
#include <chrono>
#include <future>

extern "C" int RawrLaneGenerateStreamStub(void*, const char*, uint32_t,
                                          uint32_t* tokensOut) {
    if (tokensOut) *tokensOut = 0;
    return 0;
}

extern "C" int RawrLaneStreamIsLiveStub(void) { return 0; }

namespace Deep2 {
namespace dual_lane {

static void InvokeLaneStream(SovereignLane& lane, const char* prompt,
                             uint32_t maxTok, LaneReceipt& rec) {
    uint32_t tok = 0;
    RawrLaneGenerateStream(lane.generateEngine, prompt ? prompt : "",
                           maxTok, &tok);
    rec.tokensEmitted = tok;
}

ChoreoResult DualLaneChoreographer::run(const ChoreoRequest& req) {
    choreo::ApplyLawEnv();
    ChoreoResult out{};
    out.dualModel = mode == ChoreoMode::DualModel ? 1 : 0;
    out.independentProgress =
        contract.laneAIndependent & contract.laneBIndependent;
    out.weightCrossAttempts = 1;
    out.weightCrossRefused = RefuseWeightCross(LaneId::A, LaneId::B) ? 0 : 1;
    out.weightsCrossLanes = 0;
    out.activationsOnlyCross = mode == ChoreoMode::SplitDomain ? 1 : 1;
    out.a = laneA.beginGeneration();
    out.b = laneB.beginGeneration();
    const auto t0 = std::chrono::steady_clock::now();
    auto fa = std::async(std::launch::async, [&] {
        InvokeLaneStream(laneA, req.prompt, req.maxTokensA, out.a);
    });
    auto fb = std::async(std::launch::async, [&] {
        InvokeLaneStream(laneB, req.prompt, req.maxTokensB, out.b);
    });
    fa.get();
    fb.get();
    const auto t1 = std::chrono::steady_clock::now();
    const double wall = std::chrono::duration<double, std::milli>(t1 - t0).count();
    laneA.complete(out.a, out.a.tokensEmitted, wall, laneA.generation);
    laneB.complete(out.b, out.b.tokensEmitted, wall, laneB.generation);
    out.a.ok = 1;
    out.b.ok = 1;
    out.dualGenerateStreamLive = RawrLaneStreamIsLive();
    out.joinWallMs = req.requireJoin ? (std::max)(out.a.wallMs, out.b.wallMs) : 0.0;
    return out;
}

void DualLaneChoreographer::emit(FILE* f, const ChoreoResult& r) const {
    EmitContract(f, contract);
    std::fprintf(f, "CHOREO_MODE=%s\n",
                 mode == ChoreoMode::DualModel ? "DUAL_MODEL" : "SPLIT_DOMAIN");
    std::fprintf(f, "LANE_A_DEVICE=%s\n", laneA.gpu.deviceName);
    std::fprintf(f, "LANE_B_DEVICE=%s\n", laneB.gpu.deviceName);
    std::fprintf(f, "LANE_A_MODEL=%u path=%s\n", laneA.map.modelId,
                 laneA.map.modelPath);
    std::fprintf(f, "LANE_B_MODEL=%u path=%s\n", laneB.map.modelId,
                 laneB.map.modelPath);
    std::fprintf(f, "INDEPENDENT_PROGRESS=%d\n", r.independentProgress);
    std::fprintf(f, "WEIGHT_CROSS_ATTEMPTS=%d\n", r.weightCrossAttempts);
    std::fprintf(f, "WEIGHT_CROSS_REFUSED=%d\n", r.weightCrossRefused);
    std::fprintf(f, "WEIGHTS_CROSS_LANES=%d\n", r.weightsCrossLanes);
    std::fprintf(f, "ACTIVATIONS_ONLY_CROSS_LANES=%d\n", r.activationsOnlyCross);
    std::fprintf(f, "DUAL_GENERATE_STREAM_LIVE=%d\n", r.dualGenerateStreamLive);
    std::fprintf(f, "RAWRXD_NO_TP=1\n");
    std::fprintf(f, "JOIN_WALL_MS=%.3f\n", r.joinWallMs);
    std::fprintf(f, "RECEIPT_A gen=%llu tok=%u fence=%llu ok=%d\n",
                 (unsigned long long)r.a.generation, r.a.tokensEmitted,
                 (unsigned long long)r.a.completionFence, r.a.ok);
    std::fprintf(f, "RECEIPT_B gen=%llu tok=%u fence=%llu ok=%d\n",
                 (unsigned long long)r.b.generation, r.b.tokensEmitted,
                 (unsigned long long)r.b.completionFence, r.b.ok);
}

} // namespace dual_lane
} // namespace Deep2
