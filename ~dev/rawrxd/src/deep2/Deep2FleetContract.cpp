#include "Deep2FleetContract.hpp"
#include <algorithm>
#include <cmath>

namespace Deep2 {

static double qtile(std::vector<double> v, double q) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const double pos = q * double(v.size() - 1);
    const size_t lo = static_cast<size_t>(std::floor(pos));
    const size_t hi = static_cast<size_t>(std::ceil(pos));
    if (lo == hi) return v[lo];
    const double f = pos - double(lo);
    return v[lo]*(1.0-f) + v[hi]*f;
}

static bool near_rel(double a, double b, double rel) noexcept {
    if (a <= 0.0 || b <= 0.0) return true;
    const double d = std::fabs(a-b);
    return d <= std::max(a,b)*rel;
}

const char* FleetContract::familyName(FleetFamily f) noexcept {
    switch (f) {
        case FleetFamily::Qwen3Next: return "QWEN3_NEXT_80B_A3B";
        case FleetFamily::Nemotron35Lightning: return "NEMOTRON_3_5_LIGHTNING_30B_A3B";
        case FleetFamily::GptOss120B: return "GPT_OSS_120B_A5_1B";
        case FleetFamily::LagunaS21: return "LAGUNA_S_2_1_118B_A8B";
        case FleetFamily::DeepSeekV4Flash: return "DEEPSEEK_V4_FLASH_284B_A13B";
        default: return "UNKNOWN";
    }
}

bool FleetContract::metadataMatches(const ModelEnvelope& e,
                                    const RuntimeModelMeta& m) noexcept {
    if (!near_rel(e.totalParamsB,m.totalParamsB,0.03)) return false;
    if (!near_rel(e.activeParamsB,m.activeParamsB,0.08)) return false;

    auto eq = [](uint32_t expected, uint32_t got) {
        return expected == 0 || got == 0 || expected == got;
    };

    if (!eq(e.layers,m.layers)) return false;
    if (!eq(e.experts,m.experts)) return false;
    if (!eq(e.expertsPerToken,m.expertsPerToken)) return false;
    if (!eq(e.sharedExperts,m.sharedExperts)) return false;
    if (!eq(e.hidden,m.hidden)) return false;
    if (!eq(e.heads,m.heads)) return false;
    if (!eq(e.kvHeads,m.kvHeads)) return false;
    if (!eq(e.headDim,m.headDim)) return false;

    if (e.context && m.context && m.context < e.context) return false;
    if (e.useMLA && !m.useMLA) return false;
    if (e.useSSM && !m.useSSM) return false;
    if (e.useHybridLinearAttention && !m.useHybridLinearAttention) return false;
    if (e.useSlidingWindow && !m.useSlidingWindow) return false;
    return true;
}

ContractStats FleetContract::summarize(const std::vector<ContractSample>& in) {
    ContractStats s{};
    s.samples=in.size();
    if (in.empty()) return s;

    std::vector<double> raw,eff,roofTps,roof,bw,cf,ov,sk,hs,qi;
    s.parityAll=true; s.stableAll=true;

    for (const auto& x : in) {
        raw.push_back(x.rawTps);
        eff.push_back(x.effectiveTps);
        roofTps.push_back(x.physicalRooflineTps);
        roof.push_back(x.rooflineFraction);
        bw.push_back(x.bandwidthFraction);
        cf.push_back(x.computeFraction);
        ov.push_back(x.overlap);
        sk.push_back(x.skew);
        hs.push_back(x.hostSync);
        qi.push_back(x.queueIdle);
        s.reloadBytes += x.reloadBytes;
        s.hostMaterializations += x.hostMaterializations;
        s.hostTokenCopies += x.hostTokenCopies;
        s.peerCopyBytes += x.peerCopyBytes;
        s.gpu0Forwards += x.gpu0Forwards;
        s.gpu1Forwards += x.gpu1Forwards;
        s.parityAll = s.parityAll && x.parity;
        s.stableAll = s.stableAll && x.stable;
    }

    s.p10RawTps=qtile(raw,.10);
    s.medianRawTps=qtile(raw,.50);
    s.medianEffectiveTps=qtile(eff,.50);
    s.p10PhysicalRooflineTps=qtile(roofTps,.10);
    s.p10RooflineFraction=qtile(roof,.10);
    s.medianRooflineFraction=qtile(roof,.50);
    s.p10BandwidthFraction=qtile(bw,.10);
    s.p10ComputeFraction=qtile(cf,.10);
    s.medianOverlap=qtile(ov,.50);
    s.p90Skew=qtile(sk,.90);
    s.p90HostSync=qtile(hs,.90);
    s.p90QueueIdle=qtile(qi,.90);
    return s;
}

ContractDecision FleetContract::certify(const ModelPerformanceContract& c,
                                        const RuntimeModelMeta& m,
                                        const ContractStats& s) noexcept {
    if (!metadataMatches(c.envelope,m)) return {false,"METADATA_MISMATCH"};
    if (m.context && c.contextBucketMax && m.context < c.contextBucketMax)
        return {false,"CONTEXT_CAPACITY"};
    if (s.samples < c.minSamples) return {false,"SAMPLES"};

    // Contract target must be physically supportable with explicit headroom.
    if (s.p10PhysicalRooflineTps <
        c.minMedianRawTps * c.minRooflineHeadroom)
        return {false,"TARGET_EXCEEDS_PHYSICAL_ROOFLINE"};

    if (!s.parityAll) return {false,"PARITY"};
    if (!s.stableAll) return {false,"OUTPUT_STABILITY"};
    if (!s.gpu0Forwards || !s.gpu1Forwards) return {false,"BOTH_GPUS"};
    if (s.reloadBytes) return {false,"RELOAD"};
    if (s.hostMaterializations) return {false,"HOST_MATERIALIZATION"};
    if (s.hostTokenCopies) return {false,"HOST_TOKEN_COPY"};
    if (s.peerCopyBytes) return {false,"PEER_COPY"};

    if (s.p10RawTps < c.minP10RawTps) return {false,"P10_RAW_TPS"};
    if (s.medianRawTps < c.minMedianRawTps) return {false,"MEDIAN_RAW_TPS"};
    if (s.p10RooflineFraction < c.minP10RooflineFraction)
        return {false,"P10_ROOFLINE"};
    if (s.medianRooflineFraction < c.minMedianRooflineFraction)
        return {false,"MEDIAN_ROOFLINE"};
    if (s.p10BandwidthFraction < c.minP10BandwidthFraction)
        return {false,"P10_BANDWIDTH"};
    if (s.p10ComputeFraction < c.minP10ComputeFraction)
        return {false,"P10_COMPUTE"};
    if (s.medianOverlap < c.minMedianOverlap) return {false,"OVERLAP"};
    if (s.p90Skew > c.maxP90Skew) return {false,"SKEW"};
    if (s.p90HostSync > c.maxP90HostSync) return {false,"HOST_SYNC"};
    if (s.p90QueueIdle > c.maxP90QueueIdle) return {false,"QUEUE_IDLE"};
    return {true,"PASS"};
}

} // namespace Deep2
