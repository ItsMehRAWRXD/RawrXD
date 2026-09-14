#include "rawrxd/src/deep2/Deep2B61_65Fleet.hpp"
#include <cstdio>
#include <vector>

using namespace Deep2;

static int fail(const char* x) {
    std::printf("FAIL=%s\n",x);
    return 1;
}

static std::vector<ContractSample> synth(const ModelPerformanceContract& c,
                                         double median,
                                         double roofTps,
                                         double roofFrac,
                                         double bw,
                                         double cf,
                                         double overlap,
                                         double skew,
                                         double sync,
                                         double idle) {
    std::vector<ContractSample> out;
    for (int i=0;i<336;++i) {
        ContractSample s{};
        const double wig=double((i%17)-8)*0.006*median;
        s.rawTps=median+wig;
        s.effectiveTps=(median*1.15)+wig;
        s.physicalRooflineTps=roofTps;
        s.rooflineFraction=roofFrac+double(i%5)*.001;
        s.bandwidthFraction=bw+double(i%5)*.001;
        s.computeFraction=cf+double(i%4)*.001;
        s.overlap=overlap+double(i%3)*.001;
        s.skew=skew+double(i%4)*.001;
        s.hostSync=sync+double(i%3)*.0005;
        s.queueIdle=idle+double(i%4)*.0007;
        s.reloadBytes=0;
        s.hostMaterializations=0;
        s.hostTokenCopies=0;
        s.peerCopyBytes=0;
        s.gpu0Forwards=48;
        s.gpu1Forwards=48;
        s.parity=true;
        s.stable=true;
        out.push_back(s);
    }
    return out;
}

static int run_contract(const char* tag,
                        const ModelPerformanceContract& c,
                        const RuntimeModelMeta& m,
                        double median,
                        double roofTps,
                        double roofFrac,
                        double bw,
                        double cf,
                        double overlap,
                        double skew,
                        double sync,
                        double idle) {
    auto v=synth(c,median,roofTps,roofFrac,bw,cf,overlap,skew,sync,idle);
    auto st=FleetContract::summarize(v);
    auto d=FleetContract::certify(c,m,st);
    std::printf("%s_FAMILY=%s\n",tag,FleetContract::familyName(c.envelope.family));
    std::printf("%s_P10_TPS=%.3f MEDIAN_TPS=%.3f P10_ROOF_TPS=%.3f ROOF_FRAC=%.6f CERT=%s\n",
        tag,st.p10RawTps,st.medianRawTps,st.p10PhysicalRooflineTps,
        st.medianRooflineFraction,d.firstFailure);
    if(!d.pass) return 1;
    return 0;
}

int main() {
    auto q=B61QwenNextContract();
    auto n=B62NemotronContract();
    auto g=B63GptOssContract();
    auto l=B64LagunaContract();
    auto d=B65DeepSeekFlashContract();

    if(!FleetContract::metadataMatches(q.envelope,B61QwenNextContractReferenceMeta()))
        return fail("B61_META");
    if(!FleetContract::metadataMatches(n.envelope,B62NemotronContractReferenceMeta()))
        return fail("B62_META");
    if(!FleetContract::metadataMatches(g.envelope,B63GptOssContractReferenceMeta()))
        return fail("B63_META");
    if(!FleetContract::metadataMatches(l.envelope,B64LagunaContractReferenceMeta()))
        return fail("B64_META");
    if(!FleetContract::metadataMatches(d.envelope,B65DeepSeekFlashContractReferenceMeta()))
        return fail("B65_META");

    // Deliberate mismatch check: wrong total size must fail binding.
    auto bad=B61QwenNextContractReferenceMeta();
    bad.totalParamsB=60.0;
    if(FleetContract::metadataMatches(q.envelope,bad))
        return fail("FAIL_CLOSED_META");

    if(run_contract("B61",q,B61QwenNextContractReferenceMeta(),
                    47.0,55.0,.87,.84,.62,.93,.025,.008,.012)) return 1;
    if(run_contract("B62",n,B62NemotronContractReferenceMeta(),
                    73.0,82.0,.89,.82,.64,.94,.024,.008,.012)) return 1;
    if(run_contract("B63",g,B63GptOssContractReferenceMeta(),
                    32.0,38.0,.86,.80,.58,.93,.028,.009,.013)) return 1;
    if(run_contract("B64",l,B64LagunaContractReferenceMeta(),
                    19.0,23.0,.84,.79,.52,.91,.035,.012,.017)) return 1;
    if(run_contract("B65",d,B65DeepSeekFlashContractReferenceMeta(),
                    13.0,16.0,.82,.76,.46,.89,.045,.017,.022)) return 1;

    std::printf("DEEP2_BATCH61_65_SELFTEST=PASS\n");
    std::printf("CONTRACTS=%zu\n",B61_65ShowcaseContracts().size());
    return 0;
}
