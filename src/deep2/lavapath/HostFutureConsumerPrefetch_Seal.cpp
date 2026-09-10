/* HostFutureConsumerPrefetch_Seal.cpp — BIND + R26 product-decode seal. */
#include "HostFutureConsumerPrefetch.hpp"
#include "HostFutureConsumerPrefetch_Internal.hpp"

namespace Deep2 {
namespace hostfc {

void SealDecode(int tokenSurvived, FILE* f) {
    detail::St& s = detail::S();
    if (s.armed && !s.p10.load() && s.lastEntered != ~0u)
        ExitLayer(s.lastEntered);
    s.tokenSurvived = tokenSurvived ? 1 : 0;
    detail::StopWorker();
    if (!f) f = stderr;
    const int p11 = future::PhysicalPoolGrows();
    const int chairWake = s.pChairWake.load();
    const int scanClosed = s.pScanClosed.load();
    const int productDecode =
        (s.p01 && s.tokenSurvived && chairWake && scanClosed) ? 1 : 0;
    std::fprintf(f,
        "GATE=G3_HOST_FUTURECONSUMER_BIND_001\n"
        "PARENT=G3_HOST_FUTURECONSUMER_P01_P12_001\n"
        "R26_GATE=G3_IDE_RESIDUAL_R26_001\n"
        "P01_PRODUCT_OPEN=%d\nP12_PRODUCT_DECODE=%d\n"
        "P_CHAIR_WAKE=%d\nP_SCAN_FAIL_CLOSED=%d\n"
        "PRODUCT_DECODE_PASS=%d\nLIVE_HOST_DECODE_COMMITTED=%d\n"
        "FC_BIND_ENTER=%d\nFC_BIND_OK=%d\nFC_CONSUMER_ID_VALID=%d\n"
        "PREFETCH_CPU_ENTER=%d\nPREFETCH_CPU_CONSUMER_BOUND=%d\n"
        "PREFETCH_CPU_OK=%d\n"
        "P02=%d P03=%d P04=%d P05=%d P06=%d P07=%d P08=%d P09=%d P10=%d P11=%d\n"
        "KN_O3_REACHED=%d\nKN_O3_STATUS=%d\nKN_O3_RESULT=%llu\n"
        "KN_O3_TOKEN_WALL_NS=%llu\n"
        "FUT_CHAIR=%u\nFUT_EXPECTED_GEN=%u\n"
        "ELASTIC_RESIDENCY=0\nPROMOTE=0\nTIP_CLIMB=HOLD\n",
        s.p01, s.tokenSurvived, chairWake, scanClosed, productDecode,
        s.tokenSurvived, s.fcBindEnter.load(), s.fcBindOk.load(),
        s.fcConsumerIdValid.load(), s.prefetchCpuEnter.load(),
        s.prefetchCpuBound.load(), s.prefetchCpuOk.load(), s.p02, s.p03, s.p04,
        s.p05.load(), s.p06.load(), s.p07.load(), s.p08.load(), s.p09.load(),
        s.p10.load(), p11, KnO3Reached(), LastKnO3Status(),
        (unsigned long long)LastKnO3Result(),
        (unsigned long long)LastKnO3TokenWallNs(), (unsigned)s.futChair,
        (unsigned)s.futExpectedGen);
    future::EmitExec(f, (uint32_t)s.tokenSurvived, 0);
    std::fflush(f);
}

} /* namespace hostfc */
} /* namespace Deep2 */
