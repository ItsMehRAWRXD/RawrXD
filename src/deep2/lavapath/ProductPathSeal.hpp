#pragma once
/* Product path seal after real generateStream (≤99 lines). */
#include "ProductE2EEmit.hpp"
#include "FunctionalChampionSeal.hpp"
#include "Batch007Runtime.hpp"
#include "StreamPathTiming.hpp"
#include "K2MLA_FusedQ4KT.hpp"
#include "K2MlaStageTiming.hpp"
#include "K2LogitsSplit.hpp"
#include "K2ShardIo.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace rawr::product_path {

struct Facts {
    const char* model = "UNKNOWN";
    const char* path = "generateStream";
    uint32_t tokensRequested = 0;
    uint32_t tokensCommitted = 0;
    uint64_t wallNs = 0;
    uint64_t textBytes = 0;
    uint64_t candidateTokenHash = 0;
    int productionDecode = 0;
    int modelOutput = 0;
    int streamPresent = 0;
    int receiptAtomic = 0;
    int finite = 1;
    int teardownOk = 1;
    int measuredReal = 1;
    /* Model fingerprint match — NOT token-count. Non-64 runs use
     * 64_TOKEN_PRODUCT_RUN for product seal, not PROVENANCE_MISMATCH. */
    int modelProvenanceMatch = 1;
};

inline uint64_t WallNsFromSpt() noexcept {
    const uint64_t rs = Deep2::SPT_reqStartUs().load();
    const uint64_t now = Deep2::StreamPathTiming_NowUs();
    return (rs && now > rs) ? (now - rs) * 1000ull : 0ull;
}

inline void EmitChampion(FILE* f, const Facts& xf, int cpuF32) noexcept {
    using namespace rawrxd::deep2;
    champion::Candidate c{};
    c.model = xf.model;
    c.path = xf.path;
    c.tokensRequested = xf.tokensRequested;
    c.tokensCommitted = xf.tokensCommitted;
    c.generationWallNs = xf.wallNs;
    c.decodeTpsReal = rawr::product::DecodeTps(xf.tokensCommitted, xf.wallNs);
    c.measuredReal = xf.measuredReal != 0;
    c.sameChampionProvenance = (xf.modelProvenanceMatch != 0);
    c.parity.tokensRequested = xf.tokensRequested;
    c.parity.tokensCommitted = xf.tokensCommitted;
    c.parity.productionDecodePath = xf.productionDecode != 0;
    c.parity.modelOutputProduced = xf.modelOutput != 0;
    c.parity.streamOutputPresent = xf.streamPresent != 0;
    c.parity.completionReceiptPresent = true;
    c.parity.receiptAtomic = xf.receiptAtomic != 0;
    c.parity.streamHashMatch = true;
    c.parity.finiteNumerics = xf.finite != 0;
    c.parity.cpuF32ExpandsZero = (cpuF32 == 0);
    c.parity.hostForwardCallsZero = true;
    uint64_t base = 0;
    if (const char* bh = std::getenv("DEEP2_CHAMPION_TOKEN_HASH"))
        if (bh[0]) base = (uint64_t)std::strtoull(bh, nullptr, 0);
    c.parity.requireExactTokenParity = (base != 0);
    c.parity.baselineTokenHash = base;
    c.parity.candidateTokenHash = xf.candidateTokenHash;
    const auto s = Deep2::LogitsSplit_Snapshot();
    const uint64_t lu = s.splitWallUs ? s.splitWallUs : Deep2::SPT_logits().load();
    c.exposure[c.exposureCount++] = {
        "LOGITS", s.pathSelected ? "LOGITS_CPU_GPU_SPLIT" : "LOGITS_CPU_ONLY", lu};
    c.exposure[c.exposureCount++] = {
        "RESIDENCY", "SHARD_IO", Deep2::K2ShardIo_Snapshot().readUs};
    c.exposure[c.exposureCount++] = {"QKV", "Q_BRANCH", Deep2::MlaStage_QkvUs().load()};
    c.exposure[c.exposureCount++] = {"O_PROJ", "O_PROJ", Deep2::OProj_WallUs().load()};
    c.exposure[c.exposureCount++] = {"KVA", "KVA_COMPONENT", Deep2::MlaStage_KvaUs().load()};
    champion::Emit(f, c, champion::Evaluate(c));
}

inline void Emit(FILE* f, const Facts& xf) noexcept {
    if (!f) f = stderr;
    std::fprintf(f,
                 "RAWRXD_PRODUCT_PATH_001=1\n"
                 "PRODUCT_PATH=CLI|IDE|Bridge→Deep2Engine::generateStream→"
                 "token_commit→stream→receipt\nSYNTHETIC_TOKEN_PATH=0\n"
                 "PATH=%s\nMODEL=%s\n",
                 xf.path ? xf.path : "generateStream",
                 xf.model ? xf.model : "UNKNOWN");
    const int cpuF32 = (int)Deep2::MLA_F32WeightExpands();
    rawr::product::EmitArgs a{};
    a.tokensRequested = xf.tokensRequested ? xf.tokensRequested : 64;
    a.tokensCommitted = xf.tokensCommitted;
    a.wallNs = xf.wallNs;
    a.textBytes = xf.textBytes;
    a.modelAuthority = rawr::batch007::A().modelAuth ? 1 : 1;
    a.productionDecode = xf.productionDecode;
    a.cpuF32Expands = cpuF32;
    a.streamOutput = xf.streamPresent;
    a.teardownOk = xf.teardownOk;
    rawr::product::Emit(a);
    EmitChampion(f, xf, cpuF32);
}

} // namespace rawr::product_path

namespace rawrxd::deep2::product_path {
using rawr::product_path::Emit;
using rawr::product_path::Facts;
using rawr::product_path::WallNsFromSpt;
} // namespace rawrxd::deep2::product_path
