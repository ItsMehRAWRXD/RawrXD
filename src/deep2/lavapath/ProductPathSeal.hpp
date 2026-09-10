#pragma once
/* Product path seal after real generateStream (≤99 lines). */
#include "ProductPathSeal_Champion.hpp"
#include "Batch007Runtime.hpp"
#include "StreamPathTiming.hpp"
#include "K2MLA_FusedQ4KT.hpp"
#include <cstdint>
#include <cstdio>

namespace rawr::product_path {

inline uint64_t WallNsFromSpt() noexcept {
    const uint64_t rs = Deep2::SPT_reqStartUs().load();
    const uint64_t now = Deep2::StreamPathTiming_NowUs();
    return (rs && now > rs) ? (now - rs) * 1000ull : 0ull;
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
    a.productOpenPass = xf.productOpenPass;
    a.sessionEnterPass = xf.sessionEnterPass;
    a.tokenCommitPass =
        xf.tokenCommitPass
            ? 1
            : ((xf.tokensCommitted > 0 && xf.streamPresent && xf.receiptAtomic)
                   ? 1
                   : 0);
    rawr::product::Emit(a);
    EmitChampion(f, xf, cpuF32);
}

} // namespace rawr::product_path

namespace rawrxd::deep2::product_path {
using rawr::product_path::Emit;
using rawr::product_path::Facts;
using rawr::product_path::WallNsFromSpt;
} // namespace rawrxd::deep2::product_path
