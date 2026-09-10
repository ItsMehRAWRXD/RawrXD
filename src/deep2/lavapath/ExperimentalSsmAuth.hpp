#pragma once
/* Experimental SSM auth resume — scaffolding ≠ champion PROMOTE. ≤99.
   User-auth: RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1
   READY still = PromoteReady tetrad; PROMOTE=0; MULTI_FAMILY next. */
#include "Deep2ProductGate.hpp"
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace Deep2 {
namespace experimental_ssm {

inline int AllowFlag() noexcept {
    const char* e = std::getenv("RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM");
    return (e && e[0] == '1') ? 1 : 0;
}

/* Emit when experimental path is entered (load or compute). */
inline void EmitAuthResume(FILE* f, size_t ssmLayers) noexcept {
    if (!f) f = stderr;
    const int allow = AllowFlag();
    std::fprintf(f,
                 "EXPERIMENTAL_SSM_AUTH_RESUME=%d\n"
                 "PROMOTE_AUTHORIZATION=%s\n"
                 "RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=%d\n"
                 "SSM_HYBRID_LAYERS=%zu\n"
                 "EXPERIMENTAL_NEQ_SSM_CERTIFIED_IMPL=1\n"
                 "EXPERIMENTAL_NEQ_CHAMPION_PROMOTE=1\n"
                 "CHAMPION_PROMOTE=0\n"
                 "PROMOTE=0\n"
                 "TIP_CLIMB=HOLD\n"
                 "FINAL_READY_GATE=PRODUCT_OPEN_PASS&&SESSION_ENTER_PASS&&"
                 "GENERATED_TOKENS>0&&TOKEN_COMMIT_PASS\n"
                 "NEXT_INDEPENDENT_GATE=MULTI_FAMILY\n"
                 "NOTE=TINYLLAMA_R25_PRODUCTOPEN_NE_MULTI_FAMILY;"
                 "EXPERIMENTAL_MAY_SATISFY_TETRAD_NOT_CERT\n"
                 "GATE=G3_E_SSM_EXPERIMENTAL_AUTH_001\n",
                 allow,
                 allow ? "RESUME_EXPERIMENTAL_TO_E2E_READY" : "HELD",
                 allow, ssmLayers);
    std::fflush(f);
}

/* Experimental PRODUCT_PASS may use tetrad; never sets PROMOTE=1. */
inline int ExperimentalReady(int openPass, int sessionPass, uint64_t genTok,
                             int commitPass) noexcept {
    if (!AllowFlag()) return 0;
    return product_gate::PromoteReady(openPass, sessionPass, genTok, commitPass);
}

} /* namespace experimental_ssm */
} /* namespace Deep2 */
