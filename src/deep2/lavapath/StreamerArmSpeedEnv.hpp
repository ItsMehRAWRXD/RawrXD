#pragma once
/* Product streamer ArmSpeed defaults (SetEnvIfUnset). Shared by harness + agentic. */
#include "ParseMibBudget.hpp"
#include "SetEnvDual.hpp"
#include <cstdio>
#include <cstdlib>

namespace Deep2 {

/* Returns 1 if weight budget parses; 0 fail-closed (caller exit 4). */
inline int StreamerArmSpeedEnvCore(FILE* receipt = stderr) {
    SetEnv("TOKEN_PACING", "OFF");
    SetEnv("DECODE_SLEEP", "0");
    SetEnv("DEEP2_CERT_STEP_LOG", "0");
    SetEnv("QKV_OWNER_RESI_LOG", "0");
    SetEnv("TOK_RESIDUAL_SPAM", "0");
    SetEnv("RAWRXD_FFN_TRACE", "0");
    SetEnv("DUST2_FTL", "0");
    /* DualStick+cyclone+mars+elastic+stream(reverse bunnyhop).
     * POLICY=MANUAL preserves LIVE_MECH (TRAMPOLINE force-clobbers cyclone). */
    SetEnvIfUnset("DEEP2_LIVE_POLICY", "MANUAL");
    SetEnvIfUnset("DEEP2_LIVE_MECH", "trampoline,cyclone,elastic,stream");
    SetEnvIfUnset("DEEP2_LIVE_PATH", "1");
    SetEnvIfUnset("DEEP2_GEN_ALG", "lukewarm");
    SetEnvIfUnset("RAWRXD_HOST_DECODE", "0");
    SetEnvIfUnset("DEEP2_GPU_POLICY", "MULTI");
    SetEnvIfUnset("DEEP2_GPU_DEVICE_CLASS", "DISCRETE");
    SetEnvIfUnset("RAWRXD_DEEP2_ALLOW_ELASTIC", "1");
    SetEnvIfUnset("DEEP2_MARS", "1");
    SetEnvIfUnset("RAWRXD_NVME_REVERSE_BUNNYHOP", "1");
    SetEnvIfUnset("DEEP2_MINIMAL_ENHANCE", "0");
    SetEnvIfUnset("DEEP2_WEIGHT_BUDGET_MIB", "E8B0M");
    SetEnvIfUnset("FREETOKEN_MICROZONE", "1");
    SetEnvIfUnset("DEEP2_NO_TRUNCATE_NEEDLE", "1");
    const char* budIn = std::getenv("DEEP2_WEIGHT_BUDGET_MIB");
    MibParseResult bud = ParseMibTokenEx(budIn);
    EmitWeightBudgetReceipt(receipt ? receipt : stderr, bud, "ENV");
    if (receipt != stdout)
        EmitWeightBudgetReceipt(stdout, bud, "ENV");
    if (!bud.ok) {
        std::fprintf(stderr, "MARS_ARMED=0 WEIGHT_BUDGET_PARSE=FAIL\n");
        return 0;
    }
    std::fprintf(stderr,
                 "KEN_MARS_ACTIVE=1 DEEP2_MARS=%s HOST_DECODE=%s "
                 "GPU_POLICY=%s GPU_DEVICE_CLASS=%s NO_TRUNCATE_NEEDLE=1 "
                 "PRODUCT_STREAMER_ARM=1\n",
                 std::getenv("DEEP2_MARS") ? std::getenv("DEEP2_MARS") : "?",
                 std::getenv("RAWRXD_HOST_DECODE")
                     ? std::getenv("RAWRXD_HOST_DECODE")
                     : "?",
                 std::getenv("DEEP2_GPU_POLICY") ? std::getenv("DEEP2_GPU_POLICY")
                                                : "?",
                 std::getenv("DEEP2_GPU_DEVICE_CLASS")
                     ? std::getenv("DEEP2_GPU_DEVICE_CLASS")
                     : "?");
    return 1;
}

} // namespace Deep2
