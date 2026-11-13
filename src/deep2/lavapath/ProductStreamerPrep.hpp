#pragma once
/* Agentic/product gateway: ArmSpeed + DualStick + FreeToken (not SemanticSafe). */
#include "StreamerArmSpeedEnv.hpp"
#include "DualStickStreamWindow.hpp"
#include "FreeTokenMicroZone.hpp"
#include "FutureConsumerSpace.hpp"
#include "ProcessLargeAddressAware.hpp"
#include "ExperimentalSsmAuth.hpp"
#include "../SemanticSafe.hpp"
#include <atomic>
#include <cstdlib>

namespace Deep2 {

/* Opt-in SemanticSafe if already wanted; else product streamer stack. */
inline int ProductStreamerPrep() {
    if (SemanticSafeWanted()) {
        SemanticSafeApply();
        return 1;
    }
    static std::atomic<int> armed{0};
    if (armed.load() != 0) return 1;
    if (!StreamerArmSpeedEnvCore(stderr)) return 0;
    /* GPU-required product default (no CPU-only benches/IDE/CLI).
     * Opt into HOST_DECODE only via RAWRXD_HOST_DECODE=1 or RAWR_FORCE_CPU=1.
     * LAA:NO still forces host floor (VA). */
    SetEnvIfUnset("RAWRXD_ALLOW_GPU", "1");
    const char* forceCpu = std::getenv("RAWR_FORCE_CPU");
    const char* hostDec = std::getenv("RAWRXD_HOST_DECODE");
    const char* allowGpu = std::getenv("RAWRXD_ALLOW_GPU");
    const bool explicitHost =
        (hostDec && hostDec[0] == '1') || (forceCpu && forceCpu[0] == '1');
    const bool gpuOk = allowGpu && allowGpu[0] == '1' && !explicitHost;
    const bool hostFloor = !ProcessIsLargeAddressAware() || !gpuOk;
    if (hostFloor) {
        SetEnv("RAWRXD_HOST_DECODE", "1");
        SetEnv("DEEP2_DUALSTICK_ARM", "0");
        SetEnv("DEEP2_LIVE_PATH", "0");
        SetEnv("RAWRXD_LIVE_PATH", "0");
        /* ArmSpeed SetEnvIfUnset pins MANUAL+trampoline+E8B0M — neutralize. */
        SetEnv("DEEP2_LIVE_POLICY", "OFF");
        SetEnv("DEEP2_LIVE_MECH", "none");
        /* B04/B02: keep elastic — multi-shard HOST_DECODE acquires via fileOffset. */
        SetEnvIfUnset("RAWRXD_DEEP2_ALLOW_ELASTIC", "1");
        /* B04: capture ArmSpeed SetEnvIfUnset("E8B0M") BEFORE host-floor overwrite. */
        char rawBud[64] = {};
        const char* preFloorSrc = "UNSET";
        if (const char* p = std::getenv("DEEP2_WEIGHT_BUDGET_MIB")) {
            size_t n = 0;
            while (p[n] && n + 1 < sizeof(rawBud)) {
                rawBud[n] = p[n];
                ++n;
            }
            rawBud[n] = 0;
            preFloorSrc = "ARMSPEED_SETENVIFUNSET_OR_USER";
        }
        const char* explicitBudget = std::getenv("WEIGHT_BUDGET_MIB");
        const char* postFloorSrc = "HOST_FLOOR_RAM_EIGHTH";
        if (explicitBudget && explicitBudget[0]) {
            SetEnv("DEEP2_WEIGHT_BUDGET_MIB", explicitBudget);
            postFloorSrc = "USER_WEIGHT_BUDGET_MIB";
        } else {
            MEMORYSTATUSEX memStatus{};
            memStatus.dwLength = sizeof(memStatus);
            GlobalMemoryStatusEx(&memStatus);
            const unsigned __int64 totalRAM = memStatus.ullTotalPhys;
            const unsigned __int64 eighthRAM = totalRAM / 8;
            unsigned __int64 defaultMib = 2048ULL;
            if (eighthRAM > defaultMib * 1024ULL * 1024ULL)
                defaultMib = eighthRAM / (1024ULL * 1024ULL);
            if (defaultMib > 32768ULL)
                defaultMib = 32768ULL;
            char buf[64] = {};
            _snprintf_s(buf, sizeof(buf), "%llu", (unsigned long long)defaultMib);
            SetEnv("WEIGHT_BUDGET_MIB", buf);
            SetEnv("DEEP2_WEIGHT_BUDGET_MIB", buf);
        }
        /* WEIGHT_BUDGET_BYTES unset so WEIGHT_BUDGET_MIB path is authoritative. */
        {
            MibParseResult raw = ParseMibTokenEx(rawBud[0] ? rawBud : nullptr);
            const char* effStr = std::getenv("DEEP2_WEIGHT_BUDGET_MIB");
            MibParseResult eff = ParseMibTokenEx(effStr);
            EmitWeightBudgetReceipt(stderr, eff, postFloorSrc);
            std::fprintf(stderr,
                         "WEIGHT_BUDGET_PRE_FLOOR_SRC=%s\n"
                         "WEIGHT_BUDGET_PRE_FLOOR_RAW=\"%s\"\n"
                         "WEIGHT_BUDGET_PRE_FLOOR_MIB=%llu\n"
                         "WEIGHT_BUDGET_POST_FLOOR_SRC=%s\n"
                         "WEIGHT_BUDGET_ENV_PRESENT=%d\n"
                         "WEIGHT_BUDGET_ENV_RAW=\"%s\"\n"
                         "WEIGHT_BUDGET_PARSE_OK=%d\n"
                         "WEIGHT_BUDGET_INPUT_MIB=%llu\n"
                         "WEIGHT_BUDGET_EFFECTIVE_MIB=%llu\n"
                         "RESIDENCY_BUDGET_MIB=%llu\n"
                         "BUDGET_RELATION_VALID=%d\n"
                         "NOTE=REAP_TARGET_NE_RESIDENCY_BUDGET; "
                         "ARMSPEED_E8B0M_IS_SETENVIFUNSET_DEFAULT; "
                         "MODEL_SIZE_NE_PHYSICAL_RESIDENCY\n",
                         preFloorSrc, rawBud[0] ? rawBud : "(unset)",
                         (unsigned long long)(raw.ok ? raw.mib : 0ULL),
                         postFloorSrc, effStr && effStr[0] ? 1 : 0,
                         effStr ? effStr : "(unset)", eff.ok,
                         (unsigned long long)(eff.ok ? eff.mib : 0ULL),
                         (unsigned long long)(eff.ok ? eff.mib : 0ULL),
                         (unsigned long long)(eff.ok ? eff.mib : 0ULL),
                         (eff.ok && eff.mib > 0) ? 1 : 0);
            std::fflush(stderr);
        }
        SetEnv("DEEP2_GPU_FWD", "0");
        SetEnv("RAWRXD_GPU_FWD", "0");
        SetEnv("DEEP2_MARS", "0");
        SetEnv("DEEP2_MINIMAL_ENHANCE", "1");
        /* HOST_DECODE move is mmap NVMe→RAM, not reverse-chunk bunnyhop. */
        SetEnv("RAWRXD_NVME_REVERSE_BUNNYHOP", "0");
        /* Force Vulkan loader off ICD scan (relative .\amdvlk64.dll + missing
         * System32 copy → ERROR_INVALID_PARAMETER / error 87 MessageBox). */
        SetEnv("VK_ICD_FILENAMES", "C:\\rawrxd_blocked_no_vulkan_icd.json");
        SetEnv("VK_DRIVER_FILES", "C:\\rawrxd_blocked_no_vulkan_icd.json");
        SetEnv("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
        DualStickMarkRequested(false);
        freetoken::Init(FREETOKEN_ZONE_BYTES, 4);
        future::InitFromPhysicalPool();
        armed.store(1);
        std::fprintf(stderr,
                     "PRODUCT_LAA=%d HOST_DECODE=1 DUALSTICK_ARM=0 "
                     "MINIMAL_ENHANCE=1 VK_ICD=BLOCKED WHY=R1_HOST_FLOOR\n"
                     "PRODUCT_STREAMER_PREP=1 AGENTIC_PATH=1\n",
                     ProcessIsLargeAddressAware() ? 1 : 0);
        if (experimental_ssm::AllowFlag())
            experimental_ssm::EmitAuthResume(stderr, 0);
        std::fflush(stderr);
        return 1;
    }
    const char* armDs = std::getenv("DEEP2_DUALSTICK_ARM");
    DualStickMarkRequested(!(armDs && armDs[0] == '0'));
    DeviceManagerSnapshot snap{};
    MibParseResult bud =
        ParseMibTokenEx(std::getenv("DEEP2_WEIGHT_BUDGET_MIB"));
    if (Deep2Device_Enumerate(snap)) {
        (void)Deep2Device_ApplyPolicy(snap);
        if (!(armDs && armDs[0] == '0')) {
            DualStickWindowPlan wp =
                PlanDualStickWindows(snap, bud.bytes);
            ArmDualStickNoTruncate(wp);
        }
    }
    SetEnvIfUnset("DEEP2_GPU_FWD", "1");
    SetEnvIfUnset("RAWRXD_GPU_FWD", "1");
    SetEnv("RAWRXD_HOST_DECODE", "0");
    freetoken::Init(FREETOKEN_ZONE_BYTES, 4);
    future::InitFromPhysicalPool();
    armed.store(1);
    std::fprintf(stderr,
                 "PRODUCT_LAA=%d HOST_DECODE=0 ALLOW_GPU=1 "
                 "PRODUCT_STREAMER_PREP=1 AGENTIC_PATH=1 GPU_DEFAULT=1\n",
                 ProcessIsLargeAddressAware() ? 1 : 0);
    if (experimental_ssm::AllowFlag())
        experimental_ssm::EmitAuthResume(stderr, 0);
    std::fflush(stderr);
    return 1;
}

} // namespace Deep2
