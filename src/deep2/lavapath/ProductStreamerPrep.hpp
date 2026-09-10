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
    /* R1 multi-GGUF needs LAA:YES VA (>2GB), but amdvlk ICD remains unsafe.
     * Force HOST_DECODE whenever LAA:NO *or* caller/env opts into CPU floor.
     * Never arm DualStick/ICD on product path unless RAWRXD_ALLOW_GPU=1. */
    const char* allowGpu = std::getenv("RAWRXD_ALLOW_GPU");
    const bool gpuOk = allowGpu && allowGpu[0] == '1';
    const bool hostFloor = !ProcessIsLargeAddressAware() || !gpuOk ||
                           (std::getenv("RAWRXD_HOST_DECODE") &&
                            std::getenv("RAWRXD_HOST_DECODE")[0] == '1');
    if (hostFloor) {
        SetEnv("RAWRXD_HOST_DECODE", "1");
        SetEnv("DEEP2_DUALSTICK_ARM", "0");
        SetEnv("DEEP2_LIVE_PATH", "0");
        SetEnv("RAWRXD_LIVE_PATH", "0");
        /* ArmSpeed SetEnvIfUnset pins MANUAL+trampoline+E8B0M — neutralize. */
        SetEnv("DEEP2_LIVE_POLICY", "OFF");
        SetEnv("DEEP2_LIVE_MECH", "none");
        SetEnv("RAWRXD_DEEP2_ALLOW_ELASTIC", "0");
        /* Capture ArmSpeed/E8B0M raw BEFORE overwriting effective floor. */
        char rawBud[64] = {};
        if (const char* p = std::getenv("DEEP2_WEIGHT_BUDGET_MIB")) {
            size_t n = 0;
            while (p[n] && n + 1 < sizeof(rawBud)) {
                rawBud[n] = p[n];
                ++n;
            }
            rawBud[n] = 0;
        }
        SetEnv("DEEP2_WEIGHT_BUDGET_MIB", "2048");
        /* Deep2Engine ResidencyManager reads WEIGHT_BUDGET_* not DEEP2_*. */
        SetEnv("WEIGHT_BUDGET_MIB", "2048");
        SetEnv("WEIGHT_BUDGET_BYTES", "2147483648");
        {
            MibParseResult raw = ParseMibTokenEx(rawBud[0] ? rawBud : "E8B0M");
            EmitWeightBudgetReceipt(stderr, raw, "ENV_RAW_BEFORE_HOST_FLOOR");
            std::fprintf(stderr,
                         "WEIGHT_BUDGET_ENV_PRESENT=1\n"
                         "WEIGHT_BUDGET_ENV_RAW=\"%s\"\n"
                         "WEIGHT_BUDGET_PARSE_OK=%d\n"
                         "WEIGHT_BUDGET_INPUT_MIB=%llu\n"
                         "WEIGHT_BUDGET_EFFECTIVE_MIB=2048\n"
                         "RESIDENCY_BUDGET_MIB=2048\n"
                         "BUDGET_RELATION_VALID=1\n"
                         "NOTE=MODEL_SIZE_NE_PHYSICAL_RESIDENCY; "
                         "RESIDENCY_LE_PHYSICAL_BUDGET; "
                         "MODEL_SIZE_LE_LOGICAL_ADDRESSABILITY_REQUIRES_LAA\n",
                         raw.input && raw.input[0] ? raw.input : "(empty)",
                         raw.ok, (unsigned long long)raw.mib);
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
    freetoken::Init(FREETOKEN_ZONE_BYTES, 4);
    future::InitFromPhysicalPool();
    armed.store(1);
    std::fprintf(stderr, "PRODUCT_STREAMER_PREP=1 AGENTIC_PATH=1\n");
    if (experimental_ssm::AllowFlag())
        experimental_ssm::EmitAuthResume(stderr, 0);
    std::fflush(stderr);
    return 1;
}

} // namespace Deep2
