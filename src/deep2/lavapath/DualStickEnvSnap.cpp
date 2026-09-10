/* DualStickEnvSnap.cpp — requested→harness→dualstick env provenance. */
#include "DualStickStreamWindow.hpp"
#include <cstdlib>
#include <cstring>

namespace Deep2 {

struct EnvSnap {
    char policyRequested[32]{};
    char policyAfterHarness[32]{};
    char policyAfterDualstick[32]{};
    char nameRequested[128]{};
    char nameAfterDualstick[64]{};
    char marsRequested[16]{};
    char marsEffective[16]{};
    char elasticRequested[16]{};
    char elasticEffective[16]{};
    int  nameCleared = 0;
};

static EnvSnap& Snap() {
    static EnvSnap s;
    return s;
}

static void Take(char* dst, size_t n, const char* a, const char* b) {
    const char* v = std::getenv(a);
    if (!v || !*v) v = b ? std::getenv(b) : nullptr;
    if (!v || !*v) std::snprintf(dst, n, "UNSET");
    else std::snprintf(dst, n, "%s", v);
}

void DualStickEnvSnapRequested() {
    EnvSnap& s = Snap();
    Take(s.policyRequested, sizeof(s.policyRequested), "DEEP2_GPU_POLICY",
         "RAWRXD_GPU_POLICY");
    Take(s.nameRequested, sizeof(s.nameRequested), "RAWRXD_GPU_NAME",
         "DEEP2_GPU_SELECT");
    Take(s.marsRequested, sizeof(s.marsRequested), "DEEP2_MARS", nullptr);
    Take(s.elasticRequested, sizeof(s.elasticRequested),
         "RAWRXD_DEEP2_ALLOW_ELASTIC", nullptr);
}

void DualStickEnvSnapAfterHarness() {
    EnvSnap& s = Snap();
    Take(s.policyAfterHarness, sizeof(s.policyAfterHarness), "DEEP2_GPU_POLICY",
         "RAWRXD_GPU_POLICY");
}

void DualStickEnvSnapAfterDualstick() {
    EnvSnap& s = Snap();
    Take(s.policyAfterDualstick, sizeof(s.policyAfterDualstick),
         "DEEP2_GPU_POLICY", "RAWRXD_GPU_POLICY");
    Take(s.nameAfterDualstick, sizeof(s.nameAfterDualstick), "RAWRXD_GPU_NAME",
         "DEEP2_GPU_SELECT");
    /* DualStickNoTruncate clears name to empty → report CLEARED. */
    const char* nm = std::getenv("RAWRXD_GPU_NAME");
    const char* sel = std::getenv("DEEP2_GPU_SELECT");
    if ((!nm || !*nm) && (!sel || !*sel)) {
        std::snprintf(s.nameAfterDualstick, sizeof(s.nameAfterDualstick),
                      "CLEARED");
        s.nameCleared = 1;
    }
    Take(s.marsEffective, sizeof(s.marsEffective), "DEEP2_MARS", nullptr);
    /* ALLOW only — do not label as EFFECTIVE. STACK elastic=N is authority. */
    Take(s.elasticEffective, sizeof(s.elasticEffective),
         "RAWRXD_DEEP2_ALLOW_ELASTIC", nullptr);
}

void EmitDualStickEnvAuthority(FILE* f) {
    if (!f) f = stderr;
    EnvSnap& s = Snap();
    const int polH = std::strcmp(s.policyRequested, s.policyAfterHarness) != 0;
    const int polD = std::strcmp(s.policyAfterHarness, s.policyAfterDualstick) != 0;
    const int nameMut = std::strcmp(s.nameRequested, s.nameAfterDualstick) != 0;
    const char* polOwn =
        polD ? "DualStickNoTruncate" : (polH ? "StreamerArmSpeedEnv" : "NONE");
    std::fprintf(f,
        "GPU_POLICY_REQUESTED=%s\nGPU_POLICY_AFTER_HARNESS=%s\n"
        "GPU_POLICY_AFTER_DUALSTICK=%s\nGPU_POLICY_EFFECTIVE=%s\n"
        "GPU_NAME_REQUESTED=%s\nGPU_NAME_AFTER_DUALSTICK=%s\n"
        "GPU_NAME_CLEAR_OWNER=%s\nMARS_REQUESTED=%s\nMARS_EFFECTIVE=%s\n"
        "ELASTIC_REQUESTED=%s\nELASTIC_ALLOW=%s\n"
        "ELASTIC_EFFECTIVE_NOTE=use_STACK_elastic_not_ALLOW\n"
        "ENV_MUTATION_GPU_POLICY=%d\nENV_MUTATION_GPU_POLICY_OWNER=%s\n"
        "ENV_MUTATION_GPU_NAME=%d\nENV_MUTATION_GPU_NAME_OWNER=%s\n",
        s.policyRequested, s.policyAfterHarness, s.policyAfterDualstick,
        s.policyAfterDualstick[0] ? s.policyAfterDualstick : "UNSET",
        s.nameRequested, s.nameAfterDualstick,
        s.nameCleared ? "DualStickNoTruncate" : "NONE", s.marsRequested,
        s.marsEffective, s.elasticRequested, s.elasticEffective, polH || polD,
        polOwn, nameMut, nameMut ? "DualStickNoTruncate" : "NONE");
}
} // namespace Deep2
