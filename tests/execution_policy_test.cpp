// =============================================================================
// execution_policy_test.cpp — P0 adaptive VRAM admission certification.
// =============================================================================
// Verifies: safe budget = device - max(1GiB, device/8); the budget never
// exceeds the physical safe limit; a user-locked cap is NOT overridden by a
// session-level adaptive delta (fail-closed authority).
// =============================================================================
#include <cstdio>
#include <cstdint>

#include "deep2/execution_policy/ExecutionPolicyBridge.hpp"
#include "deep2/execution_policy/ExecutionPolicyStore.hpp"

using namespace Deep2::Exec;

static int g_fail = 0;
static void Check(const char* name, bool ok) {
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) ++g_fail;
}

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    const uint64_t gib = 1ull << 30;

    // 1. Safe budget on a 32 GiB device = 28 GiB.
    {
        uint64_t budget = 0;
        const auto r = ApplyAdaptiveVramAdmission(32 * gib, 18 * gib, &budget);
        Check("admission.ok", r.ok);
        Check("admission.safe_budget_28g", budget == 28 * gib);
        Check("admission.never_above_safe",
              budget <= 32 * gib - (std::max)(1 * gib, (32 * gib) / 8));
    }

    // 2. Model larger than the safe budget does NOT raise the budget.
    {
        uint64_t budget = 0;
        ApplyAdaptiveVramAdmission(32 * gib, 64 * gib, &budget);
        Check("admission.no_inflation_for_big_model", budget == 28 * gib);
    }

    // 3. User-locked cap wins over the session delta.
    {
        ExecutionPolicy lock;
        Bytes cap;
        cap.n = 12 * gib;
        lock.memory.vramBudget.force(cap, SettingAuthority::UserLocked,
                                     SettingMutability::Immediate);
        auto lr = ExecutionPolicyStore::Instance().apply(
            lock, SettingAuthority::UserLocked, "test:user-lock");
        Check("user_lock.applied", lr.ok);
        const auto& eff0 = ActivePolicy().memory.vramBudget;
        std::printf("[INFO] after user lock: present=%d auth=%d n=%llu\n",
                    (int)eff0.present, (int)eff0.authority,
                    (unsigned long long)(eff0.present ? eff0.value.n : 0));
        uint64_t budget = 0;
        const auto r = ApplyAdaptiveVramAdmission(32 * gib, 18 * gib, &budget);
        const auto& eff1 = ActivePolicy().memory.vramBudget;
        std::printf("[INFO] after adaptive: present=%d auth=%d n=%llu ok=%d\n",
                    (int)eff1.present, (int)eff1.authority,
                    (unsigned long long)(eff1.present ? eff1.value.n : 0),
                    (int)r.ok);
        // The session delta must not loosen the user lock.
        const uint64_t effective = PolicyVramHardCapBytes();
        Check("user_lock.stays_authoritative",
              effective == 12 * gib || !r.ok);
    }

    std::printf("EXECUTION_POLICY_TEST %s (failures=%d)\n",
                g_fail == 0 ? "PASS" : "FAIL", g_fail);
    return g_fail == 0 ? 0 : 1;
}