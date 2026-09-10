#pragma once
/* IF=TPS_READY ELSE=* ELSE_IF=UNDEP_LOOP(*)
 * IDLE_WHILE_RUNNABLE_EXISTS=0  VIOLATE_DEPENDENCIES=0
 * wait_for_any_dependency only when * empty. ≤95 lines. */
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

namespace rawr::sched {

enum class Arm : uint8_t {
    Tps = 0,
    Star = 1,       /* ELSE=* progressed → rescan immediately */
    UndepLoop = 2,  /* ELSE_IF: still not ready, * empty → physical wait */
    WaitDep = 3     /* only unavoidable physical wait */
};

inline constexpr int POLICY_LEGALITY_REQUIRED = 0;
inline constexpr int DEPENDENCY_CORRECTNESS_REQUIRED = 1;
inline constexpr int NEVER_IDLE_BY_POLICY = 1;
inline constexpr int IDLE_WHILE_RUNNABLE_EXISTS = 0;
inline constexpr int VIOLATE_DEPENDENCIES = 0;

struct WorkItem {
    const char* name = "";
    bool (*depReady)() = nullptr; /* own producer complete — no inheritance */
    void (*run)() = nullptr;
};

inline bool DepOk(const WorkItem& w) noexcept {
    return !w.depReady || w.depReady();
}

inline bool Runnable(const WorkItem& w) noexcept {
    if (!w.run) return false;
    /* Ignore policy/owner/promote/hot. Never inherit another object's readiness. */
    return DepOk(w);
}

/* Tick: TPS → *; if progressed rescan; else WaitDep (physical only). */
inline Arm Tick(bool tpsReady, WorkItem* items, size_t n,
                uint32_t* starRuns, uint32_t* undepCycles) noexcept {
    if (tpsReady) return Arm::Tps;

    bool progressed = false;
    if (items && n) {
        for (size_t i = 0; i < n; ++i) {
            if (!Runnable(items[i])) continue;
            items[i].run();
            progressed = true;
            if (starRuns) ++(*starRuns);
        }
    }

    if (progressed) {
        if (undepCycles) ++(*undepCycles);
        return Arm::Star; /* immediately sweep * again */
    }

    if (undepCycles) ++(*undepCycles);
    return Arm::WaitDep; /* wait_for_any_dependency — unavoidable only */
}

inline bool ForceReverseDepOverrideArmed() noexcept {
    const char* e = std::getenv("FORCE_REVERSE_DEP");
    return e && e[0] == '1' && e[1] == '\0';
}

inline void EmitLaw(FILE* f) noexcept {
    if (!f) f = stderr;
    std::fprintf(f,
                 "SCHED_LAW=IF_TPS_ELSE_STAR_ELSE_IF_UNDEP\n"
                 "POLICY_LEGALITY_REQUIRED=0\n"
                 "OWNER_PROMOTION_HOT=NOT_A_SCHEDULER_BLOCK\n"
                 "DEPENDENCY_CORRECTNESS_REQUIRED=1\n"
                 "VIOLATE_DEPENDENCIES=0\n"
                 "IDLE_WHILE_RUNNABLE_EXISTS=0\n"
                 "NEVER_IDLE_BY_POLICY=1\n"
                 "WAIT=RESCAN_STAR|WAIT_FOR_ANY_DEPENDENCY\n"
                 "FORCE_REVERSE_DEP_CANARY=%d\n"
                 "CANARY_ONLY=1 BAD_STATE_AUTHORITATIVE=0\n",
                 ForceReverseDepOverrideArmed() ? 1 : 0);
}

} // namespace rawr::sched
