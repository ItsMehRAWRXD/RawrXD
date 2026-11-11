#pragma once
#include "Deep2B36WaveDot.hpp"
#include "Deep2B37RegisterTune.hpp"
#include "Deep2B38CoopGemv.hpp"
#include "Deep2B39FamilySpecializer.hpp"
#include "Deep2B40PhysicalSeal.hpp"

namespace Deep2 {

struct B36_40BackendOps {
    void* user = nullptr;
    bool (*applyWaveDot)(void*, const B36WaveDotPlan&) = nullptr;
    bool (*applyRegisterTune)(void*, const B37RegisterPlan&) = nullptr;
    bool (*applyCoopGemv)(void*, const B38CoopPlan&) = nullptr;
    bool (*applyFamilySpecializer)(void*, const B39FamilyPlan&) = nullptr;
    bool (*applyPhysicalSeal)(void*, const B40PhysicalStats&) = nullptr;
};

inline bool ApplyB36_40(B36_40BackendOps& o,
                        const B36WaveDotPlan& a,
                        const B37RegisterPlan& b,
                        const B38CoopPlan& c,
                        const B39FamilyPlan& d,
                        const B40PhysicalStats& e) {
    if (o.applyWaveDot && !o.applyWaveDot(o.user, a)) return false;
    if (o.applyRegisterTune && !o.applyRegisterTune(o.user, b)) return false;
    if (o.applyCoopGemv && !o.applyCoopGemv(o.user, c)) return false;
    if (o.applyFamilySpecializer && !o.applyFamilySpecializer(o.user, d)) return false;
    if (o.applyPhysicalSeal && !o.applyPhysicalSeal(o.user, e)) return false;
    return true;
}

} // namespace Deep2