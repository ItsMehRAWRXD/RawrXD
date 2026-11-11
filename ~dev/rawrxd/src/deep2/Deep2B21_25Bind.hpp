#pragma once
#include "Deep2B21QuantPack.hpp"
#include "Deep2B22LdsReuse.hpp"
#include "Deep2B23PersistentQueue.hpp"
#include "Deep2B24SpecDecode.hpp"
#include "Deep2B25Autotune.hpp"

namespace Deep2 {

struct B21_25BackendOps {
    void* user = nullptr;
    bool (*applyQuantPack)(void*, const QuantPackPlan&) = nullptr;
    bool (*applyLdsReuse)(void*, const LdsReusePlan&) = nullptr;
    bool (*installPersistentQueue)(void*, const PersistentQueuePlan&) = nullptr;
    bool (*configureSpecDecode)(void*, const SpecDecodePlan&) = nullptr;
    bool (*applyTuneCandidate)(void*, const TuneCandidate&) = nullptr;
};

inline bool ApplyB21_25(B21_25BackendOps& o,
                        const QuantPackPlan& qp,
                        const LdsReusePlan& lds,
                        const PersistentQueuePlan& pq,
                        const SpecDecodePlan& sd,
                        const TuneCandidate& tc) {
    if (o.applyQuantPack && !o.applyQuantPack(o.user, qp)) return false;
    if (o.applyLdsReuse && !o.applyLdsReuse(o.user, lds)) return false;
    if (o.installPersistentQueue && !o.installPersistentQueue(o.user, pq)) return false;
    if (o.configureSpecDecode && !o.configureSpecDecode(o.user, sd)) return false;
    if (o.applyTuneCandidate && !o.applyTuneCandidate(o.user, tc)) return false;
    return true;
}

}
