// ============================================================================
// WeightConsumptionCensus.cpp — RAWRXD_WEIGHT_CONSUMPTION_CENSUS_001
// ============================================================================
#include "WeightConsumptionCensus.hpp"

namespace rawrxd::deep2::weightcensus {

WeightConsumptionCensus& WeightConsumptionCensus::instance() {
    static WeightConsumptionCensus inst;
    return inst;
}

bool WeightConsumptionCensus::record(const Event& ev) {
    std::lock_guard<std::mutex> lock(mtx_);
    CensusRecord rec;
    rec.event    = ev;
    rec.sequence = nextSeq_++;
    records_.push_back(std::move(rec));
    return true;
}

std::vector<CensusRecord> WeightConsumptionCensus::records() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return records_;
}

void WeightConsumptionCensus::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    records_.clear();
    nextSeq_ = 1;
}

WeightConsumptionCensus::Summary WeightConsumptionCensus::summary() const {
    std::lock_guard<std::mutex> lock(mtx_);
    Summary s{};
    s.totalEvents = records_.size();
    for (const auto& r : records_) {
        s.totalBytes += r.event.bytes;
        switch (r.event.route) {
            case Route::Bypass:          ++s.bypassCount;     break;
            case Route::LinearWDelegated: ++s.delegatedCount; break;
            case Route::LinearWOwned:    ++s.ownedCount;      break;
            default: break;
        }
    }
    return s;
}

} // namespace rawrxd::deep2::weightcensus
