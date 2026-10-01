#include "ContinuousEventLedger.hpp"

namespace rawrxd::continuous {

void EventLedger::append(const LedgerEvent& ev) {
    std::lock_guard<std::mutex> lk(mu_);
    LedgerEvent copy = ev;
    copy.sequence = nextSeq_++;
    events_.push_back(std::move(copy));
}

std::vector<LedgerEvent> EventLedger::replaySince(uint64_t lastAckedSequence) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<LedgerEvent> out;
    for (const auto& ev : events_) {
        if (ev.sequence > lastAckedSequence) {
            out.push_back(ev);
        }
    }
    return out;
}

uint64_t EventLedger::highestSequence() const {
    std::lock_guard<std::mutex> lk(mu_);
    return nextSeq_ > 1 ? nextSeq_ - 1 : 0;
}

void EventLedger::clear() {
    std::lock_guard<std::mutex> lk(mu_);
    events_.clear();
    nextSeq_ = 1;
}

} // namespace rawrxd::continuous
