#include "EventLedger.hpp"

namespace rawrxd::continuous {

void EventLedger::append(uint64_t runId, const Event& ev) {
    std::lock_guard<std::mutex> lk(mu_);
    auto& run = runs_[runId];
    Record r{};
    r.sequence = run.nextSequence++;
    r.runId = runId;
    r.kind = ev.kind;
    r.text = ev.text;
    r.payload = ev.payload;
    r.tokenIndex = ev.token_index;
    r.workEpoch = ev.work_epoch;
    run.records.push_back(std::move(r));
}

std::vector<EventLedger::Record> EventLedger::query(uint64_t runId) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = runs_.find(runId);
    if (it == runs_.end()) return {};
    return it->second.records;
}

std::vector<EventLedger::Record> EventLedger::replay(uint64_t runId, uint64_t fromSequence) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = runs_.find(runId);
    if (it == runs_.end()) return {};
    std::vector<Record> out;
    for (const auto& r : it->second.records) {
        if (r.sequence > fromSequence) {
            out.push_back(r);
        }
    }
    return out;
}

uint64_t EventLedger::latestSequence(uint64_t runId) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = runs_.find(runId);
    if (it == runs_.end() || it->second.records.empty()) return 0;
    return it->second.records.back().sequence;
}

void EventLedger::trim(uint64_t runId, uint64_t upToSequence) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = runs_.find(runId);
    if (it == runs_.end()) return;
    auto& recs = it->second.records;
    size_t keep = 0;
    for (size_t i = 0; i < recs.size(); ++i) {
        if (recs[i].sequence > upToSequence) {
            keep = i;
            break;
        }
    }
    if (keep > 0) {
        recs.erase(recs.begin(), recs.begin() + static_cast<std::ptrdiff_t>(keep));
    }
}

void EventLedger::drop(uint64_t runId) {
    std::lock_guard<std::mutex> lk(mu_);
    runs_.erase(runId);
}

size_t EventLedger::totalRecords() const {
    std::lock_guard<std::mutex> lk(mu_);
    size_t n = 0;
    for (const auto& kv : runs_) {
        n += kv.second.records.size();
    }
    return n;
}

} // namespace rawrxd::continuous
