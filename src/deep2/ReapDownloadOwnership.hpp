#pragma once
#include <cstdint>
#include <limits>
#include <map>

namespace Deep2 { namespace Submit {
// All operations are serialized by the backend API mutex. Reserve before
// submitting; marking the attempted submission and retaining it never allocate.
template<class Payload>
class DownloadOwnership {
    struct Entry { uint64_t generation; bool attempted = false; Payload payload{}; };
public:
    struct Lease { uint64_t id = 0; Payload* payload = nullptr; };
    Lease Reserve(uint64_t generation) noexcept {
        if (next_ == std::numeric_limits<uint64_t>::max()) return {};
        try {
            const auto id = next_;
            auto it = entries_.emplace(id, Entry{generation});
            if (!it.second) return {};
            ++next_;
            return {id, &it.first->second.payload};
        } catch (...) { return {}; }
    }
    Payload* Find(uint64_t id, uint64_t generation) noexcept {
        auto it = entries_.find(id);
        return it != entries_.end() && it->second.generation == generation
            ? &it->second.payload : nullptr;
    }
    bool MarkAttempt(uint64_t id, uint64_t generation) noexcept {
        auto it = entries_.find(id);
        if (it == entries_.end() || it->second.generation != generation || it->second.attempted) return false;
        it->second.attempted = true;
        return true;
    }
    template<class Release>
    bool DiscardUnsubmitted(uint64_t id, uint64_t generation, Release release) {
        auto it = entries_.find(id);
        if (it == entries_.end() || it->second.generation != generation || it->second.attempted) return false;
        release(it->second.payload);
        entries_.erase(it);
        return true;
    }
    template<class Release>
    bool Complete(uint64_t id, uint64_t generation, int result, Release release) {
        auto it = entries_.find(id);
        if (result != 0 || it == entries_.end() || it->second.generation != generation || !it->second.attempted) return false;
        release(it->second.payload);
        entries_.erase(it);
        return true;
    }
    template<class Release>
    bool Drain(uint64_t generation, int idleResult, Release release) {
        if (idleResult != 0 && idleResult != -4) return false;
        for (const auto& entry : entries_) if (entry.second.generation != generation) return false;
        for (auto& entry : entries_) release(entry.second.payload);
        entries_.clear();
        return true;
    }
    bool Empty() const noexcept { return entries_.empty(); }
private:
    std::map<uint64_t, Entry> entries_;
    uint64_t next_ = 1;
};
} } // namespace Deep2::Submit
