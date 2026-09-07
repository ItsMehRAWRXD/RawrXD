// DecodeCarry.hpp — token N pays for N+1 via real WeightResidencyPool pins
#pragma once
#include "WeightResidencyPool.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {

// Non-owning carry: wraps the live B015 pool. No parallel fake buffers.
struct DecodeCarry {
    bool valid = false;
    uint64_t generation = 0;
    size_t sequence_length = 0;
    WeightResidencyPool* pool = nullptr; // non-owning
    std::vector<std::string> pinned_names;

    void invalidate() noexcept {
        if (pool) {
            for (const auto& n : pinned_names) pool->unpin(n);
        }
        valid = false;
        generation = 0;
        sequence_length = 0;
        pinned_names.clear();
        // pool pointer retained (engine owns pool lifetime)
    }

    // After successful T==1 decode: pin currently resident weights for N+1.
    bool prepare(WeightResidencyPool* p, size_t seqLen, uint64_t gen) {
        invalidate();
        pool = p;
        if (!pool || pool->resident_bytes() == 0) return false;
        pool->for_each_resident([&](const ResidentWeight& w) {
            pool->pin(w.name);
            pinned_names.push_back(w.name);
        });
        if (pinned_names.empty()) return false;
        sequence_length = seqLen;
        generation = gen;
        valid = true;
        return true;
    }
};

} // namespace rawrxd
