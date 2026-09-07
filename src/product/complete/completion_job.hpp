#pragma once
#include "../runtime/cancellation.hpp"
#include "../runtime/execution_types.hpp"
#include <cstdint>
#include <string>
namespace rawr::product {

struct CompletionJob {
    uint64_t id = 0;
    uint64_t gen = 0;
    ExecutionRequest req;
    CancelToken* cancel = nullptr;
    int speculative = 0;
};

inline bool JobLive(const CompletionJob& j, uint64_t liveGen,
                    const CancelToken* cancel) {
    if (j.gen != liveGen) return false;
    if (cancel && cancel->requested()) return false;
    if (j.cancel && j.cancel->requested()) return false;
    return true;
}

} // namespace rawr::product
