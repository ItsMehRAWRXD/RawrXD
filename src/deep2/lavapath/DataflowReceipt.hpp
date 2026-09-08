#pragma once
/* Dataflow stages: consume → produce → measure. No reasoning trace. */
#include <cstdint>
#include <cstdio>

namespace rawr::flow {

struct StageReceipt {
    const char* stage = "";
    const char* consumes = "";
    const char* produces = "";
    uint64_t timeUs = 0;
    uint32_t pass = 0;
    const char* detail = "";
};

inline void Emit(const StageReceipt& r) noexcept {
    std::printf("STAGE=%s CONSUMES=%s PRODUCES=%s TIME_US=%llu "
                "STATUS=%s %s\n",
                r.stage, r.consumes, r.produces,
                (unsigned long long)r.timeUs, r.pass ? "PASS" : "FAIL",
                r.detail);
}

/*
  Stable optimize loop per stage:
    Discover → Validate → Measure → Optimize → Measure → Accept|Reject
  Accept requires: correct output AND lower wall time.
*/

} // namespace rawr::flow
