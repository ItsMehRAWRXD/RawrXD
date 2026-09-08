#pragma once
/* RAWR_TIME_001 — causal SPIN time; wall is observer only. */
#include <chrono>
#include <cstdint>
#include <type_traits>

namespace rawr::spin {

using SpinEpoch = uint64_t;

struct SpinTime {
    SpinEpoch open = 0;  /* causal state at token admission */
    SpinEpoch close = 0; /* causal state at token completion */
};

constexpr SpinEpoch TokenSpan(const SpinTime& s) noexcept {
    return s.close - s.open;
}

/* SPIN is causal order, not physical duration. */
static_assert(!std::is_same_v<SpinEpoch, std::chrono::nanoseconds>,
              "SPIN is causal order, not physical duration");

} // namespace rawr::spin

#define RAWR_TIME_001 1
#define TIME_DOMAIN_CAUSAL 1
#define TIME_SOURCE_STATE_TRANSITION 1
#define CLOCK_SOURCE_NONE 1
#define TIMER_REQUIRED 0
#define WALL_TIME_OBSERVER_ONLY 1
#define WALL_TIME_NEVER_CONTROLS_SCHEDULING 1
#define WALL_TIME_NEVER_ESTABLISHES_READINESS 1
#define CAUSALITY_NEVER_FROM_WALL_TIME 1
#define SPIN_OPTIMIZES_CAUSAL_DISTANCE 1
#define BGBM_OPTIMIZES_RESIDENT_TRAFFIC 1
#define WALL_TIME_MEASURES_REALIZATION_ONLY 1
/*
  TICK := one causally relevant state transition
  SPIN := minimal closed causal cycle → one committed token
  SPIN_OPEN(N)  := token N obtains immutable input authority
  SPIN_CLOSE(N) := token N obtains immutable output authority
  TOKEN(N)      := CLOSE(SPIN(N))
  S_N = SPIN_TIME(N) := causal_distance(OPEN, CLOSE)  // NOT ns
  W_N = WALL_TIME(N) := observer metric only
  TPS_real := tokens / wall_seconds                   // external truth

  NO EXECUTION DECISION MAY REQUIRE "how much time has passed?"
  IF THE SAME DECISION CAN BE DERIVED FROM "what state is ready?"

  Prefetch: when consumer(N+1) inevitable AND storage free of N's deps
  Evict:    retain(page) iff future causal frontier references(page)
  Await:    await(operand) — never wait_for(device) as progress law

  SPIN optimizes causal distance; BG~BM~ optimizes resident traffic;
  wall time only measures their realization.
*/
