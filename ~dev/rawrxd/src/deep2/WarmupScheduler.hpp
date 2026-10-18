#pragma once
// Stub: Warmup Scheduler
namespace Deep2 {
struct WarmupConfig {};
struct WarmupStats { int prefetched=0; };
class WarmupScheduler {
public:
    WarmupStats stats;
};
} // namespace Deep2
