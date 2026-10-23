#pragma once
// Deep2PerfProbe: dependency-free C++20 performance attribution.
// Compile into Deep2; instrumentation is opt-in and does not alter scheduling.
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string_view>

namespace deep2::perf {
enum class Stage : unsigned {
    CpuPrepare, QuantGemv, Attention, Moe, GpuSubmit, GpuWait,
    HostToDevice, DeviceToHost, Sample, LayerTotal, Count
};
inline constexpr std::array<std::string_view, static_cast<unsigned>(Stage::Count)> names = {
    "cpu_prepare", "quant_gemv", "attention", "moe", "gpu_submit", "gpu_wait",
    "host_to_device", "device_to_host", "sample", "layer_total"
};
struct Counter {
    std::atomic<std::uint64_t> calls{0}, nanos{0}, bytes{0};
};
class Probe {
    std::array<Counter, static_cast<unsigned>(Stage::Count)> counters_{};
    std::atomic<std::uint64_t> tokens_{0}, gpu_dispatches_{0}, gpu_queue_submits_{0}, gpu_fallbacks_{0};
public:
    static Probe& instance() { static Probe p; return p; }
    static bool enabled() {
        static const bool value = [] { const char* v = std::getenv("DEEP2_PERF_PROBE"); return v && v[0]=='1'; }();
        return value;
    }
    void add(Stage s, std::uint64_t ns, std::uint64_t bytes=0) noexcept {
        if (!enabled()) return;
        auto& c=counters_[static_cast<unsigned>(s)];
        c.calls.fetch_add(1, std::memory_order_relaxed);
        c.nanos.fetch_add(ns, std::memory_order_relaxed);
        c.bytes.fetch_add(bytes, std::memory_order_relaxed);
    }
    void token() noexcept { if(enabled()) tokens_.fetch_add(1, std::memory_order_relaxed); }
    void dispatch() noexcept { if(enabled()) gpu_dispatches_.fetch_add(1, std::memory_order_relaxed); }
    void queueSubmit() noexcept { if(enabled()) gpu_queue_submits_.fetch_add(1, std::memory_order_relaxed); }
    void fallback() noexcept { if(enabled()) gpu_fallbacks_.fetch_add(1, std::memory_order_relaxed); }
    void reset() noexcept {
        tokens_.store(0, std::memory_order_relaxed);
        gpu_dispatches_.store(0, std::memory_order_relaxed);
        gpu_queue_submits_.store(0, std::memory_order_relaxed);
        gpu_fallbacks_.store(0, std::memory_order_relaxed);
        for(unsigned i=0;i<static_cast<unsigned>(Stage::Count);++i) {
            counters_[i].calls.store(0, std::memory_order_relaxed);
            counters_[i].nanos.store(0, std::memory_order_relaxed);
            counters_[i].bytes.store(0, std::memory_order_relaxed);
        }
    }
    void report(std::FILE* out=stderr) const noexcept {
        std::fprintf(out,"DEEP2_PERF_PROBE tokens=%llu gpu_dispatches=%llu gpu_queue_submits=%llu gpu_fallbacks=%llu\n",
            (unsigned long long)tokens_.load(), (unsigned long long)gpu_dispatches_.load(),
            (unsigned long long)gpu_queue_submits_.load(), (unsigned long long)gpu_fallbacks_.load());
        for(unsigned i=0;i<static_cast<unsigned>(Stage::Count);++i) {
            const auto& c=counters_[i];
            auto n=c.calls.load(), ns=c.nanos.load(), b=c.bytes.load();
            std::fprintf(out,"PERF stage=%.*s calls=%llu wall_ms=%.3f bytes=%llu\n",
                (int)names[i].size(),names[i].data(),(unsigned long long)n,
                (double)ns/1e6,(unsigned long long)b);
        }
    }
};
class Scope {
    Stage stage_;
    std::uint64_t bytes_;
    bool active_;
    std::chrono::steady_clock::time_point start_;
public:
    explicit Scope(Stage s, std::uint64_t bytes=0) noexcept : stage_(s), bytes_(bytes),
        active_(Probe::enabled()), start_(active_?std::chrono::steady_clock::now():std::chrono::steady_clock::time_point{}) {}
    ~Scope() noexcept {
        if(active_) {
            auto ns=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start_).count();
            Probe::instance().add(stage_, static_cast<std::uint64_t>(ns),bytes_);
        }
    }
    Scope(const Scope&)=delete;
    Scope& operator=(const Scope&)=delete;
};
}
#define DEEP2_PERF_JOIN_(a,b) a##b
#define DEEP2_PERF_JOIN(a,b) DEEP2_PERF_JOIN_(a,b)
#define DEEP2_PERF_SCOPE(stage) ::deep2::perf::Scope DEEP2_PERF_JOIN(_deep2_perf_scope_,__LINE__)(::deep2::perf::Stage::stage)
#define DEEP2_PERF_SCOPE_BYTES(stage,n) ::deep2::perf::Scope DEEP2_PERF_JOIN(_deep2_perf_scope_,__LINE__)(::deep2::perf::Stage::stage,(n))
