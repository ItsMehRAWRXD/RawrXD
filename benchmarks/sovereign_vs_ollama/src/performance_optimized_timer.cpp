// performance_optimized_timer.cpp
// Batch 9: High-Performance Timer Implementation
//
// Provides nanosecond-precision timing with minimal overhead
// Uses platform-specific high-resolution clocks
// Implements cache-line alignment to prevent false sharing

#include <chrono>
#include <cstdint>
#include <atomic>
#include <thread>
#include <vector>
#include <numeric>
#include <algorithm>

// Platform-specific includes
#ifdef _WIN32
    #include <windows.h>
#else
    #include <time.h>
#endif

namespace Benchmark {
namespace Performance {

// Cache line size (common on x86_64)
constexpr size_t CACHE_LINE_SIZE = 64;

// Aligned storage to prevent false sharing
template<typename T>
struct alignas(CACHE_LINE_SIZE) AlignedStorage {
    T value;
};

// High-resolution timer using platform-specific implementations
class OptimizedTimer {
public:
    OptimizedTimer() {
        Calibrate();
    }

    // Start timing
    inline void Start() noexcept {
        start_time_ = GetTicks();
    }

    // Stop timing and return duration in nanoseconds
    inline uint64_t Stop() noexcept {
        uint64_t end_time = GetTicks();
        return TicksToNanoseconds(end_time - start_time_);
    }

    // Get current timestamp in nanoseconds
    static uint64_t Now() noexcept {
        return TicksToNanoseconds(GetTicks());
    }

    // Get timer resolution in nanoseconds
    static uint64_t Resolution() noexcept {
        return resolution_ns_;
    }

    // Calibrate timer (call once at startup)
    static void Calibrate() {
        // Measure overhead
        constexpr int CALIBRATION_RUNS = 1000;
        std::vector<uint64_t> overheads;
        overheads.reserve(CALIBRATION_RUNS);

        OptimizedTimer timer;
        for (int i = 0; i < CALIBRATION_RUNS; ++i) {
            timer.Start();
            uint64_t elapsed = timer.Stop();
            overheads.push_back(elapsed);
        }

        // Use median overhead
        std::sort(overheads.begin(), overheads.end());
        overhead_ns_ = overheads[CALIBRATION_RUNS / 2];

        // Calculate resolution
        resolution_ns_ = CalculateResolution();
    }

    // Get timer overhead in nanoseconds
    static uint64_t Overhead() noexcept {
        return overhead_ns_;
    }

private:
    uint64_t start_time_ = 0;
    static inline uint64_t overhead_ns_ = 0;
    static inline uint64_t resolution_ns_ = 0;

    // Platform-specific tick counter
    static inline uint64_t GetTicks() noexcept {
#ifdef _WIN32
        LARGE_INTEGER freq;
        LARGE_INTEGER count;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&count);
        return static_cast<uint64_t>(count.QuadPart);
#else
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + 
               static_cast<uint64_t>(ts.tv_nsec);
#endif
    }

    // Convert ticks to nanoseconds
    static inline uint64_t TicksToNanoseconds(uint64_t ticks) noexcept {
#ifdef _WIN32
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        return (ticks * 1000000000ULL) / static_cast<uint64_t>(freq.QuadPart);
#else
        return ticks; // Already in nanoseconds on Linux
#endif
    }

    static uint64_t CalculateResolution() {
        // Measure minimum measurable time
        constexpr int RESOLUTION_RUNS = 100;
        std::vector<uint64_t> deltas;
        
        for (int i = 0; i < RESOLUTION_RUNS; ++i) {
            auto t1 = GetTicks();
            auto t2 = GetTicks();
            deltas.push_back(t2 - t1);
        }

        // Use minimum non-zero delta
        std::sort(deltas.begin(), deltas.end());
        for (auto d : deltas) {
            if (d > 0) {
                return TicksToNanoseconds(d);
            }
        }
        return 1; // Default to 1ns
    }
};

// Lock-free sample collector for minimal overhead
class LockFreeSampleCollector {
public:
    explicit LockFreeSampleCollector(size_t capacity = 1000)
        : capacity_(capacity), 
          buffer_(capacity),
          write_index_(0) {}

    // Add a sample (lock-free, thread-safe for single producer)
    inline void AddSample(uint64_t value) noexcept {
        size_t index = write_index_.fetch_add(1, std::memory_order_relaxed);
        if (index < capacity_) {
            buffer_[index].value = value;
        }
    }

    // Get collected samples
    std::vector<uint64_t> GetSamples() const {
        size_t count = std::min(write_index_.load(std::memory_order_acquire), capacity_);
        std::vector<uint64_t> result;
        result.reserve(count);
        
        for (size_t i = 0; i < count; ++i) {
            result.push_back(buffer_[i].value);
        }
        return result;
    }

    // Reset collector
    void Reset() noexcept {
        write_index_.store(0, std::memory_order_release);
    }

    // Get number of samples collected
    size_t Count() const noexcept {
        return std::min(write_index_.load(std::memory_order_acquire), capacity_);
    }

private:
    size_t capacity_;
    std::vector<AlignedStorage<uint64_t>> buffer_;
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> write_index_;
};

// CPU affinity setter for consistent measurements
class CPUAffinity {
public:
    // Pin current thread to specific CPU core
    static bool PinToCore(int core_id) {
#ifdef _WIN32
        DWORD_PTR mask = 1ULL << core_id;
        return SetThreadAffinityMask(GetCurrentThread(), mask) != 0;
#else
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(core_id, &cpuset);
        return pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) == 0;
#endif
    }

    // Get number of available CPU cores
    static int GetCoreCount() {
#ifdef _WIN32
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        return static_cast<int>(sysinfo.dwNumberOfProcessors);
#else
        return sysconf(_SC_NPROCESSORS_ONLN);
#endif
    }
};

// Memory prefetch hints
inline void PrefetchRead(const void* ptr) noexcept {
#ifdef _WIN32
    _mm_prefetch(static_cast<const char*>(ptr), _MM_HINT_T0);
#else
    __builtin_prefetch(ptr, 0, 3);
#endif
}

// Prevent compiler reordering
inline void MemoryBarrier() noexcept {
    std::atomic_thread_fence(std::memory_order_seq_cst);
}

// Benchmark the timer itself
struct TimerBenchmarkResult {
    uint64_t overhead_ns;
    uint64_t resolution_ns;
    double precision_percent;
};

inline TimerBenchmarkResult BenchmarkTimer() {
    TimerBenchmarkResult result;
    
    // Measure overhead
    constexpr int OVERHEAD_RUNS = 10000;
    std::vector<uint64_t> overheads;
    overheads.reserve(OVERHEAD_RUNS);
    
    OptimizedTimer timer;
    for (int i = 0; i < OVERHEAD_RUNS; ++i) {
        timer.Start();
        uint64_t elapsed = timer.Stop();
        overheads.push_back(elapsed);
    }
    
    std::sort(overheads.begin(), overheads.end());
    result.overhead_ns = overheads[OVERHEAD_RUNS / 2];
    
    // Measure resolution
    result.resolution_ns = OptimizedTimer::Resolution();
    
    // Calculate precision (overhead as percentage of typical measurement)
    result.precision_percent = (static_cast<double>(result.overhead_ns) / 100000.0) * 100.0;
    
    return result;
}

} // namespace Performance
} // namespace Benchmark
