// ============================================================================
// test_debugbridge_telemetry.cpp
// Standalone test for DebugBridge telemetry system
// Validates sequence tracking, latency measurement, and arena monitoring
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <thread>
#include <atomic>
#include <chrono>

// Minimal DebugBridgeEvent structure for testing
enum class DebugBridgeEventType : uint32_t {
    None = 0,
    BreakpointHit,
    SingleStep,
    ProcessCreated,
    ProcessExited
};

struct DebugBridgeEvent {
    DebugBridgeEventType type;
    uint32_t processId;
    uint32_t threadId;
    
    // Sequence tracking for producer/consumer telemetry
    uint64_t sequence;
    uint64_t submitTimestamp;
    uint64_t renderTimestamp;
    
    union {
        struct { uint64_t address; } breakpoint;
        struct { uint64_t exitCode; } processExit;
    };
    
    DebugBridgeEvent() : type(DebugBridgeEventType::None), processId(0), threadId(0),
                         sequence(0), submitTimestamp(0), renderTimestamp(0) {}
};

// Telemetry tracking (matches DebugBridge.hpp)
struct DebugTelemetry {
    std::atomic<uint64_t> submittedSequence{0};
    std::atomic<uint64_t> renderedSequence{0};
    std::atomic<uint64_t> droppedEvents{0};
    std::atomic<uint64_t> totalEvents{0};
    
    std::atomic<uint64_t> lastStateAgeMs{0};
    std::atomic<uint64_t> maxStateAgeMs{0};
    
    std::atomic<uint64_t> arenaHighWater{0};
    std::atomic<uint64_t> currentArena{0};
    
    uint64_t GetSequenceGaps() const {
        uint64_t submitted = submittedSequence.load();
        uint64_t rendered = renderedSequence.load();
        return (submitted > rendered) ? (submitted - rendered) : 0;
    }
    
    void RecordSubmit(uint64_t seq) {
        submittedSequence.store(seq);
        totalEvents.fetch_add(1);
    }
    
    void RecordRender(uint64_t seq, uint64_t ageMs) {
        renderedSequence.store(seq);
        lastStateAgeMs.store(ageMs);
        
        uint64_t maxAge = maxStateAgeMs.load();
        if (ageMs > maxAge) {
            maxStateAgeMs.store(ageMs);
        }
    }
    
    void RecordDrop() {
        droppedEvents.fetch_add(1);
    }
    
    void UpdateArena(uint64_t used, uint64_t highWater) {
        currentArena.store(used);
        arenaHighWater.store(highWater);
    }
};

// Test globals
static DebugTelemetry g_telemetry;
static std::atomic<uint64_t> g_sequenceCounter{0};
static std::atomic<bool> g_running{true};
static std::atomic<uint64_t> g_arenaUsed{5242880}; // 5MB base

// Event submission (producer thread)
void ProducerThread() {
    uint64_t eventCount = 0;
    auto startTime = std::chrono::steady_clock::now();

    while (g_running.load()) {
        // Model 8,333 events/sec submission rate
        for (int i = 0; i < 833; i++) {
            uint64_t seq = ++g_sequenceCounter;
            uint64_t timestamp = GetTickCount64();

            g_telemetry.RecordSubmit(seq);

            // Model arena growth
            g_arenaUsed.fetch_add(1024); // 1KB per event
            g_telemetry.UpdateArena(g_arenaUsed.load(), g_arenaUsed.load());

            eventCount++;
        }
        
        // Sleep 100ms (100Hz sampling)
        Sleep(100);
        
        // Log progress every second
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime).count();
        if (elapsed % 5 == 0 && elapsed > 0) {
            printf("[Producer] %llu events submitted, seq=%llu\n", 
                   (unsigned long long)eventCount, 
                   (unsigned long long)g_sequenceCounter.load());
        }
    }
}

// Event rendering (consumer thread)
void ConsumerThread() {
    uint64_t lastRenderedSeq = 0;
    auto startTime = std::chrono::steady_clock::now();

    while (g_running.load()) {
        // Get current submitted sequence
        uint64_t submittedSeq = g_telemetry.submittedSequence.load();

        // Model coalescing: only render every 30th event
        uint64_t targetRender = submittedSeq;
        if (targetRender > lastRenderedSeq + 30) {
            targetRender = lastRenderedSeq + 30;
        }

        if (targetRender > lastRenderedSeq) {
            // Calculate state age
            uint64_t ageMs = (targetRender - lastRenderedSeq) * 2; // ~2ms per event gap
            
            g_telemetry.RecordRender(targetRender, ageMs);
            lastRenderedSeq = targetRender;
            
            // Record dropped events
            uint64_t dropped = submittedSeq - targetRender;
            for (uint64_t i = 0; i < dropped; i++) {
                g_telemetry.RecordDrop();
            }
        }
        
        // Sleep 33ms (30Hz render rate)
        Sleep(33);
        
        // Log telemetry every 5 seconds
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startTime).count();
        if (elapsed % 5 == 0 && elapsed > 0 && elapsed % 10 == 5) {
            uint64_t gaps = g_telemetry.GetSequenceGaps();
            uint64_t lastAge = g_telemetry.lastStateAgeMs.load();
            uint64_t maxAge = g_telemetry.maxStateAgeMs.load();
            uint64_t arena = g_telemetry.arenaHighWater.load();
            
            printf("[Consumer] Gaps: %llu | LastAge: %llums | MaxAge: %llums | Arena: %llu\n",
                   (unsigned long long)gaps,
                   (unsigned long long)lastAge,
                   (unsigned long long)maxAge,
                   (unsigned long long)arena);
        }
    }
}

// Output telemetry summary (matches DebugBridge.cpp)
void LogTelemetrySummary() {
    uint64_t submitted = g_telemetry.submittedSequence.load();
    uint64_t rendered = g_telemetry.renderedSequence.load();
    uint64_t gaps = g_telemetry.GetSequenceGaps();
    uint64_t dropped = g_telemetry.droppedEvents.load();
    uint64_t total = g_telemetry.totalEvents.load();
    uint64_t lastAge = g_telemetry.lastStateAgeMs.load();
    uint64_t maxAge = g_telemetry.maxStateAgeMs.load();
    uint64_t arena = g_telemetry.arenaHighWater.load();
    
    // Output in DebugBridge format
    printf("[DebugTelemetry] Submitted: %llu | Rendered: %llu | Gaps: %llu | "
           "Dropped: %llu | Total: %llu | LastAge: %llums | MaxAge: %llums | Arena: %llu\n",
           (unsigned long long)submitted,
           (unsigned long long)rendered,
           (unsigned long long)gaps,
           (unsigned long long)dropped,
           (unsigned long long)total,
           (unsigned long long)lastAge,
           (unsigned long long)maxAge,
           (unsigned long long)arena);
}

int main(int argc, char* argv[]) {
    int durationSeconds = 10;
    if (argc > 1) {
        durationSeconds = atoi(argv[1]);
    }
    
    printf("========================================\n");
    printf("DebugBridge Telemetry Test\n");
    printf("Duration: %d seconds\n", durationSeconds);
    printf("========================================\n\n");
    
    printf("Simulating:\n");
    printf("  - Producer: 8,333 events/sec\n");
    printf("  - Consumer: 30 renders/sec (coalesced)\n");
    printf("  - Expected: High gaps, low latency, stable arena\n\n");
    
    // Start producer and consumer threads
    std::thread producer(ProducerThread);
    std::thread consumer(ConsumerThread);
    
    // Run for specified duration
    Sleep(durationSeconds * 1000);
    
    // Stop threads
    g_running.store(false);
    producer.join();
    consumer.join();
    
    // Final telemetry output
    printf("\n========================================\n");
    printf("Final Telemetry Summary\n");
    printf("========================================\n");
    LogTelemetrySummary();
    
    // Calculate rates
    uint64_t submitted = g_telemetry.submittedSequence.load();
    uint64_t rendered = g_telemetry.renderedSequence.load();
    double submissionRate = (double)submitted / durationSeconds;
    double renderRate = (double)rendered / durationSeconds;
    
    printf("\nRates:\n");
    printf("  Submission Rate: %.2f events/sec\n", submissionRate);
    printf("  Render Rate: %.2f renders/sec\n", renderRate);
    printf("  Coalescing Ratio: %.2f%%\n", 
           (submitted > 0) ? ((double)(submitted - rendered) / submitted * 100) : 0);
    
    // Validate thresholds
    printf("\n========================================\n");
    printf("Threshold Validation\n");
    printf("========================================\n");
    
    uint64_t maxAge = g_telemetry.maxStateAgeMs.load();
    uint64_t arena = g_telemetry.arenaHighWater.load();
    uint64_t baseArena = 5242880;
    double arenaGrowth = ((double)arena - baseArena) / baseArena * 100;
    
    printf("Max Latency: %llums (threshold: 500ms) - %s\n",
           (unsigned long long)maxAge,
           (maxAge < 500) ? "PASS" : "FAIL");
    
    printf("Arena Growth: %.2f%% (threshold: 50%%) - %s\n",
           arenaGrowth,
           (arenaGrowth < 50) ? "PASS" : "FAIL");
    
    printf("\nTest Complete.\n");
    
    return (maxAge < 500 && arenaGrowth < 50) ? 0 : 1;
}
