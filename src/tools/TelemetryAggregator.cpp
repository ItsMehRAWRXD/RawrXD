//=============================================================================
// Telemetry Aggregator CLI Tool
// Reads lock-free ring buffer and outputs to CSV for VAL-025 analysis
// Build: cl /W4 /O2 /EHsc TelemetryAggregator.cpp /link kernel32.lib
//=============================================================================

#include "../debug/TelemetryRingBuffer.hpp"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#include <algorithm>

using namespace RawrXD::DebugUI;

// Calculate percentile from sorted data
template<typename T>
T CalculatePercentile(const std::vector<T>& sortedData, double percentile) {
    if (sortedData.empty()) return 0;
    
    size_t index = static_cast<size_t>(
        (percentile / 100.0) * (sortedData.size() - 1)
    );
    return sortedData[std::min(index, sortedData.size() - 1)];
}

void PrintUsage(const char* program) {
    printf("Usage: %s [options]\n", program);
    printf("Options:\n");
    printf("  -d, --duration SECONDS    Capture duration (default: 60)\n");
    printf("  -o, --output FILE         Output CSV file (default: telemetry.csv)\n");
    printf("  -v, --verbose             Verbose output\n");
    printf("  -h, --help                Show this help\n");
}

int main(int argc, char* argv[]) {
    int durationSeconds = 60;
    const char* outputFile = "telemetry.csv";
    bool verbose = false;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--duration") == 0) {
            if (i + 1 < argc) durationSeconds = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) outputFile = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
    }
    
    printf("╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD Telemetry Aggregator - VAL-025 Certification            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
    
    printf("Connecting to shared memory: %ls\n", SharedMemoryTelemetry::kSharedMemName);
    
    SharedMemoryTelemetry telemetry;
    if (!telemetry.InitializeConsumer()) {
        printf("ERROR: Failed to connect to IDE telemetry stream.\n");
        printf("       Is RawrXD-Win32IDE.exe running?\n");
        return 1;
    }
    
    printf("Connected! Capturing for %d seconds...\n\n", durationSeconds);
    
    // Open output file
    FILE* csv = fopen(outputFile, "w");
    if (!csv) {
        printf("ERROR: Cannot open output file: %s\n", outputFile);
        return 1;
    }
    
    // Write CSV header
    fprintf(csv, "TimestampUs,Submitted,Rendered,Gaps,Dropped,Total,LastAgeMs,MaxAgeMs,ArenaBytes\n");
    
    // Capture loop
    DWORD startTime = GetTickCount();
    std::vector<uint64_t> latencies;
    size_t entriesCaptured = 0;
    size_t entriesDropped = 0;
    
    while ((GetTickCount() - startTime) / 1000 < static_cast<DWORD>(durationSeconds)) {
        auto entry = telemetry.Pop();
        
        if (entry.has_value()) {
            const auto& e = entry.value();
            
            // Write to CSV
            fprintf(csv, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
                e.timestampUs,
                e.submittedSequence,
                e.renderedSequence,
                e.submittedSequence - e.renderedSequence, // Gaps
                e.droppedEvents,
                e.totalEvents,
                e.lastStateAgeMs,
                e.maxStateAgeMs,
                e.arenaHighWater
            );
            
            // Collect latency samples
            if (e.lastStateAgeMs > 0) {
                latencies.push_back(e.lastStateAgeMs);
            }
            
            entriesCaptured++;
            
            if (verbose) {
                printf("[Entry %zu] Age: %llums, Arena: %llu\n",
                    entriesCaptured, e.lastStateAgeMs, e.arenaHighWater);
            }
        } else {
            // No data available, wait a bit
            Sleep(10);
        }
        
        // Progress update every 10 seconds
        int elapsed = (GetTickCount() - startTime) / 1000;
        static int lastProgress = -1;
        int progress = (elapsed / durationSeconds) * 10;
        if (progress != lastProgress && progress > 0) {
            printf("  Progress: %d%% (%ds / %ds)\n", progress * 10, elapsed, durationSeconds);
            lastProgress = progress;
        }
    }
    
    fclose(csv);
    telemetry.Shutdown();
    
    // Calculate percentiles
    printf("\nCapture complete! Entries: %zu\n\n", entriesCaptured);
    
    if (!latencies.empty()) {
        std::sort(latencies.begin(), latencies.end());
        
        uint64_t p50 = CalculatePercentile(latencies, 50.0);
        uint64_t p95 = CalculatePercentile(latencies, 95.0);
        uint64_t p99 = CalculatePercentile(latencies, 99.0);
        uint64_t maxLatency = latencies.back();
        
        printf("╔══════════════════════════════════════════════════════════════════╗\n");
        printf("║  VAL-025 LATENCY ANALYSIS                                         ║\n");
        printf("╠══════════════════════════════════════════════════════════════════╣\n");
        printf("║  Samples:   %10zu                                            ║\n", latencies.size());
        printf("║  P50:        %10llums  (Threshold: < 20ms)   %s\n", 
               p50, p50 < 20 ? "✅ PASS" : "❌ FAIL");
        printf("║  P95:        %10llums  (Threshold: < 100ms)  %s\n", 
               p95, p95 < 100 ? "✅ PASS" : "❌ FAIL");
        printf("║  P99:        %10llums  (Threshold: < 250ms)  %s\n", 
               p99, p99 < 250 ? "✅ PASS" : "❌ FAIL");
        printf("║  Max:        %10llums  (Threshold: < 500ms)  %s\n", 
               maxLatency, maxLatency < 500 ? "✅ PASS" : "❌ FAIL");
        printf("╚══════════════════════════════════════════════════════════════════╝\n");
        
        // Overall certification
        bool certified = (p50 < 20) && (p95 < 100) && (p99 < 250) && (maxLatency < 500);
        printf("\n%s\n", certified 
            ? "✅ VAL-025 CERTIFICATION: PASSED" 
            : "❌ VAL-025 CERTIFICATION: FAILED");
    } else {
        printf("WARNING: No latency data captured.\n");
    }
    
    printf("\nOutput written to: %s\n", outputFile);
    
    return 0;
}
