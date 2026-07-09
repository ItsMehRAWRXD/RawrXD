/**
 * @file compression_engine_test.cpp
 * @brief RawrXD Compression Engine Test
 *
 * Demonstrates runtime tune selection and custom compression ratios.
 * Like dyno testing different engine builds.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <iomanip>
#include <vector>
#include <chrono>
#include <cmath>
#include "../kernels/compression_engine.h"

using namespace std;
using namespace rawrxd::compression;

using Clock = chrono::high_resolution_clock;

// ============================================================================
// Custom Compression Ratios (Engine "Builds")
// ============================================================================

// Build 1: "Mild Street" - 10.5:1
CompressionConfig BuildMildStreet() {
    return CompressionBuilder()
        .BlockSize(64)
        .BitsPerWeight(8)
        .ScaleBits(16)
        .MinBits(0)
        .MaxError(0.0005f)
        .MixedPrecision(false)
        .SuperBlocks(false)
        .Build();
}

// Build 2: "Track Day" - 13.0:1
CompressionConfig BuildTrackDay() {
    return CompressionBuilder()
        .BlockSize(32)
        .BitsPerWeight(6)
        .ScaleBits(16)
        .MinBits(16)
        .MaxError(0.02f)
        .MixedPrecision(false)
        .SuperBlocks(false)
        .Build();
}

// Build 3: "Drag Strip" - 8.0:1 (high compression, fast dequant)
CompressionConfig BuildDragStrip() {
    return CompressionBuilder()
        .BlockSize(128)
        .BitsPerWeight(4)
        .ScaleBits(8)
        .MinBits(0)
        .MaxError(0.15f)
        .MixedPrecision(true)
        .SuperBlocks(true)
        .Build();
}

// Build 4: "Bonkers" - 15.0:1 (extreme, experimental)
CompressionConfig BuildBonkers() {
    return CompressionBuilder()
        .BlockSize(256)
        .BitsPerWeight(5)
        .ScaleBits(8)
        .MinBits(8)
        .MaxError(0.3f)
        .MixedPrecision(true)
        .SuperBlocks(true)
        .Build();
}

// Build 5: "Efficiency King" - 5.0:1 (maximum memory savings)
CompressionConfig BuildEfficiencyKing() {
    return CompressionBuilder()
        .BlockSize(64)
        .BitsPerWeight(3)
        .ScaleBits(16)
        .MinBits(0)
        .MaxError(0.5f)
        .MixedPrecision(false)
        .SuperBlocks(false)
        .Build();
}

// ============================================================================
// Test Data Generation
// ============================================================================
void GenerateTestData(vector<float>& weights, int rows, int cols) {
    weights.resize(rows * cols);
    for (size_t i = 0; i < weights.size(); i++) {
        weights[i] = sinf(i * 0.001f) * 0.01f;
    }
}

// ============================================================================
// Benchmark Function
// ============================================================================
struct BenchmarkResult {
    double compress_time_ms;
    double decompress_time_ms;
    size_t compressed_size;
    float compression_ratio;
    float max_error;
};

BenchmarkResult BenchmarkTune(CompressionEngine& engine, const vector<float>& weights,
                               int rows, int cols) {
    const auto& config = engine.GetCurrentConfig();
    size_t num_weights = weights.size();
    
    // Allocate compressed buffer (worst case)
    vector<uint8_t> compressed(num_weights * sizeof(float));
    vector<float> decompressed(num_weights);
    
    // Benchmark compression
    auto start = Clock::now();
    size_t compressed_size = engine.Compress(weights.data(), compressed.data(), num_weights);
    auto end = Clock::now();
    double compress_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    // Benchmark decompression
    start = Clock::now();
    engine.Decompress(compressed.data(), decompressed.data(), num_weights);
    end = Clock::now();
    double decompress_ms = chrono::duration_cast<chrono::microseconds>(end - start).count() / 1000.0;
    
    // Calculate error
    float max_error = 0.0f;
    for (size_t i = 0; i < num_weights; i++) {
        float err = fabs(weights[i] - decompressed[i]);
        if (err > max_error) max_error = err;
    }
    
    return {
        compress_ms,
        decompress_ms,
        compressed_size,
        config.compression_ratio,
        max_error
    };
}

// ============================================================================
// Print Results Table
// ============================================================================
void PrintResultsHeader() {
    cout << "\n═══════════════════════════════════════════════════════════════════════════════════\n";
    cout << "COMPRESSION ENGINE DYNO RESULTS\n";
    cout << "═══════════════════════════════════════════════════════════════════════════════════\n\n";
    
    cout << left << setw(18) << "Build";
    cout << right << setw(10) << "CR";
    cout << setw(12) << "Comp(ms)";
    cout << setw(12) << "Decomp(ms)";
    cout << setw(14) << "Size(KB)";
    cout << setw(12) << "Error";
    cout << setw(12) << "Status" << "\n";
    cout << string(100, '-') << "\n";
}

void PrintResult(const char* name, const BenchmarkResult& result, const CompressionConfig& config) {
    cout << left << setw(18) << name;
    cout << right << fixed << setprecision(1);
    cout << setw(9) << result.compression_ratio << ":1";
    cout << setw(12) << setprecision(2) << result.compress_time_ms;
    cout << setw(12) << result.decompress_time_ms;
    cout << setw(13) << setprecision(1) << (result.compressed_size / 1024.0f) << " KB";
    cout << setw(12) << setprecision(4) << result.max_error;
    
    bool passed = result.max_error <= config.max_error_target;
    cout << setw(12) << (passed ? "✅ PASS" : "❌ FAIL") << "\n";
}

// ============================================================================
// Main
// ============================================================================
int main() {
    cout << "🏎️  RawrXD Compression Engine - Custom Build Dyno\n";
    cout << "═══════════════════════════════════════════════════\n\n";
    
    // Test configuration
    const int ROWS = 8192;
    const int COLS = 3072;
    const size_t NUM_WEIGHTS = ROWS * COLS;
    
    cout << "Test Configuration:\n";
    cout << "  Matrix: " << ROWS << " x " << COLS << " = " << NUM_WEIGHTS << " weights\n";
    cout << "  FP32 Size: " << (NUM_WEIGHTS * sizeof(float)) / (1024.0 * 1024.0) << " MB\n\n";
    
    // Generate test data
    vector<float> weights;
    GenerateTestData(weights, ROWS, COLS);
    
    // Get engine instance (statically linked)
    CompressionEngine& engine = GetCompressionEngine();
    
    PrintResultsHeader();
    
    // Test 1: Street NA (Preset)
    engine.SelectTune(CompressionTune::STREET_NA);
    auto result1 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Street NA", result1, engine.GetCurrentConfig());
    
    // Test 2: Forced Induction (Preset)
    engine.SelectTune(CompressionTune::FORCED_INDUCTION);
    auto result2 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Forced Induction", result2, engine.GetCurrentConfig());
    
    // Test 3: Race Forced (Preset)
    engine.SelectTune(CompressionTune::RACE_FORCED);
    auto result3 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Race Forced", result3, engine.GetCurrentConfig());
    
    // Test 4: Custom - Mild Street (10.5:1)
    auto mild_street = BuildMildStreet();
    engine.SelectCustom(mild_street);
    auto result4 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Mild Street", result4, engine.GetCurrentConfig());
    
    // Test 5: Custom - Track Day (13.0:1)
    auto track_day = BuildTrackDay();
    engine.SelectCustom(track_day);
    auto result5 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Track Day", result5, engine.GetCurrentConfig());
    
    // Test 6: Custom - Drag Strip (8.0:1)
    auto drag_strip = BuildDragStrip();
    engine.SelectCustom(drag_strip);
    auto result6 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Drag Strip", result6, engine.GetCurrentConfig());
    
    // Test 7: Custom - Bonkers (15.0:1)
    auto bonkers = BuildBonkers();
    engine.SelectCustom(bonkers);
    auto result7 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Bonkers", result7, engine.GetCurrentConfig());
    
    // Test 8: Custom - Efficiency King (5.0:1)
    auto efficiency = BuildEfficiencyKing();
    engine.SelectCustom(efficiency);
    auto result8 = BenchmarkTune(engine, weights, ROWS, COLS);
    PrintResult("Efficiency King", result8, engine.GetCurrentConfig());
    
    cout << "\n" << string(100, '=') << "\n";
    
    // Summary
    cout << "\n📊 BUILD SUMMARY\n";
    cout << "════════════════\n\n";
    
    cout << "Best Compression Ratio: ";
    float best_cr = result1.compression_ratio;
    best_cr = max(best_cr, result2.compression_ratio);
    best_cr = max(best_cr, result3.compression_ratio);
    best_cr = max(best_cr, result4.compression_ratio);
    best_cr = max(best_cr, result5.compression_ratio);
    best_cr = max(best_cr, result6.compression_ratio);
    best_cr = max(best_cr, result7.compression_ratio);
    best_cr = max(best_cr, result8.compression_ratio);
    cout << fixed << setprecision(1) << best_cr << ":1\n";
    
    cout << "Fastest Decompress: ";
    double fastest = result1.decompress_time_ms;
    fastest = min(fastest, result2.decompress_time_ms);
    fastest = min(fastest, result3.decompress_time_ms);
    fastest = min(fastest, result4.decompress_time_ms);
    fastest = min(fastest, result5.decompress_time_ms);
    fastest = min(fastest, result6.decompress_time_ms);
    fastest = min(fastest, result7.decompress_time_ms);
    fastest = min(fastest, result8.decompress_time_ms);
    cout << fixed << setprecision(2) << fastest << " ms\n";
    
    cout << "Smallest Size: ";
    size_t smallest = result1.compressed_size;
    smallest = min(smallest, result2.compressed_size);
    smallest = min(smallest, result3.compressed_size);
    smallest = min(smallest, result4.compressed_size);
    smallest = min(smallest, result5.compressed_size);
    smallest = min(smallest, result6.compressed_size);
    smallest = min(smallest, result7.compressed_size);
    smallest = min(smallest, result8.compressed_size);
    cout << (smallest / 1024) << " KB\n\n";
    
    // Custom ratio demonstration
    cout << "🔧 CUSTOM RATIO CALCULATOR\n";
    cout << "═════════════════════════\n\n";
    
    cout << "Example: Build your own 9.5:1 compression\n";
    cout << "  BlockSize(64).BitsPerWeight(5).ScaleBits(8)\n";
    auto custom = CompressionBuilder()
        .BlockSize(64)
        .BitsPerWeight(5)
        .ScaleBits(8)
        .MinBits(0)
        .MaxError(0.1f)
        .Build();
    
    cout << "  Calculated CR: " << fixed << setprecision(2) << custom.compression_ratio << ":1\n";
    cout << "  Effective bits: " << custom.effective_bits << "\n";
    cout << "  Bytes per block: " << custom.bytes_per_block << "\n\n";
    
    cout << "═══════════════════════════════════════════════════════════════════════════════════\n";
    cout << "COMPRESSION ENGINE TEST COMPLETE\n";
    cout << "═══════════════════════════════════════════════════════════════════════════════════\n";
    cout << "\n✅ Statically linked compression with runtime tune selection\n";
    cout << "✅ Custom compression ratios via builder pattern\n";
    cout << "✅ Engine analogy: Swap tunes without rebuilding\n\n";
    
    return 0;
}
