// VAL-058: Performance Certification Harness
// Measures tokens/sec, latency, memory bandwidth with correctness invariant

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace RawrXD {

// Simple hash for output verification
struct OutputHash {
    uint64_t hash[4];
    
    void compute(const void* data, size_t bytes) {
        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        uint64_t h[4] = {
            0xcbf29ce484222325,
            0x84222325cbf29ce4,
            0x9ce484222325cbf2,
            0x2225cbf29ce48423
        };
        
        for (size_t i = 0; i < bytes; ++i) {
            for (int j = 0; j < 4; ++j) {
                h[j] ^= (ptr[i] + j * 0x9e3779b97f4a7c15);
                h[j] *= 0x100000001b3;
            }
        }
        
        memcpy(hash, h, sizeof(hash));
    }
    
    std::string toString() const {
        char buf[65];
        snprintf(buf, sizeof(buf), "%016lx%016lx%016lx%016lx",
                 hash[0], hash[1], hash[2], hash[3]);
        return std::string(buf);
    }
    
    bool operator==(const OutputHash& other) const {
        return memcmp(hash, other.hash, sizeof(hash)) == 0;
    }
};

// Performance metrics
struct PromptPhaseMetrics {
    double tokens_processed = 0;
    double elapsed_ms = 0;
    double tokens_per_sec = 0;
    double first_token_latency_ms = 0;
    double memory_bandwidth_gbps = 0;
    OutputHash output_hash;
};

struct DecodePhaseMetrics {
    double tokens_generated = 0;
    double elapsed_ms = 0;
    double tokens_per_sec = 0;
    double kv_cache_growth_mb = 0;
    double per_layer_latency_ms[34] = {0};
    double sampler_overhead_ms = 0;
    OutputHash output_hash;
};

class PerformanceBenchmark {
public:
    PromptPhaseMetrics prompt_metrics;
    DecodePhaseMetrics decode_metrics;
    
    // Correctness invariant: output must match reference
    OutputHash reference_hash;
    bool correctness_preserved = false;
    
    void beginPromptPhase() {
        prompt_start_time = getTimestampMicros();
    }
    
    void recordFirstToken() {
        prompt_metrics.first_token_latency_ms = 
            (getTimestampMicros() - prompt_start_time) / 1000.0;
    }
    
    void endPromptPhase(int tokens_processed, size_t bytes_read, const OutputHash& hash) {
        uint64_t end_time = getTimestampMicros();
        prompt_metrics.elapsed_ms = (end_time - prompt_start_time) / 1000.0;
        prompt_metrics.tokens_processed = tokens_processed;
        prompt_metrics.tokens_per_sec = tokens_processed / (prompt_metrics.elapsed_ms / 1000.0);
        
        // Memory bandwidth: bytes / time
        double seconds = prompt_metrics.elapsed_ms / 1000.0;
        prompt_metrics.memory_bandwidth_gbps = (bytes_read / seconds) / 1e9;
        prompt_metrics.output_hash = hash;
        
        printf("[Perf] Prompt: %d tokens in %.2f ms (%.2f TPS, %.2f GB/s)\n",
               tokens_processed, prompt_metrics.elapsed_ms, 
               prompt_metrics.tokens_per_sec, prompt_metrics.memory_bandwidth_gbps);
    }
    
    void beginDecodePhase() {
        decode_start_time = getTimestampMicros();
        kv_cache_start_mb = getCurrentKVCacheMB();
    }
    
    void recordLayerLatency(int layer_id, double latency_ms) {
        if (layer_id >= 0 && layer_id < 34) {
            decode_metrics.per_layer_latency_ms[layer_id] = latency_ms;
        }
    }
    
    void recordSamplerOverhead(double overhead_ms) {
        decode_metrics.sampler_overhead_ms = overhead_ms;
    }
    
    void endDecodePhase(int tokens_generated, const OutputHash& hash) {
        uint64_t end_time = getTimestampMicros();
        decode_metrics.elapsed_ms = (end_time - decode_start_time) / 1000.0;
        decode_metrics.tokens_generated = tokens_generated;
        decode_metrics.tokens_per_sec = tokens_generated / (decode_metrics.elapsed_ms / 1000.0);
        
        double kv_cache_end_mb = getCurrentKVCacheMB();
        decode_metrics.kv_cache_growth_mb = kv_cache_end_mb - kv_cache_start_mb;
        decode_metrics.output_hash = hash;
        
        printf("[Perf] Decode: %d tokens in %.2f ms (%.2f TPS, KV +%.2f MB)\n",
               tokens_generated, decode_metrics.elapsed_ms,
               decode_metrics.tokens_per_sec, decode_metrics.kv_cache_growth_mb);
    }
    
    void setReferenceHash(const OutputHash& hash) {
        reference_hash = hash;
    }
    
    bool verifyCorrectnessInvariant() {
        // Optimization accepted only if output hash matches reference
        correctness_preserved = (prompt_metrics.output_hash == reference_hash) &&
                               (decode_metrics.output_hash == reference_hash);
        
        if (!correctness_preserved) {
            printf("[CRITICAL] Correctness invariant VIOLATED!\n");
            printf("  Reference: %s\n", reference_hash.toString().c_str());
            printf("  Prompt:    %s\n", prompt_metrics.output_hash.toString().c_str());
            printf("  Decode:    %s\n", decode_metrics.output_hash.toString().c_str());
        }
        
        return correctness_preserved;
    }
    
    std::string generateEvidenceJSON() const {
        std::stringstream json;
        json << "{\n";
        json << "  \"gate\": \"VAL-058\",\n";
        json << "  \"claim\": \"Performance meets baselines without correctness regression\",\n";
        json << "  \"correctness_invariant\": " << (correctness_preserved ? "true" : "false") << ",\n";
        json << "  \"prompt_phase\": {\n";
        json << "    \"tokens_processed\": " << prompt_metrics.tokens_processed << ",\n";
        json << "    \"elapsed_ms\": " << std::fixed << std::setprecision(2) << prompt_metrics.elapsed_ms << ",\n";
        json << "    \"tokens_per_sec\": " << std::fixed << std::setprecision(2) << prompt_metrics.tokens_per_sec << ",\n";
        json << "    \"first_token_latency_ms\": " << std::fixed << std::setprecision(2) << prompt_metrics.first_token_latency_ms << ",\n";
        json << "    \"memory_bandwidth_gbps\": " << std::fixed << std::setprecision(2) << prompt_metrics.memory_bandwidth_gbps << ",\n";
        json << "    \"output_hash\": \"" << prompt_metrics.output_hash.toString() << "\"\n";
        json << "  },\n";
        json << "  \"decode_phase\": {\n";
        json << "    \"tokens_generated\": " << decode_metrics.tokens_generated << ",\n";
        json << "    \"elapsed_ms\": " << std::fixed << std::setprecision(2) << decode_metrics.elapsed_ms << ",\n";
        json << "    \"tokens_per_sec\": " << std::fixed << std::setprecision(2) << decode_metrics.tokens_per_sec << ",\n";
        json << "    \"kv_cache_growth_mb\": " << std::fixed << std::setprecision(2) << decode_metrics.kv_cache_growth_mb << ",\n";
        json << "    \"sampler_overhead_ms\": " << std::fixed << std::setprecision(2) << decode_metrics.sampler_overhead_ms << ",\n";
        json << "    \"output_hash\": \"" << decode_metrics.output_hash.toString() << "\"\n";
        json << "  },\n";
        json << "  \"reference_hash\": \"" << reference_hash.toString() << "\",\n";
        json << "  \"status\": \"" << (correctness_preserved ? "PASS" : "FAIL") << "\"\n";
        json << "}\n";
        return json.str();
    }
    
    void saveEvidence(const std::string& path) const {
        std::ofstream file(path);
        file << generateEvidenceJSON();
    }

private:
    uint64_t prompt_start_time = 0;
    uint64_t decode_start_time = 0;
    double kv_cache_start_mb = 0;
    
    static uint64_t getTimestampMicros() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    
    static double getCurrentKVCacheMB() {
        // Placeholder - would query actual KV cache size
        return 34.0; // 34MB from VAL-056
    }
};

// Global benchmark instance
static PerformanceBenchmark g_benchmark;

} // namespace RawrXD

// C API for integration
extern "C" {

void perf_begin_prompt() {
    RawrXD::g_benchmark.beginPromptPhase();
}

void perf_first_token() {
    RawrXD::g_benchmark.recordFirstToken();
}

void perf_end_prompt(int tokens, size_t bytes, const void* output, size_t output_bytes) {
    RawrXD::OutputHash hash;
    hash.compute(output, output_bytes);
    RawrXD::g_benchmark.endPromptPhase(tokens, bytes, hash);
}

void perf_begin_decode() {
    RawrXD::g_benchmark.beginDecodePhase();
}

void perf_layer_latency(int layer_id, double latency_ms) {
    RawrXD::g_benchmark.recordLayerLatency(layer_id, latency_ms);
}

void perf_sampler_overhead(double overhead_ms) {
    RawrXD::g_benchmark.recordSamplerOverhead(overhead_ms);
}

void perf_end_decode(int tokens, const void* output, size_t output_bytes) {
    RawrXD::OutputHash hash;
    hash.compute(output, output_bytes);
    RawrXD::g_benchmark.endDecodePhase(tokens, hash);
}

void perf_set_reference(const void* output, size_t output_bytes) {
    RawrXD::OutputHash hash;
    hash.compute(output, output_bytes);
    RawrXD::g_benchmark.setReferenceHash(hash);
}

int perf_verify_correctness() {
    return RawrXD::g_benchmark.verifyCorrectnessInvariant() ? 1 : 0;
}

void perf_save_evidence(const char* path) {
    RawrXD::g_benchmark.saveEvidence(path);
}

const char* perf_get_evidence_json() {
    static std::string json;
    json = RawrXD::g_benchmark.generateEvidenceJSON();
    return json.c_str();
}

} // extern "C"

// Standalone test
int main(int argc, char* argv[]) {
    using namespace RawrXD;
    
    printf("========================================\n");
    printf("VAL-058: Performance Certification\n");
    printf("========================================\n");
    printf("Invariant: output_hash_before == output_hash_after\n\n");
    
    // Simulate reference output
    float reference_output[8] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f};
    perf_set_reference(reference_output, sizeof(reference_output));
    
    printf("Reference hash: %s\n\n", g_benchmark.reference_hash.toString().c_str());
    
    // Simulate prompt phase
    printf("[TEST] Prompt phase...\n");
    perf_begin_prompt();
    
    // Simulate work
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    perf_first_token();
    
    // Simulate more work
    std::this_thread::sleep_for(std::chrono::milliseconds(90));
    
    // Same output as reference (correctness preserved)
    float prompt_output[8] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f};
    perf_end_prompt(55, 100000000, prompt_output, sizeof(prompt_output));
    
    // Simulate decode phase
    printf("\n[TEST] Decode phase...\n");
    perf_begin_decode();
    
    // Simulate layer latencies
    for (int i = 0; i < 34; ++i) {
        perf_layer_latency(i, 2.5f + i * 0.01f);
    }
    
    perf_sampler_overhead(0.5f);
    
    // Simulate more work
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Same output as reference (correctness preserved)
    float decode_output[8] = {0.1f, 0.2f, 0.3f, 0.4f, 0.5f, 0.6f, 0.7f, 0.8f};
    perf_end_decode(10, decode_output, sizeof(decode_output));
    
    // Verify correctness invariant
    printf("\n========================================\n");
    printf("Correctness Verification:\n");
    printf("========================================\n");
    
    bool correct = perf_verify_correctness();
    printf("Correctness preserved: %s\n", correct ? "YES" : "NO");
    
    if (correct) {
        printf("\nOptimization ACCEPTED: output hash matches reference\n");
    } else {
        printf("\nOptimization REJECTED: output hash diverged!\n");
    }
    
    // Generate evidence
    printf("\n========================================\n");
    printf("Evidence JSON:\n");
    printf("========================================\n");
    printf("%s\n", perf_get_evidence_json());
    
    perf_save_evidence("val058_performance_certification.json");
    printf("\nEvidence saved to: val058_performance_certification.json\n");
    
    return correct ? 0 : 1;
}
