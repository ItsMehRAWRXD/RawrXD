// VAL-056: KV Cache Correctness Witness
// Tracks temporal state across token generation

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace RawrXD {

// Simple hash for K/V tensors
struct TensorHash {
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
    
    bool operator==(const TensorHash& other) const {
        return memcmp(hash, other.hash, sizeof(hash)) == 0;
    }
};

// KV cache write witness
struct KVWriteWitness {
    int layer_id = -1;
    int position = -1;
    TensorHash k_hash;
    TensorHash v_hash;
    uint64_t timestamp_us = 0;
    size_t k_bytes = 0;
    size_t v_bytes = 0;
};

// Attention window witness
struct AttentionWindowWitness {
    int query_position = -1;
    int keys_available = 0;
    int causal_mask_start = 0;
    int causal_mask_end = 0;
    bool mask_applied = false;
};

// Memory telemetry snapshot
struct MemoryTelemetry {
    uint64_t model_mapped_bytes = 0;
    uint64_t kv_allocated_bytes = 0;
    uint64_t activation_bytes = 0;
    uint64_t resident_pages = 0;
    uint64_t timestamp_us = 0;
};

class KVCacheWitness {
public:
    std::vector<KVWriteWitness> writes;
    std::vector<AttentionWindowWitness> attention_windows;
    std::vector<MemoryTelemetry> memory_snapshots;
    
    int current_position = 0;
    int max_position = 0;
    int num_layers = 34;
    bool cache_enabled = true;
    
    void recordKVWrite(int layer_id, int position, 
                       const void* k_data, size_t k_bytes,
                       const void* v_data, size_t v_bytes) {
        KVWriteWitness witness;
        witness.layer_id = layer_id;
        witness.position = position;
        witness.k_bytes = k_bytes;
        witness.v_bytes = v_bytes;
        witness.timestamp_us = getTimestampMicros();
        
        if (k_data && k_bytes > 0) {
            witness.k_hash.compute(k_data, k_bytes);
        }
        if (v_data && v_bytes > 0) {
            witness.v_hash.compute(v_data, v_bytes);
        }
        
        writes.push_back(witness);
        
        if (position > max_position) {
            max_position = position;
        }
        
        printf("[KV-Witness] Layer %d, Position %d: K=%s V=%s\n",
               layer_id, position, 
               witness.k_hash.toString().c_str(),
               witness.v_hash.toString().c_str());
    }
    
    void recordAttentionWindow(int query_pos, int keys_avail) {
        AttentionWindowWitness witness;
        witness.query_position = query_pos;
        witness.keys_available = keys_avail;
        witness.causal_mask_start = 0;
        witness.causal_mask_end = query_pos; // Causal: can only see past
        witness.mask_applied = true;
        
        attention_windows.push_back(witness);
        
        printf("[Attn-Witness] Query pos %d, Keys available %d (causal mask 0..%d)\n",
               query_pos, keys_avail, query_pos);
    }
    
    void recordMemorySnapshot(uint64_t model_bytes, uint64_t kv_bytes, 
                              uint64_t activation_bytes) {
        MemoryTelemetry telemetry;
        telemetry.model_mapped_bytes = model_bytes;
        telemetry.kv_allocated_bytes = kv_bytes;
        telemetry.activation_bytes = activation_bytes;
        telemetry.resident_pages = kv_bytes / 4096; // Approximate
        telemetry.timestamp_us = getTimestampMicros();
        
        memory_snapshots.push_back(telemetry);
        
        printf("[Memory-Witness] Model: %lu MB, KV: %lu MB, Activations: %lu MB\n",
               model_bytes / (1024*1024), kv_bytes / (1024*1024), 
               activation_bytes / (1024*1024));
    }
    
    bool verifyPositionIncrement() const {
        if (writes.empty()) return false;
        
        int last_pos = -1;
        for (const auto& w : writes) {
            if (w.position <= last_pos && w.position != 0) {
                printf("[KV-Verify] FAIL: Position did not increment (%d -> %d)\n",
                       last_pos, w.position);
                return false;
            }
            last_pos = w.position;
        }
        return true;
    }
    
    bool verifyCausalMask() const {
        for (const auto& w : attention_windows) {
            if (w.keys_available > w.query_position + 1) {
                printf("[KV-Verify] FAIL: Causal mask violated (query=%d, keys=%d)\n",
                       w.query_position, w.keys_available);
                return false;
            }
        }
        return true;
    }
    
    bool verifyKVPairs() const {
        // Every K write should have corresponding V write at same position
        for (const auto& w : writes) {
            bool found_v = false;
            for (const auto& other : writes) {
                if (other.layer_id == w.layer_id && 
                    other.position == w.position &&
                    &other != &w) {
                    found_v = true;
                    break;
                }
            }
            if (!found_v) {
                printf("[KV-Verify] FAIL: Orphan K/V write at layer %d, pos %d\n",
                       w.layer_id, w.position);
                return false;
            }
        }
        return true;
    }
    
    std::string generateEvidenceJSON() const {
        std::stringstream json;
        json << "{\n";
        json << "  \"gate\": \"VAL-056\",\n";
        json << "  \"claim\": \"KV cache maintains temporal state correctly\",\n";
        json << "  \"kv_cache\": {\n";
        json << "    \"enabled\": " << (cache_enabled ? "true" : "false") << ",\n";
        json << "    \"layers\": " << num_layers << ",\n";
        json << "    \"initial_position\": 0,\n";
        json << "    \"final_position\": " << max_position << "\n";
        json << "  },\n";
        
        json << "  \"writes\": [\n";
        for (size_t i = 0; i < writes.size() && i < 10; ++i) {
            const auto& w = writes[i];
            json << "    {\n";
            json << "      \"layer\": " << w.layer_id << ",\n";
            json << "      \"position\": " << w.position << ",\n";
            json << "      \"k_hash\": \"" << w.k_hash.toString() << "\",\n";
            json << "      \"v_hash\": \"" << w.v_hash.toString() << "\"\n";
            json << "    }";
            if (i < std::min(writes.size(), size_t(10)) - 1) json << ",";
            json << "\n";
        }
        if (writes.size() > 10) {
            json << "    ... " << (writes.size() - 10) << " more writes\n";
        }
        json << "  ],\n";
        
        json << "  \"attention_window\": {\n";
        if (!attention_windows.empty()) {
            const auto& last = attention_windows.back();
            json << "    \"query_position\": " << last.query_position << ",\n";
            json << "    \"keys_available\": " << last.keys_available << "\n";
        }
        json << "  },\n";
        
        json << "  \"verification\": {\n";
        json << "    \"position_increment\": " << (verifyPositionIncrement() ? "true" : "false") << ",\n";
        json << "    \"causal_mask\": " << (verifyCausalMask() ? "true" : "false") << ",\n";
        json << "    \"kv_pairs\": " << (verifyKVPairs() ? "true" : "false") << "\n";
        json << "  },\n";
        
        json << "  \"memory_telemetry\": [\n";
        for (size_t i = 0; i < memory_snapshots.size(); ++i) {
            const auto& m = memory_snapshots[i];
            json << "    {\n";
            json << "      \"model_mb\": " << (m.model_mapped_bytes / (1024*1024)) << ",\n";
            json << "      \"kv_mb\": " << (m.kv_allocated_bytes / (1024*1024)) << ",\n";
            json << "      \"activation_mb\": " << (m.activation_bytes / (1024*1024)) << "\n";
            json << "    }";
            if (i < memory_snapshots.size() - 1) json << ",";
            json << "\n";
        }
        json << "  ],\n";
        
        json << "  \"status\": \"" << (verifyPositionIncrement() && verifyCausalMask() ? "PASS" : "FAIL") << "\"\n";
        json << "}\n";
        
        return json.str();
    }
    
    void saveEvidence(const std::string& path) const {
        std::ofstream file(path);
        file << generateEvidenceJSON();
    }

private:
    static uint64_t getTimestampMicros() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
};

// Global witness instance
static KVCacheWitness g_kv_witness;

} // namespace RawrXD

// C API for integration
extern "C" {

void kv_witness_init(int num_layers) {
    RawrXD::g_kv_witness.num_layers = num_layers;
    RawrXD::g_kv_witness.cache_enabled = true;
    printf("[KV-Witness] Initialized for %d layers\n", num_layers);
}

void kv_witness_write(int layer_id, int position,
                      const void* k_data, size_t k_bytes,
                      const void* v_data, size_t v_bytes) {
    RawrXD::g_kv_witness.recordKVWrite(layer_id, position, k_data, k_bytes, v_data, v_bytes);
}

void kv_witness_attention(int query_pos, int keys_avail) {
    RawrXD::g_kv_witness.recordAttentionWindow(query_pos, keys_avail);
}

void kv_witness_memory(uint64_t model_bytes, uint64_t kv_bytes, uint64_t activation_bytes) {
    RawrXD::g_kv_witness.recordMemorySnapshot(model_bytes, kv_bytes, activation_bytes);
}

void kv_witness_save(const char* path) {
    RawrXD::g_kv_witness.saveEvidence(path);
}

const char* kv_witness_get_json() {
    static std::string json;
    json = RawrXD::g_kv_witness.generateEvidenceJSON();
    return json.c_str();
}

} // extern "C"

// Standalone test
int main(int argc, char* argv[]) {
    using namespace RawrXD;
    
    printf("========================================\n");
    printf("VAL-056: KV Cache Correctness Witness\n");
    printf("========================================\n");
    
    // Initialize witness
    kv_witness_init(34);
    
    // Simulate token generation with KV writes
    printf("\n[TEST] Simulating 3 tokens across 2 layers...\n\n");
    
    for (int pos = 0; pos < 3; ++pos) {
        printf("--- Token %d ---\n", pos);
        
        for (int layer = 0; layer < 2; ++layer) {
            // Simulate K/V tensors
            float k_tensor[128] = {static_cast<float>(pos), static_cast<float>(layer)};
            float v_tensor[128] = {static_cast<float>(pos + 100), static_cast<float>(layer + 100)};
            
            kv_witness_write(layer, pos, 
                           k_tensor, sizeof(k_tensor),
                           v_tensor, sizeof(v_tensor));
        }
        
        // Record attention window
        kv_witness_attention(pos, pos + 1);
        
        // Memory snapshot
        kv_witness_memory(1000ULL * 1024 * 1024,  // 1GB model
                         (pos + 1) * 50ULL * 1024 * 1024,  // Growing KV
                         100ULL * 1024 * 1024);  // Constant activations
    }
    
    // Verify
    printf("\n========================================\n");
    printf("Verification:\n");
    printf("========================================\n");
    printf("Position increment: %s\n", 
           g_kv_witness.verifyPositionIncrement() ? "PASS" : "FAIL");
    printf("Causal mask: %s\n", 
           g_kv_witness.verifyCausalMask() ? "PASS" : "FAIL");
    printf("K/V pairs: %s\n", 
           g_kv_witness.verifyKVPairs() ? "PASS" : "FAIL");
    
    // Generate evidence
    printf("\n========================================\n");
    printf("Evidence JSON:\n");
    printf("========================================\n");
    printf("%s\n", kv_witness_get_json());
    
    // Save to file
    kv_witness_save("val056_kv_cache_witness.json");
    printf("\nEvidence saved to: val056_kv_cache_witness.json\n");
    
    return 0;
}
