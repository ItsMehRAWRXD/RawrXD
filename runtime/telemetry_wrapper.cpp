// ============================================================================
// telemetry_wrapper.cpp - C++ Wrapper for MASM Telemetry Core
// ============================================================================

#include "telemetry_ids.hpp"
#include <iostream>
#include <iomanip>
#include <vector>
#include <map>
#include <cstring>

namespace RawrXD {
namespace Runtime {
namespace Telemetry {

// ============================================================================
// Phase Name Lookup (for human-readable output)
// ============================================================================
const char* GetPhaseName(uint32_t phase_id) {
    switch (phase_id) {
        // Format adapters
        case TELEMETRY_GGUF_INIT_START:     return "GGUF_INIT_START";
        case TELEMETRY_GGUF_INIT_END:       return "GGUF_INIT_END";
        case TELEMETRY_GGUF_TENSOR_START:   return "GGUF_TENSOR_START";
        case TELEMETRY_GGUF_TENSOR_END:     return "GGUF_TENSOR_END";
        case TELEMETRY_GGUF_METADATA_PARSE: return "GGUF_METADATA_PARSE";
        case TELEMETRY_GGUF_LOAD_COMPLETE:  return "GGUF_LOAD_COMPLETE";
        
        // Quantization
        case TELEMETRY_Q2K_DECODE_BLOCK:    return "Q2K_DECODE_BLOCK";
        case TELEMETRY_Q4K_DECODE_BLOCK:    return "Q4K_DECODE_BLOCK";
        case TELEMETRY_Q6K_DECODE_BLOCK:    return "Q6K_DECODE_BLOCK";
        case TELEMETRY_Q8K_DECODE_BLOCK:    return "Q8K_DECODE_BLOCK";
        case TELEMETRY_F16_TO_F32:          return "F16_TO_F32";
        case TELEMETRY_BF16_TO_F32:         return "BF16_TO_F32";
        case TELEMETRY_DEQUANTIZE_ROW:      return "DEQUANTIZE_ROW";
        
        // Normalization
        case TELEMETRY_RMSNORM_START:       return "RMSNORM_START";
        case TELEMETRY_RMSNORM_END:         return "RMSNORM_END";
        case TELEMETRY_LAYERNORM_START:     return "LAYERNORM_START";
        case TELEMETRY_LAYERNORM_END:       return "LAYERNORM_END";
        
        // Attention
        case TELEMETRY_ATTENTION_START:     return "ATTENTION_START";
        case TELEMETRY_ATTENTION_QKV:       return "ATTENTION_QKV";
        case TELEMETRY_ATTENTION_ROPE:      return "ATTENTION_ROPE";
        case TELEMETRY_ATTENTION_SCORES:    return "ATTENTION_SCORES";
        case TELEMETRY_ATTENTION_SOFTMAX:   return "ATTENTION_SOFTMAX";
        case TELEMETRY_ATTENTION_WEIGHTED:  return "ATTENTION_WEIGHTED";
        case TELEMETRY_ATTENTION_OUTPUT:    return "ATTENTION_OUTPUT";
        case TELEMETRY_ATTENTION_END:       return "ATTENTION_END";
        
        // MLP
        case TELEMETRY_MLP_START:           return "MLP_START";
        case TELEMETRY_MLP_GATE:            return "MLP_GATE";
        case TELEMETRY_MLP_UP:                return "MLP_UP";
        case TELEMETRY_MLP_SiLU:            return "MLP_SiLU";
        case TELEMETRY_MLP_MUL:               return "MLP_MUL";
        case TELEMETRY_MLP_DOWN:              return "MLP_DOWN";
        case TELEMETRY_MLP_END:               return "MLP_END";
        
        // Layer
        case TELEMETRY_LAYER_START:         return "LAYER_START";
        case TELEMETRY_LAYER_ATTN:          return "LAYER_ATTN";
        case TELEMETRY_LAYER_MLP:           return "LAYER_MLP";
        case TELEMETRY_LAYER_END:           return "LAYER_END";
        
        // Backend
        case TELEMETRY_BRIDGE_INIT:         return "BRIDGE_INIT";
        case TELEMETRY_BRIDGE_LOAD_MODEL:   return "BRIDGE_LOAD_MODEL";
        case TELEMETRY_BRIDGE_BIND_TENSORS: return "BRIDGE_BIND_TENSORS";
        case TELEMETRY_TOKEN_EMBED:         return "TOKEN_EMBED";
        case TELEMETRY_TRANSFORMER_FORWARD: return "TRANSFORMER_FORWARD";
        case TELEMETRY_LOGITS_PROJECTION:   return "LOGITS_PROJECTION";
        case TELEMETRY_SAMPLING:            return "SAMPLING";
        case TELEMETRY_BRIDGE_SHUTDOWN:     return "BRIDGE_SHUTDOWN";
        
        // Generation
        case TELEMETRY_GENERATION_START:    return "GENERATION_START";
        case TELEMETRY_GENERATION_TOKEN:    return "GENERATION_TOKEN";
        case TELEMETRY_GENERATION_BATCH:    return "GENERATION_BATCH";
        case TELEMETRY_GENERATION_PREFILL:  return "GENERATION_PREFILL";
        case TELEMETRY_GENERATION_END:       return "GENERATION_END";
        
        // Memory
        case TELEMETRY_KV_CACHE_ALLOC:      return "KV_CACHE_ALLOC";
        case TELEMETRY_KV_CACHE_WRITE:      return "KV_CACHE_WRITE";
        case TELEMETRY_KV_CACHE_READ:       return "KV_CACHE_READ";
        case TELEMETRY_TENSOR_ALLOC:        return "TENSOR_ALLOC";
        case TELEMETRY_TENSOR_FREE:         return "TENSOR_FREE";
        
        // System
        case TELEMETRY_SYSTEM_INIT:         return "SYSTEM_INIT";
        case TELEMETRY_SYSTEM_SHUTDOWN:     return "SYSTEM_SHUTDOWN";
        case TELEMETRY_THREAD_POOL_EXEC:    return "THREAD_POOL_EXEC";
        
        default:                            return "UNKNOWN";
    }
}

// ============================================================================
// Telemetry Dumper (human-readable output)
// ============================================================================
void DumpTelemetry(std::ostream& out) {
    uint64_t count = Telemetry_GetCount();
    if (count == 0) {
        out << "No telemetry entries." << std::endl;
        return;
    }
    
    // Allocate buffer for entries
    std::vector<TelemetryEntry> buffer(count);
    uint64_t read = Telemetry_Dump(buffer.data(), count);
    
    out << "=== Telemetry Dump (" << read << " entries) ===" << std::endl;
    out << std::setw(8) << "Index" << " "
       << std::setw(20) << "Phase" << " "
       << std::setw(16) << "Timestamp" << " "
       << std::setw(16) << "Value0" << " "
       << std::setw(16) << "Value1" << std::endl;
    out << std::string(85, '-') << std::endl;
    
    uint64_t first_timestamp = (read > 0) ? buffer[0].timestamp : 0;
    
    for (uint64_t i = 0; i < read; ++i) {
        const auto& entry = buffer[i];
        uint64_t rel_time = entry.timestamp - first_timestamp;
        
        out << std::setw(8) << i << " "
           << std::setw(20) << GetPhaseName(entry.phase_id) << " "
           << std::setw(16) << rel_time << " "
           << std::setw(16) << entry.value0 << " "
           << std::setw(16) << entry.value1 << std::endl;
    }
    
    uint64_t dropped = Telemetry_GetDropped();
    if (dropped > 0) {
        out << "\nWARNING: " << dropped << " entries dropped (buffer full)" << std::endl;
    }
}

// ============================================================================
// Telemetry Analysis
// ============================================================================
struct PhaseTiming {
    uint32_t phase_id;
    uint64_t count;
    uint64_t total_cycles;
    uint64_t min_cycles;
    uint64_t max_cycles;
};

void AnalyzeTelemetry(std::ostream& out) {
    uint64_t count = Telemetry_GetCount();
    if (count == 0) {
        out << "No telemetry entries to analyze." << std::endl;
        return;
    }
    
    std::vector<TelemetryEntry> buffer(count);
    uint64_t read = Telemetry_Dump(buffer.data(), count);
    
    // Build timing map for START/END pairs
    std::map<uint32_t, PhaseTiming> timings;
    std::map<uint32_t, uint64_t> start_times;
    
    for (uint64_t i = 0; i < read; ++i) {
        const auto& entry = buffer[i];
        uint32_t phase = entry.phase_id;
        
        // Check if this is a START phase
        if (phase & 0x1) {  // Odd = END, Even = START (convention)
            // This is an END phase - look for matching START
            uint32_t start_phase = phase - 1;
            auto it = start_times.find(start_phase);
            if (it != start_times.end()) {
                uint64_t duration = entry.timestamp - it->second;
                
                auto& timing = timings[start_phase];
                timing.phase_id = start_phase;
                timing.count++;
                timing.total_cycles += duration;
                if (timing.count == 1 || duration < timing.min_cycles) {
                    timing.min_cycles = duration;
                }
                if (duration > timing.max_cycles) {
                    timing.max_cycles = duration;
                }
                
                start_times.erase(it);
            }
        } else {
            // This is a START phase
            start_times[phase] = entry.timestamp;
        }
    }
    
    out << "=== Telemetry Analysis ===" << std::endl;
    out << std::setw(20) << "Phase" << " "
       << std::setw(10) << "Count" << " "
       << std::setw(16) << "Avg Cycles" << " "
       << std::setw(16) << "Min Cycles" << " "
       << std::setw(16) << "Max Cycles" << std::endl;
    out << std::string(90, '-') << std::endl;
    
    for (const auto& [phase_id, timing] : timings) {
        uint64_t avg = timing.total_cycles / timing.count;
        out << std::setw(20) << GetPhaseName(phase_id) << " "
           << std::setw(10) << timing.count << " "
           << std::setw(16) << avg << " "
           << std::setw(16) << timing.min_cycles << " "
           << std::setw(16) << timing.max_cycles << std::endl;
    }
}

} // namespace Telemetry
} // namespace Runtime
} // namespace RawrXD
