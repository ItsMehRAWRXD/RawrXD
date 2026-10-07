// ============================================================================
// Multi-GPU Routing - R9700 / RX7800XT Residency
// ============================================================================
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>

namespace Deep2 {
    struct GPUDevice {
        std::string name;
        uint64_t vram_capacity;
        uint64_t vram_used;
        bool is_integrated;
    };

    class RoutingEngine {
    public:
        RoutingEngine() {}
        
        void registerDevice(int id, const std::string& name, uint64_t vram, bool integrated) {
            devices[id] = {name, vram, 0, integrated};
        }

        int assignTensor(const std::string& name, uint64_t sizeBytes) {
            // Prioritize dedicated GPU (RX 7800 XT) for MoE experts
            bool isMoE = (name.find("ffn_gate") != std::string::npos || 
                          name.find("ffn_down") != std::string::npos ||
                          name.find("ffn_up") != std::string::npos);
            
            int bestId = -1;
            uint64_t maxFree = 0;
            
            for (auto& pair : devices) {
                auto& dev = pair.second;
                uint64_t free = dev.vram_capacity - dev.vram_used;
                
                if (isMoE && !dev.is_integrated && free >= sizeBytes) {
                    dev.vram_used += sizeBytes;
                    return pair.first;
                }
                
                if (free >= sizeBytes && free > maxFree) {
                    maxFree = free;
                    bestId = pair.first;
                }
            }
            
            if (bestId != -1) {
                devices[bestId].vram_used += sizeBytes;
            }
            return bestId;
        }
        
    private:
        std::unordered_map<int, GPUDevice> devices;
    };
}
