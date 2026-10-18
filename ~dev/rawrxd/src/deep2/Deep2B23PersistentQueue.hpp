#pragma once
#include <cstdint>
#include <vector>

namespace Deep2 {

enum class PersistentOp : uint8_t {
    Norm, QKV, Rope, Attention, OProj, Router, ExpertGateUp,
    ExpertDown, Residual, Logits
};

struct PersistentCommand {
    PersistentOp op{};
    uint32_t layer = 0;
    uint32_t deviceMask = 1;
    uint32_t arg0 = 0;
    uint32_t arg1 = 0;
};

struct PersistentQueuePlan {
    uint32_t ringCapacity = 0;
    uint32_t producerBatch = 0;
    uint32_t maxInflightLayers = 0;
    bool deviceLoop = true;
    bool hostWakePerToken = false;
    std::vector<PersistentCommand> templateCommands;
};

class B23PersistentQueue {
public:
    static PersistentQueuePlan make(uint32_t layers, bool moe, bool mla) noexcept;
};

}
