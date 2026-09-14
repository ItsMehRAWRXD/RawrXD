#include "Deep2B23PersistentQueue.hpp"

namespace Deep2 {

PersistentQueuePlan B23PersistentQueue::make(uint32_t layers, bool moe, bool mla) noexcept {
    PersistentQueuePlan p{};
    p.maxInflightLayers = layers >= 48 ? 4u : 2u;
    p.producerBatch = layers >= 48 ? 8u : 4u;
    p.ringCapacity = layers * (moe ? 10u : 8u) + 64u;
    p.deviceLoop = true;
    p.hostWakePerToken = false;

    for (uint32_t l=0; l<layers; ++l) {
        p.templateCommands.push_back({PersistentOp::Norm,l,3,0,0});
        p.templateCommands.push_back({PersistentOp::QKV,l,3,mla?1u:0u,0});
        p.templateCommands.push_back({PersistentOp::Rope,l,3,0,0});
        p.templateCommands.push_back({PersistentOp::Attention,l,3,mla?1u:0u,0});
        p.templateCommands.push_back({PersistentOp::OProj,l,3,0,0});
        if (moe) {
            p.templateCommands.push_back({PersistentOp::Router,l,3,0,0});
            p.templateCommands.push_back({PersistentOp::ExpertGateUp,l,3,0,0});
            p.templateCommands.push_back({PersistentOp::ExpertDown,l,3,0,0});
        }
        p.templateCommands.push_back({PersistentOp::Residual,l,3,0,0});
    }
    p.templateCommands.push_back({PersistentOp::Logits,layers,1,0,0});
    return p;
}

}
