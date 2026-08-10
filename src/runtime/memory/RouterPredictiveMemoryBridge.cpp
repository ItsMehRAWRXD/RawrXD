#include "RouterPredictiveMemoryBridge.hpp"

namespace RawrXD {
namespace Memory {

void BindRouterToPredictiveMemory(TensorExecutionRouter& router,
                                  PredictiveMemoryManager& manager,
                                  DeviceId device) {
    (void)device;
    router.setMemoryManager(&manager);
}

} // namespace Memory
} // namespace RawrXD
