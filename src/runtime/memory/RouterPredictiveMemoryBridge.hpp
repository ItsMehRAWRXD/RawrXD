#pragma once

#include "runtime/TensorExecutionRouter.hpp"
#include "runtime/memory/PredictiveMemoryManager.hpp"

namespace RawrXD {
namespace Memory {

// B003 bridge: wire router execution hooks to predictive-memory APIs.
void BindRouterToPredictiveMemory(TensorExecutionRouter& router,
                                  PredictiveMemoryManager& manager,
                                  DeviceId device = 0);

} // namespace Memory
} // namespace RawrXD
