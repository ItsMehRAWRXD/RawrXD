#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace deep2 {
using DeviceId = uint32_t;
struct LayerAssignment { uint32_t first, end; DeviceId device; }; // half-open range
struct TransferStats { uint64_t bytes=0, transfers=0; double wall_ms=0; };
struct DeviceMemory { DeviceId device; uint64_t capacity_bytes, reserved_bytes; };
struct Plan { std::vector<LayerAssignment> stages; uint32_t layer_count=0; };

// Engine-owned callbacks must implement actual Vulkan device memory staging, barriers,
// submission and completion. No host pointer is ever treated as a device pointer.
struct Backend {
  std::function<void(DeviceId, uint32_t, uint32_t)> run_layers;
  std::function<void(DeviceId)> synchronize;
  std::function<void(DeviceId, DeviceId, size_t)> transfer_hidden;
  std::function<void(DeviceId, uint32_t)> activate_state_owner;
};

Plan make_contiguous_plan(uint32_t layers, const std::vector<uint64_t>& layer_weight_bytes,
                          const std::vector<DeviceMemory>& devices, uint64_t safety_bytes);
void validate_plan(const Plan& plan, const std::vector<DeviceMemory>& devices);
class DualGpuBridge {
 public:
  DualGpuBridge(Plan plan, Backend backend);
  void forward();
  const TransferStats& stats() const noexcept { return stats_; }
 private:
  Plan plan_;
  Backend backend_;
  TransferStats stats_;
};
}
