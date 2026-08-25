#pragma once

#include "OutOfCoreRuntime.hpp"
#include <cstdint>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>
#include <mutex>
#include <functional>

namespace rawrxd {

// Forward declarations
class Chamber;
class PlasmaGovernor;
enum class ChamberResult : uint8_t;
struct FormulaRoute;
struct ThermalState;

class SovereignOutOfCoreRuntime {
public:
    struct Config {
        std::size_t ramBudgetBytes = 8ull * 1024 * 1024 * 1024;
        std::size_t vramBudgetBytes = 0;
        bool enableCPU = true;
        bool enableGPU = false;
        bool automaticEviction = true;
        bool automaticPatchReapply = true;
    };

    struct TensorView {
        TensorId id = 0;
        const std::uint8_t* data = nullptr;
        std::size_t size = 0;
        Residency residency = Residency::None;
        std::uint64_t generation = 0;
    };

    struct PatchRequest {
        TensorId tensor = 0;
        PatchKind kind = PatchKind::Replace;
        std::uint64_t offset = 0;
        const void* data = nullptr;
        std::size_t size = 0;
    };

    explicit SovereignOutOfCoreRuntime(const Config& config);
    ~SovereignOutOfCoreRuntime();
    SovereignOutOfCoreRuntime(const SovereignOutOfCoreRuntime&) = delete;
    SovereignOutOfCoreRuntime& operator=(const SovereignOutOfCoreRuntime&) = delete;

    bool openModelFile(const std::string& path);
    bool attachStorage(std::shared_ptr<Storage> storage);
    bool storageReady() const;

    void setCPUBackend(std::shared_ptr<ExecutionBackend> backend);
    void setGPUBackend(std::shared_ptr<ExecutionBackend> backend);
    bool hasCPUBackend() const;
    bool hasGPUBackend() const;

    bool registerTensor(const TensorDescriptor& descriptor);
    bool registerTensors(const std::vector<TensorDescriptor>& tensors);
    bool containsTensor(TensorId id) const;
    std::size_t tensorCount() const;

    ResidencyLease acquireCPU(TensorId id);
    ResidencyLease acquireGPU(TensorId id);
    bool executeCPU(TensorId id);
    bool executeGPU(TensorId id);

    bool inspect(TensorId id, std::vector<std::uint8_t>& output);
    bool inspectRange(TensorId id, std::uint64_t offset, std::size_t size, std::vector<std::uint8_t>& output);
    bool overwrite(TensorId id, std::uint64_t offset, const void* data, std::size_t size);

    PatchId installPatch(const PatchRequest& request);
    bool removePatch(PatchId id);
    bool enablePatch(PatchId id);
    bool disablePatch(PatchId id);
    bool reapplyPatches(TensorId id);

    Residency residency(TensorId id) const;
    bool evict(TensorId id);
    bool reload(TensorId id, Backend backend);

    RuntimeStats stats() const;
    void resetStats();
    std::size_t ramUsed() const;
    std::size_t vramUsed() const;
    Config config() const;
    bool initialized() const;

    // Chamber (SM0-DSP) integration
    ChamberResult evaluateChamber(const float* hidden_state, size_t dim);
    FormulaRoute routePrimitive(uint64_t context_hash);

    // Plasma Governor (thermal safety) integration
    void updateThermalState(const ThermalState& state);
    float currentThrottle() const;
    bool isEmergencyStopped() const;

private:
    std::shared_ptr<OutOfCoreRuntime> runtime_;
    std::shared_ptr<ExecutionBackend> cpuBackend_;
    std::shared_ptr<ExecutionBackend> gpuBackend_;
    std::shared_ptr<Storage> storage_;
    std::unique_ptr<Chamber> chamber_;
    std::unique_ptr<PlasmaGovernor> governor_;
    Config config_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
};

} // namespace rawrxd
