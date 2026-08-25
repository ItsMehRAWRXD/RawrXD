// ============================================================================
// SovereignOutOfCoreRuntime.cpp — The Dragon Lore Scope
// Dual-backend (CPU/GPU), deterministic routing, tokamak plasma confinement
// ============================================================================

#include "SovereignOutOfCoreRuntime.hpp"
#include "Chamber.hpp"
#include "ToroidalKVCache.hpp"
#include "PlasmaGovernor.hpp"
#include "GGMLBackend.hpp"
#include <stdexcept>
#include <chrono>

namespace rawrxd {

// ============================================================================
// SovereignOutOfCoreRuntime — The kennyS Scope
// ============================================================================
SovereignOutOfCoreRuntime::SovereignOutOfCoreRuntime(const Config& config)
    : config_(config)
{
    auto dummyStorage = std::make_shared<FileStorage>("");
    runtime_ = std::make_shared<OutOfCoreRuntime>(
        dummyStorage, config.ramBudgetBytes, config.vramBudgetBytes);

    // Default CPU backend
    cpuBackend_ = std::make_shared<CPUBackend>();
    runtime_->setBackend(cpuBackend_);

    // Initialize chamber (SM0-DSP mirror)
    chamber_ = std::make_unique<Chamber>();

    // Initialize plasma governor (thermal safety)
    governor_ = std::make_unique<PlasmaGovernor>();

    initialized_ = true;
}

SovereignOutOfCoreRuntime::~SovereignOutOfCoreRuntime() = default;

bool SovereignOutOfCoreRuntime::openModelFile(const std::string& path) {
    auto storage = std::make_shared<FileStorage>(path);
    if (!storage->valid()) return false;
    return attachStorage(storage);
}

bool SovereignOutOfCoreRuntime::attachStorage(std::shared_ptr<Storage> storage) {
    if (!storage) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    storage_ = storage;
    runtime_->setBackend(cpuBackend_);  // Reset to CPU while loading
    initialized_ = true;
    return true;
}

bool SovereignOutOfCoreRuntime::storageReady() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return storage_ != nullptr;
}

void SovereignOutOfCoreRuntime::setCPUBackend(std::shared_ptr<ExecutionBackend> backend) {
    if (!backend) throw std::invalid_argument("CPU backend is null");
    std::lock_guard<std::mutex> lock(mutex_);
    cpuBackend_ = backend;
    if (!hasGPUBackend()) {
        runtime_->setBackend(cpuBackend_);
    }
}

void SovereignOutOfCoreRuntime::setGPUBackend(std::shared_ptr<ExecutionBackend> backend) {
    if (!backend) throw std::invalid_argument("GPU backend is null");
    std::lock_guard<std::mutex> lock(mutex_);
    gpuBackend_ = backend;
    if (config_.enableGPU) {
        runtime_->setBackend(gpuBackend_);
    }
}

bool SovereignOutOfCoreRuntime::hasCPUBackend() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return cpuBackend_ != nullptr;
}

bool SovereignOutOfCoreRuntime::hasGPUBackend() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return gpuBackend_ != nullptr;
}

bool SovereignOutOfCoreRuntime::registerTensor(const TensorDescriptor& descriptor) {
    std::lock_guard<std::mutex> lock(mutex_);
    runtime_->registerTensor(descriptor);
    return true;
}

bool SovereignOutOfCoreRuntime::registerTensors(const std::vector<TensorDescriptor>& tensors) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& td : tensors) {
        runtime_->registerTensor(td);
    }
    return true;
}

bool SovereignOutOfCoreRuntime::containsTensor(TensorId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->hasTensor(id);
}

std::size_t SovereignOutOfCoreRuntime::tensorCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // OutOfCoreRuntime doesn't expose tensor count directly
    // Return 0 as placeholder; extend OutOfCoreRuntime if needed
    return 0;
}

ResidencyLease SovereignOutOfCoreRuntime::acquireCPU(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cpuBackend_) throw std::runtime_error("CPU backend not set");
    runtime_->setBackend(cpuBackend_);
    return runtime_->acquire(id, Backend::CPU);
}

ResidencyLease SovereignOutOfCoreRuntime::acquireGPU(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!gpuBackend_) throw std::runtime_error("GPU backend not set");
    runtime_->setBackend(gpuBackend_);
    return runtime_->acquire(id, Backend::GPU);
}

bool SovereignOutOfCoreRuntime::executeCPU(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!cpuBackend_) return false;
    runtime_->setBackend(cpuBackend_);
    return runtime_->execute(id);
}

bool SovereignOutOfCoreRuntime::executeGPU(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!gpuBackend_) return false;
    runtime_->setBackend(gpuBackend_);
    return runtime_->execute(id);
}

bool SovereignOutOfCoreRuntime::inspect(TensorId id, std::vector<std::uint8_t>& output) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Not directly supported by OutOfCoreRuntime; would need download
    return false;
}

bool SovereignOutOfCoreRuntime::inspectRange(TensorId id, std::uint64_t offset, std::size_t size, std::vector<std::uint8_t>& output) {
    std::lock_guard<std::mutex> lock(mutex_);
    return false;
}

bool SovereignOutOfCoreRuntime::overwrite(TensorId id, std::uint64_t offset, const void* data, std::size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);
    return false;
}

PatchId SovereignOutOfCoreRuntime::installPatch(const PatchRequest& request) {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->installPatch(request.tensor, request.kind, request.offset, request.data, request.size);
}

bool SovereignOutOfCoreRuntime::removePatch(PatchId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->removePatch(id);
}

bool SovereignOutOfCoreRuntime::enablePatch(PatchId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->setPatchEnabled(id, true);
}

bool SovereignOutOfCoreRuntime::disablePatch(PatchId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->setPatchEnabled(id, false);
}

bool SovereignOutOfCoreRuntime::reapplyPatches(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->reapplyPatches(id);
}

Residency SovereignOutOfCoreRuntime::residency(TensorId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->residency(id);
}

bool SovereignOutOfCoreRuntime::evict(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->evict(id);
}

bool SovereignOutOfCoreRuntime::reload(TensorId id, Backend backend) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Force reload by evicting then acquiring
    runtime_->evict(id);
    runtime_->acquire(id, backend);
    return true;
}

RuntimeStats SovereignOutOfCoreRuntime::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->stats();
}

void SovereignOutOfCoreRuntime::resetStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    runtime_->clearStats();
}

std::size_t SovereignOutOfCoreRuntime::ramUsed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->ramUsed();
}

std::size_t SovereignOutOfCoreRuntime::vramUsed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return runtime_->vramUsed();
}

SovereignOutOfCoreRuntime::Config SovereignOutOfCoreRuntime::config() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return config_;
}

bool SovereignOutOfCoreRuntime::initialized() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return initialized_;
}

// ============================================================================
// Chamber integration — SM0-DSP clash detection
// ============================================================================
ChamberResult SovereignOutOfCoreRuntime::evaluateChamber(const float* hidden_state, size_t dim) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!chamber_) return ChamberResult::CLASH;
    return chamber_->evaluate(hidden_state, dim);
}

FormulaRoute SovereignOutOfCoreRuntime::routePrimitive(uint64_t context_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!chamber_) return FormulaRoute{};
    return chamber_->routePrimitive(context_hash);
}

// ============================================================================
// Plasma Governor integration — thermal safety
// ============================================================================
void SovereignOutOfCoreRuntime::updateThermalState(const ThermalState& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (governor_) {
        governor_->updateThermalState(state);
    }
}

float SovereignOutOfCoreRuntime::currentThrottle() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!governor_) return 0.0f;
    return governor_->currentThrottle();
}

bool SovereignOutOfCoreRuntime::isEmergencyStopped() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!governor_) return false;
    return governor_->isEmergencyStopped();
}

} // namespace rawrxd
