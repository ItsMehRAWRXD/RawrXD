#include "MARSController.hpp"
#include <algorithm>
#include <chrono>

namespace Deep2 {

MARSController::MARSController(const MARSConfig& cfg) : cfg_(cfg) {}

MARSController::~MARSController() {
    if (initialized_.load()) shutdown();
}

bool MARSController::initialize(size_t gpu0Budget, size_t gpu1Budget) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (initialized_.load()) return true;
    cfg_.gpu0Budget = gpu0Budget;
    cfg_.gpu1Budget = gpu1Budget;
    gpu0Used_ = 0;
    gpu1Used_ = 0;
    hostUsed_ = 0;
    nextLeaseId_ = 1;
    leases_.clear();
    {
        std::lock_guard<std::mutex> slk(statsMtx_);
        stats_ = MARSStats{};
    }
    initialized_.store(true);
    return true;
}

void MARSController::shutdown() {
    std::lock_guard<std::mutex> lk(mtx_);
    leases_.clear();
    gpu0Used_ = 0;
    gpu1Used_ = 0;
    hostUsed_ = 0;
    initialized_.store(false);
}

bool MARSController::submit(const std::string& workTag) {
    (void)workTag;
    return initialized_.load();
}

bool MARSController::synchronize() {
    return initialized_.load();
}

int MARSController::chooseGpu(size_t bytes, float /*priority*/) const {
    // prefer least-utilized GPU that can fit; host (-1) if neither fits
    bool f0 = canFit(0, bytes);
    bool f1 = canFit(1, bytes);
    if (f0 && f1) {
        float u0 = cfg_.gpu0Budget > 0 ? static_cast<float>(gpu0Used_) / cfg_.gpu0Budget : 1.0f;
        float u1 = cfg_.gpu1Budget > 0 ? static_cast<float>(gpu1Used_) / cfg_.gpu1Budget : 1.0f;
        return u0 <= u1 ? 0 : 1;
    }
    if (f0) return 0;
    if (f1) return 1;
    return -1; // host resident
}

bool MARSController::canFit(int gpu, size_t bytes) const {
    if (gpu == 0) return (gpu0Used_ + bytes) <= cfg_.gpu0Budget;
    if (gpu == 1) return (gpu1Used_ + bytes) <= cfg_.gpu1Budget;
    return false;
}

void MARSController::updateUsed(int gpu, size_t bytes, bool add) {
    if (gpu == 0) gpu0Used_ = add ? (gpu0Used_ + bytes) : (gpu0Used_ > bytes ? gpu0Used_ - bytes : 0);
    else if (gpu == 1) gpu1Used_ = add ? (gpu1Used_ + bytes) : (gpu1Used_ > bytes ? gpu1Used_ - bytes : 0);
    else hostUsed_ = add ? (hostUsed_ + bytes) : (hostUsed_ > bytes ? hostUsed_ - bytes : 0);
}

VRAMLease* MARSController::placeTensor(uint64_t tensorId, const std::string& name,
                                       size_t bytes, float priority) {
    if (!initialized_.load() || bytes == 0) return nullptr;
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = leases_.find(tensorId);
    if (it != leases_.end()) {
        // already placed: update if same size, else redirect
        VRAMLease* existing = it->second.get();
        if (existing->bytes == bytes && existing->resident) return existing;
        // remove old accounting
        updateUsed(existing->gpu, existing->bytes, false);
        existing->resident = false;
    }
    int gpu = chooseGpu(bytes, priority);
    auto lease = std::make_unique<VRAMLease>();
    lease->id = nextLeaseId_++;
    lease->bytes = bytes;
    lease->gpu = gpu;
    lease->priority = priority;
    lease->name = name;
    lease->resident = true;
    lease->migrating = false;
    updateUsed(gpu, bytes, true);
    VRAMLease* ptr = lease.get();
    leases_[tensorId] = std::move(lease);
    {
        std::lock_guard<std::mutex> slk(statsMtx_);
        ++stats_.placements;
        if (gpu < 0) ++stats_.oomEvents;
    }
    return ptr;
}

size_t MARSController::placeAllTensors(
    const std::vector<std::tuple<uint64_t, std::string, size_t, float>>& items) {
    size_t placed = 0;
    for (const auto& t : items) {
        uint64_t id = std::get<0>(t);
        const std::string& name = std::get<1>(t);
        size_t bytes = std::get<2>(t);
        float pri = std::get<3>(t);
        if (placeTensor(id, name, bytes, pri)) ++placed;
    }
    return placed;
}

HotpatchResult MARSController::redirectTensor(uint64_t tensorId, int targetGPU) {
    HotpatchResult res{};
    auto t0 = std::chrono::high_resolution_clock::now();
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = leases_.find(tensorId);
    if (it == leases_.end()) return res;
    VRAMLease* lease = it->second.get();
    if (lease->gpu == targetGPU) { res.ok = true; return res; }
    if (targetGPU >= 0 && !canFit(targetGPU, lease->bytes)) {
        // cannot fit on target
        return res;
    }
    int oldGpu = lease->gpu;
    updateUsed(oldGpu, lease->bytes, false);
    updateUsed(targetGPU, lease->bytes, true);
    lease->gpu = targetGPU;
    lease->migrating = false;
    res.ok = true;
    res.leaseId = lease->id;
    res.fromGpu = oldGpu;
    res.toGpu = targetGPU;
    res.bytesMoved = lease->bytes;
    auto t1 = std::chrono::high_resolution_clock::now();
    res.latencyUs = static_cast<double>(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
    {
        std::lock_guard<std::mutex> slk(statsMtx_);
        ++stats_.redirects;
    }
    return res;
}

bool MARSController::rebalance() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (cfg_.gpu0Budget == 0 && cfg_.gpu1Budget == 0) return false;
    float u0 = cfg_.gpu0Budget > 0 ? static_cast<float>(gpu0Used_) / cfg_.gpu0Budget : 1.0f;
    float u1 = cfg_.gpu1Budget > 0 ? static_cast<float>(gpu1Used_) / cfg_.gpu1Budget : 1.0f;
    float diff = std::fabs(u0 - u1);
    if (diff <= cfg_.rebalanceThreshold) return false; // balanced enough
    // simple heuristic: move up to half the diff from overloaded to underloaded
    int src = u0 > u1 ? 0 : 1;
    int dst = src == 0 ? 1 : 0;
    size_t moved = 0;
    for (auto& p : leases_) {
        VRAMLease* lease = p.second.get();
        if (lease->gpu == src && !lease->migrating) {
            if (canFit(dst, lease->bytes)) {
                updateUsed(src, lease->bytes, false);
                updateUsed(dst, lease->bytes, true);
                lease->gpu = dst;
                moved += lease->bytes;
            }
        }
        if (moved > 0) break; // move one at a time to avoid thrashing
    }
    {
        std::lock_guard<std::mutex> slk(statsMtx_);
        ++stats_.rebalances;
    }
    return moved > 0;
}

DynamicParity MARSController::getDynamicParity() const {
    std::lock_guard<std::mutex> lk(mtx_);
    DynamicParity dp{};
    dp.gpu0Util = cfg_.gpu0Budget > 0 ? static_cast<float>(gpu0Used_) / cfg_.gpu0Budget : 0.0f;
    dp.gpu1Util = cfg_.gpu1Budget > 0 ? static_cast<float>(gpu1Used_) / cfg_.gpu1Budget : 0.0f;
    dp.gpu0Bytes = gpu0Used_;
    dp.gpu1Bytes = gpu1Used_;
    dp.hostBytes = hostUsed_;
    dp.leaseCount = leases_.size();
    float diff = std::fabs(dp.gpu0Util - dp.gpu1Util);
    dp.balanced = diff <= cfg_.rebalanceThreshold;
    return dp;
}

bool MARSController::handleTensorFault(uint64_t tensorId) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = leases_.find(tensorId);
    if (it == leases_.end()) return false;
    VRAMLease* lease = it->second.get();
    if (!lease->resident) return false;
    // migrate to host as safe fallback
    updateUsed(lease->gpu, lease->bytes, false);
    lease->gpu = -1;
    lease->resident = true;
    updateUsed(-1, lease->bytes, true);
    {
        std::lock_guard<std::mutex> slk(statsMtx_);
        ++stats_.faultsRecovered;
    }
    return true;
}

bool MARSController::handleGPUFailure(int gpu) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (gpu != 0 && gpu != 1) return false;
    size_t moved = 0;
    int dst = (gpu == 0) ? 1 : 0;
    for (auto& p : leases_) {
        VRAMLease* lease = p.second.get();
        if (lease->gpu == gpu) {
            if (canFit(dst, lease->bytes)) {
                updateUsed(gpu, lease->bytes, false);
                updateUsed(dst, lease->bytes, true);
                lease->gpu = dst;
                moved += lease->bytes;
            } else {
                // fallback to host
                updateUsed(gpu, lease->bytes, false);
                lease->gpu = -1;
                updateUsed(-1, lease->bytes, true);
                moved += lease->bytes;
            }
        }
    }
    {
        std::lock_guard<std::mutex> slk(statsMtx_);
        ++stats_.gpuFailuresHandled;
    }
    return moved > 0;
}

VRAMLease* MARSController::getLease(uint64_t tensorId) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = leases_.find(tensorId);
    return it != leases_.end() ? it->second.get() : nullptr;
}

const VRAMLease* MARSController::getLease(uint64_t tensorId) const {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = leases_.find(tensorId);
    return it != leases_.end() ? it->second.get() : nullptr;
}

MARSStats MARSController::stats() const {
    std::lock_guard<std::mutex> slk(statsMtx_);
    return stats_;
}

void MARSController::resetStats() {
    std::lock_guard<std::mutex> slk(statsMtx_);
    stats_ = MARSStats{};
}

bool MARSController::parityTest(float tolerance) const {
    std::lock_guard<std::mutex> lk(mtx_);
    float u0 = cfg_.gpu0Budget > 0 ? static_cast<float>(gpu0Used_) / cfg_.gpu0Budget : 0.0f;
    float u1 = cfg_.gpu1Budget > 0 ? static_cast<float>(gpu1Used_) / cfg_.gpu1Budget : 0.0f;
    float diff = std::fabs(u0 - u1);
    return diff <= tolerance;
}

} // namespace Deep2
