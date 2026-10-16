// ============================================================================
// OutOfCoreRuntime.cpp — Real implementation of OutOfCoreRuntime
// Replaces inline stub methods with working tensor/patch management.
// ============================================================================

#include "OutOfCoreRuntime.hpp"
#include <algorithm>
#include <cstring>

namespace rawrxd {

OutOfCoreRuntime::OutOfCoreRuntime(std::shared_ptr<Storage> storage,
                                   size_t ramBudgetBytes,
                                   size_t vramBudgetBytes)
    : storage_(std::move(storage)),
      backend_(nullptr),
      ramBudgetBytes_(ramBudgetBytes),
      vramBudgetBytes_(vramBudgetBytes) {}

OutOfCoreRuntime::~OutOfCoreRuntime() = default;

void OutOfCoreRuntime::setBackend(std::shared_ptr<ExecutionBackend> backend) {
    std::lock_guard<std::mutex> lock(mutex_);
    backend_ = std::move(backend);
}

void OutOfCoreRuntime::registerTensor(const TensorDescriptor& descriptor) {
    std::lock_guard<std::mutex> lock(mutex_);
    TensorId id = nextTensorId_++;
    TensorEntry entry;
    entry.descriptor = descriptor;
    entry.descriptor.id = id;
    entry.residency = Residency::RAM;
    ramUsed_ += descriptor.size;
    tensors_[id] = std::move(entry);
}

bool OutOfCoreRuntime::hasTensor(TensorId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return tensors_.find(id) != tensors_.end();
}

ResidencyLease OutOfCoreRuntime::acquire(TensorId id, Backend /*backend*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    if (it == tensors_.end()) {
        return ResidencyLease{};
    }
    it->second.residency = Residency::RAM;
    return ResidencyLease{id};
}

bool OutOfCoreRuntime::execute(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    if (it == tensors_.end()) {
        return false;
    }
    if (backend_) {
        return backend_->execute(it->second.descriptor, nullptr);
    }
    return true;
}

PatchId OutOfCoreRuntime::installPatch(const PatchRequest& request) {
    return installPatch(request.tensor, request.kind, request.offset,
                        request.data, request.size);
}

PatchId OutOfCoreRuntime::installPatch(TensorId tensor, PatchKind kind,
                                       uint64_t offset,
                                       const void* data, size_t size) {
    std::lock_guard<std::mutex> lock(mutex_);

    PatchEntry entry;
    entry.id = nextPatchId_++;
    entry.tensor = tensor;
    entry.kind = kind;
    entry.offset = offset;
    if (data && size > 0) {
        entry.data.assign(static_cast<const uint8_t*>(data),
                          static_cast<const uint8_t*>(data) + size);
    }
    entry.enabled = true;
    patches_[entry.id] = std::move(entry);

    // Apply patch to tensor data if present
    auto tit = tensors_.find(tensor);
    if (tit != tensors_.end()) {
        auto& tdata = tit->second.data;
        if (offset + size > tdata.size()) {
            tdata.resize(offset + size);
        }
        if (data && size > 0) {
            std::memcpy(tdata.data() + offset, data, size);
        }
    }

    return entry.id;
}

bool OutOfCoreRuntime::removePatch(PatchId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    return patches_.erase(id) > 0;
}

bool OutOfCoreRuntime::setPatchEnabled(PatchId id, bool enabled) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = patches_.find(id);
    if (it == patches_.end()) {
        return false;
    }
    it->second.enabled = enabled;
    return true;
}

bool OutOfCoreRuntime::reapplyPatches(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto tit = tensors_.find(id);
    if (tit == tensors_.end()) {
        return false;
    }
    auto& tdata = tit->second.data;
    std::fill(tdata.begin(), tdata.end(), uint8_t(0));
    for (const auto& [pid, pent] : patches_) {
        if (!pent.enabled || pent.tensor != id) continue;
        if (pent.offset + pent.data.size() > tdata.size()) {
            tdata.resize(pent.offset + pent.data.size());
        }
        std::memcpy(tdata.data() + pent.offset, pent.data.data(), pent.data.size());
    }
    return true;
}

Residency OutOfCoreRuntime::residency(TensorId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    if (it == tensors_.end()) {
        return Residency::None;
    }
    return it->second.residency;
}

bool OutOfCoreRuntime::evict(TensorId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = tensors_.find(id);
    if (it == tensors_.end()) {
        return false;
    }
    ramUsed_ -= it->second.descriptor.size;
    tensors_.erase(it);
    return true;
}

RuntimeStats OutOfCoreRuntime::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    RuntimeStats s;
    s.ramUsed = ramUsed_;
    s.vramUsed = vramUsed_;
    s.tensorCount = tensors_.size();
    return s;
}

void OutOfCoreRuntime::clearStats() {
    std::lock_guard<std::mutex> lock(mutex_);
    ramUsed_ = 0;
    vramUsed_ = 0;
}

size_t OutOfCoreRuntime::ramUsed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ramUsed_;
}

size_t OutOfCoreRuntime::vramUsed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return vramUsed_;
}

} // namespace rawrxd
