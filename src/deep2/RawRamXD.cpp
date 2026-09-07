// RawRamXD.cpp — minimal fabric implementation for K2 residency bridge
#include "RawRamXD.hpp"
#include <algorithm>
#include <cstring>

namespace rawramxd {

// ============================================================================
// CapacityLedger
// ============================================================================
CapacityLedger::CapacityLedger(const std::array<size_t, 3>& capacities)
    : capacities_(capacities) {
    for (auto& v : used_) v.store(0, std::memory_order_relaxed);
}

bool CapacityLedger::tryReserve(Tier tier, size_t bytes) noexcept {
    const size_t i = static_cast<size_t>(tier);
    if (i >= capacities_.size()) return false;
    size_t current = used_[i].load(std::memory_order_relaxed);
    for (;;) {
        if (bytes > capacities_[i] - current) return false;
        if (used_[i].compare_exchange_weak(
                current, current + bytes,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return true;
        }
    }
}

void CapacityLedger::release(Tier tier, size_t bytes) {
    const size_t i = static_cast<size_t>(tier);
    if (i >= capacities_.size()) throw std::out_of_range("CapacityLedger tier");
    size_t current = used_[i].load(std::memory_order_relaxed);
    for (;;) {
        if (bytes > current) throw std::logic_error("CapacityLedger underflow");
        if (used_[i].compare_exchange_weak(
                current, current - bytes,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            return;
        }
    }
}

size_t CapacityLedger::used(Tier tier) const noexcept {
    const size_t i = static_cast<size_t>(tier);
    return i < used_.size() ? used_[i].load(std::memory_order_acquire) : 0;
}

size_t CapacityLedger::capacity(Tier tier) const noexcept {
    const size_t i = static_cast<size_t>(tier);
    return i < capacities_.size() ? capacities_[i] : 0;
}

// ============================================================================
// CapacityReservation
// ============================================================================
CapacityReservation::CapacityReservation(
    std::shared_ptr<CapacityLedger> ledger, Tier tier, size_t bytes)
    : ledger_(std::move(ledger)), tier_(tier), bytes_(bytes), committed_(false) {}

CapacityReservation::~CapacityReservation() {
    if (!committed_ && ledger_) {
        try { ledger_->release(tier_, bytes_); } catch (...) { std::terminate(); }
    }
}

CapacityReservation::CapacityReservation(CapacityReservation&& other) noexcept
    : ledger_(std::move(other.ledger_)), tier_(other.tier_),
      bytes_(other.bytes_), committed_(other.committed_) {
    other.committed_ = true;
}

CapacityReservation& CapacityReservation::operator=(CapacityReservation&& other) noexcept {
    if (this != &other) {
        if (!committed_ && ledger_) {
            try { ledger_->release(tier_, bytes_); } catch (...) { std::terminate(); }
        }
        ledger_ = std::move(other.ledger_);
        tier_ = other.tier_;
        bytes_ = other.bytes_;
        committed_ = other.committed_;
        other.committed_ = true;
    }
    return *this;
}

void CapacityReservation::commit() noexcept { committed_ = true; }

// ============================================================================
// PhysicalAllocation
// ============================================================================
PhysicalAllocation::PhysicalAllocation(
    std::shared_ptr<TierBackend> backend,
    AllocationHandle handle,
    std::shared_ptr<CapacityLedger> ledger) noexcept
    : backend_(std::move(backend)),
      handle_(std::move(handle)),
      ledger_(std::move(ledger)) {}

PhysicalAllocation::~PhysicalAllocation() noexcept {
    if (backend_) backend_->release(handle_);
    if (ledger_) {
        try { ledger_->release(handle_.tier, handle_.size); }
        catch (...) { std::terminate(); }
    }
}

// ============================================================================
// ResidencyLease
// ============================================================================
ResidencyLease::ResidencyLease(
    std::shared_ptr<ResidencyBlock> block,
    std::shared_ptr<ResidencyVersion> version)
    : block_(std::move(block)), version_(std::move(version)) {
    if (version_) {
        version_->readerCount.fetch_add(1, std::memory_order_acq_rel);
    }
}

ResidencyLease::~ResidencyLease() { reset(); }

ResidencyLease::ResidencyLease(ResidencyLease&& other) noexcept
    : block_(std::move(other.block_)),
      version_(std::move(other.version_)) {}

ResidencyLease& ResidencyLease::operator=(ResidencyLease&& other) noexcept {
    if (this != &other) {
        reset();
        block_ = std::move(other.block_);
        version_ = std::move(other.version_);
    }
    return *this;
}

void ResidencyLease::reset() noexcept {
    if (version_) {
        version_->readerCount.fetch_sub(1, std::memory_order_acq_rel);
        version_.reset();
    }
    block_.reset();
}

void* ResidencyLease::hostPtr() const noexcept {
    return version_ && version_->allocation
        ? version_->allocation->get().hostPtr : nullptr;
}

uint64_t ResidencyLease::deviceAddress() const noexcept {
    return version_ && version_->allocation
        ? version_->allocation->get().deviceAddress : 0;
}

Tier ResidencyLease::tier() const noexcept {
    return version_ ? version_->tier : Tier::NVMe;
}

uint64_t ResidencyLease::generation() const noexcept {
    return version_ ? version_->generation : 0;
}

uint64_t ResidencyLease::blockId() const noexcept {
    return block_ ? block_->id : 0;
}

size_t ResidencyLease::size() const noexcept {
    return version_ && version_->allocation
        ? version_->allocation->get().size : 0;
}

// ============================================================================
// NVMeFileBackend
// ============================================================================
NVMeFileBackend::NVMeFileBackend(uint32_t id, uint64_t generation) {
    id_ = id; generation_ = generation;
}

AllocationHandle NVMeFileBackend::allocate(size_t bytes) {
    AllocationHandle h{};
    h.id = nextId_.fetch_add(1, std::memory_order_relaxed);
    h.tier = Tier::NVMe;
    h.backendGeneration = generation_;
    h.size = bytes;
    h.hostPtr = std::malloc(bytes);
    if (h.hostPtr) h.flags = 1 | 2; // CAP_FILE_BACKED | CAP_HOST_MEMORY
    return h;
}

void NVMeFileBackend::release(const AllocationHandle& h) noexcept {
    std::free(h.hostPtr);
}

// ============================================================================
// HostRAMBackend
// ============================================================================
HostRAMBackend::HostRAMBackend(uint32_t id, uint64_t generation) {
    id_ = id; generation_ = generation;
}

AllocationHandle HostRAMBackend::allocate(size_t bytes) {
    AllocationHandle h{};
    h.id = nextId_.fetch_add(1, std::memory_order_relaxed);
    h.tier = Tier::RAM;
    h.backendGeneration = generation_;
    h.size = bytes;
#ifdef _WIN32
    h.hostPtr = _aligned_malloc(bytes, 64);
#else
    h.hostPtr = nullptr;
    if (bytes != 0) {
        void* p = nullptr;
        if (posix_memalign(&p, 64, bytes) == 0) h.hostPtr = p;
    }
#endif
    if (h.hostPtr) h.flags = 2 | 4; // CAP_HOST_MEMORY | CAP_DMA
    return h;
}

void HostRAMBackend::release(const AllocationHandle& h) noexcept {
#ifdef _WIN32
    _aligned_free(h.hostPtr);
#else
    std::free(h.hostPtr);
#endif
}

// ============================================================================
// VulkanDeviceBackend
// ============================================================================
VulkanDeviceBackend::VulkanDeviceBackend(
    uint32_t id, uint64_t generation,
    void* user, AllocateFn allocFn, ReleaseFn relFn)
    : user_(user), allocFn_(allocFn), relFn_(relFn) {
    id_ = id; generation_ = generation;
}

AllocationHandle VulkanDeviceBackend::allocate(size_t bytes) {
    if (!allocFn_) return {};
    AllocationHandle h = allocFn_(user_, bytes);
    if (h.tier != Tier::VRAM) return {};
    if (h.backendGeneration != generation_) h.backendGeneration = generation_;
    if (h.id == 0) h.id = nextId_.fetch_add(1, std::memory_order_relaxed);
    h.size = bytes;
    return h;
}

void VulkanDeviceBackend::release(const AllocationHandle& h) noexcept {
    if (relFn_) relFn_(user_, h);
}

// ============================================================================
// MultiTierTransferEngine
// ============================================================================
MultiTierTransferEngine::MultiTierTransferEngine(
    void* vulkanContext,
    TransferSubmitFn submitFn,
    WaitFenceFn waitFn)
    : vulkanContext_(vulkanContext), submitFn_(submitFn), waitFn_(waitFn) {}

bool MultiTierTransferEngine::canTransfer(Tier src, Tier dst) const noexcept {
    if (src == dst) return false;
    return (src == Tier::NVMe && dst == Tier::RAM) ||
           (src == Tier::RAM  && dst == Tier::NVMe) ||
           (src == Tier::RAM  && dst == Tier::VRAM) ||
           (src == Tier::VRAM && dst == Tier::RAM) ||
           (src == Tier::NVMe && dst == Tier::VRAM) ||
           (src == Tier::VRAM && dst == Tier::NVMe);
}

bool MultiTierTransferEngine::transfer(
    const AllocationHandle& src, const AllocationHandle& dst,
    size_t bytes, CopyToken& token) {
    token = {};
    const Tier srcTier = src.tier;
    const Tier dstTier = dst.tier;
    if (!canTransfer(srcTier, dstTier)) return false;
    if (bytes == 0 || bytes > src.size || bytes > dst.size) return false;

    // NVMe <-> RAM: memcpy
    if ((srcTier == Tier::NVMe && dstTier == Tier::RAM) ||
        (srcTier == Tier::RAM  && dstTier == Tier::NVMe)) {
        if (!src.hostPtr || !dst.hostPtr) return false;
        std::memcpy(dst.hostPtr, src.hostPtr, bytes);
        token.id = nextToken_.fetch_add(1, std::memory_order_relaxed);
        token.completed = true;
        return true;
    }

    // RAM -> VRAM: Vulkan staging upload
    if (srcTier == Tier::RAM && dstTier == Tier::VRAM) {
        if (!src.hostPtr || !dst.nativeBuffer) return false;
        if (submitFn_ && !submitFn_(vulkanContext_, src, dst, bytes, token))
            return false;
        if (token.id == 0) {
            token.id = nextToken_.fetch_add(1, std::memory_order_relaxed);
        }
        return true;
    }

    // VRAM -> RAM: Vulkan readback
    if (srcTier == Tier::VRAM && dstTier == Tier::RAM) {
        if (!src.nativeBuffer || !dst.hostPtr) return false;
        if (submitFn_ && !submitFn_(vulkanContext_, src, dst, bytes, token))
            return false;
        if (token.id == 0) {
            token.id = nextToken_.fetch_add(1, std::memory_order_relaxed);
        }
        return true;
    }

    // NVMe <-> VRAM: two-phase via RAM (fabric orchestrates)
    // For now, return false to let fabric chain NVMe->RAM->VRAM
    return false;
}

bool MultiTierTransferEngine::wait(CopyToken token) {
    if (token.completed) return true;
    if (waitFn_) return waitFn_(vulkanContext_, token.id);
    return token.id != 0;
}

// ============================================================================
// RawRamXDFabric
// ============================================================================
RawRamXDFabric::RawRamXDFabric(
    std::shared_ptr<CapacityLedger> ledger,
    std::shared_ptr<TierBackend> nvme,
    std::shared_ptr<TierBackend> ram,
    std::shared_ptr<TierBackend> vram,
    std::shared_ptr<TransferEngine> transfer,
    size_t blockSize)
    : ledger_(std::move(ledger)),
      nvmeBackend_(std::move(nvme)),
      ramBackend_(std::move(ram)),
      vramBackend_(std::move(vram)),
      transferEngine_(std::move(transfer)),
      blockSize_(blockSize) {
    if (!ledger_ || !nvmeBackend_ || !ramBackend_ ||
        !vramBackend_ || !transferEngine_ || blockSize_ == 0) {
        throw std::invalid_argument("RawRamXDFabric invalid dependencies");
    }
}

RawRamXDFabric::~RawRamXDFabric() {
    runtimeState_.store(RuntimeState::STOPPED, std::memory_order_release);
}

uint64_t RawRamXDFabric::allocate(size_t size, const char* name) {
    if (runtimeState_.load(std::memory_order_acquire) != RuntimeState::RUNNING)
        return 0;
    if (size == 0) return 0;
    const uint64_t handleId = nextHandle_.fetch_add(1, std::memory_order_relaxed);
    auto handle = std::make_shared<Handle>();
    handle->id = handleId;
    handle->size = size;
    handle->active.store(true, std::memory_order_release);
    const size_t count = (size + blockSize_ - 1) / blockSize_;
    std::vector<std::shared_ptr<ResidencyBlock>> staged;
    staged.reserve(count);
    try {
        for (size_t i = 0; i < count; ++i) {
            const size_t bytes = std::min(blockSize_, size - i * blockSize_);
            if (!ledger_->tryReserve(Tier::NVMe, bytes)) return 0;
            CapacityReservation reservation(ledger_, Tier::NVMe, bytes);
            AllocationHandle ah = nvmeBackend_->allocate(bytes);
            if (!ah.hostPtr) return 0;
            auto physical = std::make_shared<PhysicalAllocation>(
                nvmeBackend_, std::move(ah), ledger_);
            auto block = std::make_shared<ResidencyBlock>();
            block->id = nextBlockId_.fetch_add(1, std::memory_order_relaxed);
            block->tensorId = handleId;
            block->size = static_cast<uint32_t>(bytes);
            block->name = name ? name : "unnamed";
            block->state.store(ResidencyBlock::State::RESIDENT, std::memory_order_relaxed);
            auto version = std::make_shared<ResidencyVersion>();
            version->blockId = block->id;
            version->generation = 1;
            version->tier = Tier::NVMe;
            version->backendId = nvmeBackend_->backendId();
            version->backendGeneration = nvmeBackend_->backendGeneration();
            version->allocation = std::move(physical);
            block->activeVersion = std::move(version);
            staged.push_back(std::move(block));
            reservation.commit();
        }
    } catch (...) { return 0; }
    {
        std::lock_guard<std::mutex> lock(blocksMutex_);
        for (const auto& b : staged) blocks_.emplace(b->id, b);
    }
    handle->blocks = std::move(staged);
    {
        std::lock_guard<std::mutex> lock(handlesMutex_);
        handles_.emplace(handleId, handle);
    }
    return handleId;
}

ResidencyLease RawRamXDFabric::acquire(
    uint64_t tensorId, uint32_t blockIndex, Tier targetTier) {
    if (runtimeState_.load(std::memory_order_acquire) != RuntimeState::RUNNING)
        return {};
    auto block = resolveBlockForTensor(tensorId, blockIndex);
    if (!block) return {};
    if (!ensureBlockInTier(block->id, targetTier)) return {};
    std::lock_guard<std::mutex> lock(block->blockMutex);
    return pinActiveVersionLocked(block, targetTier);
}

bool RawRamXDFabric::migrate(uint64_t blockId, Tier targetTier) {
    if (runtimeState_.load(std::memory_order_acquire) != RuntimeState::RUNNING)
        return false;
    return ensureBlockInTier(blockId, targetTier);
}

std::shared_ptr<ResidencyBlock> RawRamXDFabric::resolveBlockForTensor(
    uint64_t tensorId, uint32_t blockIndex) const {
    std::lock_guard<std::mutex> lock(handlesMutex_);
    auto it = handles_.find(tensorId);
    if (it == handles_.end()) return nullptr;
    const auto& h = it->second;
    if (!h->active.load(std::memory_order_acquire) || blockIndex >= h->blocks.size())
        return nullptr;
    return h->blocks[blockIndex];
}

std::shared_ptr<ResidencyBlock> RawRamXDFabric::resolveBlock(uint64_t blockId) const {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    auto it = blocks_.find(blockId);
    return it == blocks_.end() ? nullptr : it->second;
}

std::shared_ptr<TierBackend> RawRamXDFabric::backendFor(Tier tier) const {
    switch (tier) {
        case Tier::NVMe: return nvmeBackend_;
        case Tier::RAM:  return ramBackend_;
        case Tier::VRAM: return vramBackend_;
    }
    return nullptr;
}

bool RawRamXDFabric::ensureBlockInTier(uint64_t blockId, Tier targetTier) {
    auto block = resolveBlock(blockId);
    if (!block) return false;
    for (;;) {
        uint64_t sourceGeneration = 0;
        uint64_t ticket = 0;
        {
            std::unique_lock<std::mutex> lock(block->blockMutex);
            if (runtimeState_.load(std::memory_order_acquire) != RuntimeState::RUNNING)
                return false;
            auto active = block->activeVersion;
            if (active && active->allocation &&
                active->tier == targetTier &&
                block->state.load(std::memory_order_acquire) == ResidencyBlock::State::RESIDENT) {
                return true;
            }
            if (block->state.load(std::memory_order_acquire) == ResidencyBlock::State::MIGRATING) {
                const uint64_t waitingFor = block->migrationTicket;
                block->migrationCv.wait(lock, [&] {
                    return block->state.load(std::memory_order_acquire) != ResidencyBlock::State::MIGRATING ||
                           block->migrationTicket != waitingFor;
                });
                continue;
            }
            if (block->state.load(std::memory_order_acquire) == ResidencyBlock::State::FAILED) {
                if (!block->activeVersion || !block->activeVersion->allocation) return false;
                block->state.store(ResidencyBlock::State::RESIDENT, std::memory_order_relaxed);
            }
            active = block->activeVersion;
            if (!active || !active->allocation) return false;
            sourceGeneration = active->generation;
            ticket = nextMigrationTicket_.fetch_add(1, std::memory_order_relaxed);
            block->migrationTarget = targetTier;
            block->migrationTicket = ticket;
            block->state.store(ResidencyBlock::State::MIGRATING, std::memory_order_relaxed);
            migrationsStarted_.fetch_add(1, std::memory_order_relaxed);
        }
        const bool success = performMigration(block, targetTier, sourceGeneration, ticket);
        {
            std::lock_guard<std::mutex> lock(block->blockMutex);
            if (success) {
                block->state.store(ResidencyBlock::State::RESIDENT, std::memory_order_relaxed);
            } else {
                if (block->activeVersion && block->activeVersion->allocation) {
                    block->state.store(ResidencyBlock::State::RESIDENT, std::memory_order_relaxed);
                } else {
                    block->state.store(ResidencyBlock::State::FAILED, std::memory_order_relaxed);
                }
            }
        }
        block->migrationCv.notify_all();
        if (success) return true;
        return false;
    }
}

bool RawRamXDFabric::performMigration(
    const std::shared_ptr<ResidencyBlock>& block,
    Tier targetTier, uint64_t sourceGeneration, uint64_t ticket) {
    auto targetBackend = backendFor(targetTier);
    if (!targetBackend) return false;
    const size_t bytes = block->size;
    if (!ledger_->tryReserve(targetTier, bytes)) return false;
    CapacityReservation reservation(ledger_, targetTier, bytes);
    AllocationHandle dstHandle = targetBackend->allocate(bytes);
    if (dstHandle.size != bytes ||
        (!dstHandle.hostPtr && !dstHandle.nativeBuffer)) {
        return false;
    }
    auto dstPhysical = std::make_shared<PhysicalAllocation>(
        targetBackend, std::move(dstHandle), ledger_);
    std::shared_ptr<PhysicalAllocation> srcPhysical;
    {
        std::lock_guard<std::mutex> lock(block->blockMutex);
        auto current = block->activeVersion;
        if (!current || !current->allocation ||
            current->generation != sourceGeneration ||
            block->migrationTicket != ticket ||
            block->state.load(std::memory_order_acquire) != ResidencyBlock::State::MIGRATING) {
            return false;
        }
        srcPhysical = current->allocation;
    }
    if (!srcPhysical ||
        !transferEngine_->canTransfer(srcPhysical->get().tier, targetTier)) {
        migrationsFailed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    CopyToken token{};
    if (!transferEngine_->transfer(
            srcPhysical->get(), dstPhysical->get(), bytes, token)) {
        migrationsFailed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    if (!transferEngine_->wait(token)) {
        migrationsFailed_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(block->blockMutex);
        auto current = block->activeVersion;
        if (!current || !current->allocation ||
            current->generation != sourceGeneration ||
            block->migrationTicket != ticket ||
            block->state.load(std::memory_order_acquire) != ResidencyBlock::State::MIGRATING) {
            migrationsFailed_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        auto newVersion = std::make_shared<ResidencyVersion>();
        newVersion->blockId = block->id;
        newVersion->generation = current->generation + 1;
        newVersion->tier = targetTier;
        newVersion->backendId = targetBackend->backendId();
        newVersion->backendGeneration = targetBackend->backendGeneration();
        newVersion->allocation = std::move(dstPhysical);
        block->retiredVersions.push_back(std::move(block->activeVersion));
        block->activeVersion = std::move(newVersion);
        reclaimRetiredLocked(*block);
    }
    reservation.commit();
    migrationsCompleted_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

ResidencyLease RawRamXDFabric::pinActiveVersionLocked(
    const std::shared_ptr<ResidencyBlock>& block, Tier targetTier) {
    if (runtimeState_.load(std::memory_order_acquire) != RuntimeState::RUNNING)
        return {};
    auto version = block->activeVersion;
    if (!version || !version->allocation || version->tier != targetTier ||
        block->state.load(std::memory_order_acquire) != ResidencyBlock::State::RESIDENT)
        return {};
    version->readerCount.fetch_add(1, std::memory_order_acq_rel);
    return ResidencyLease(block, std::move(version));
}

void RawRamXDFabric::reclaimRetiredLocked(ResidencyBlock& block) {
    block.retiredVersions.erase(
        std::remove_if(
            block.retiredVersions.begin(),
            block.retiredVersions.end(),
            [](const std::shared_ptr<ResidencyVersion>& v) {
                return v && v->readerCount.load(std::memory_order_acquire) == 0;
            }),
        block.retiredVersions.end());
}

RawRamXDFabric::Stats RawRamXDFabric::stats() const {
    Stats s;
    s.nvmeUsed = ledger_->used(Tier::NVMe);
    s.ramUsed  = ledger_->used(Tier::RAM);
    s.vramUsed = ledger_->used(Tier::VRAM);
    s.migrationsStarted   = migrationsStarted_.load(std::memory_order_acquire);
    s.migrationsCompleted = migrationsCompleted_.load(std::memory_order_acquire);
    s.migrationsFailed    = migrationsFailed_.load(std::memory_order_acquire);
    return s;
}

} // namespace rawramxd
