#include "RawRamXD_v22.hpp"

#include <cstdlib>
#ifdef _WIN32
#include <malloc.h>
#endif

namespace rawramxd {

// ============================================================================
// CapacityLedger
// ============================================================================

CapacityLedger::CapacityLedger(const std::array<size_t, 3>& capacities)
    : capacities_(capacities) {
    for (auto& v : used_) {
        v.store(0, std::memory_order_relaxed);
    }
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
    if (i >= capacities_.size())
        throw std::out_of_range("CapacityLedger tier");

    size_t current = used_[i].load(std::memory_order_relaxed);
    for (;;) {
        if (bytes > current)
            throw std::logic_error("CapacityLedger underflow");

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
    return i < used_.size()
        ? used_[i].load(std::memory_order_acquire)
        : 0;
}

size_t CapacityLedger::capacity(Tier tier) const noexcept {
    const size_t i = static_cast<size_t>(tier);
    return i < capacities_.size() ? capacities_[i] : 0;
}

// ============================================================================
// CapacityReservation
// ============================================================================

CapacityReservation::CapacityReservation(
    std::shared_ptr<CapacityLedger> ledger,
    Tier tier,
    size_t bytes)
    : ledger_(std::move(ledger)),
      tier_(tier),
      bytes_(bytes),
      committed_(false) {
    if (ledger_ && !ledger_->tryReserve(tier_, bytes_)) {
        bytes_ = 0;
    }
}

CapacityReservation::~CapacityReservation() {
    if (!committed_ && ledger_ && bytes_ > 0) {
        try {
            ledger_->release(tier_, bytes_);
        } catch (...) {
            std::terminate();
        }
    }
}

CapacityReservation::CapacityReservation(CapacityReservation&& other) noexcept
    : ledger_(std::move(other.ledger_)),
      tier_(other.tier_),
      bytes_(other.bytes_),
      committed_(other.committed_) {
    other.committed_ = true;
}

CapacityReservation& CapacityReservation::operator=(
    CapacityReservation&& other) noexcept {
    if (this != &other) {
        if (!committed_ && ledger_) {
            try {
                ledger_->release(tier_, bytes_);
            } catch (...) {
                std::terminate();
            }
        }
        ledger_ = std::move(other.ledger_);
        tier_ = other.tier_;
        bytes_ = other.bytes_;
        committed_ = other.committed_;
        other.committed_ = true;
    }
    return *this;
}

void CapacityReservation::commit() noexcept {
    committed_ = true;
}

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
    if (backend_) {
        backend_->release(handle_);
    }
    if (ledger_) {
        try {
            ledger_->release(handle_.tier, handle_.size);
        } catch (...) {
            std::terminate();
        }
    }
}

// ============================================================================
// RawRamXDTransferEngine (composite router for all tier pairs)
// ============================================================================

bool RawRamXDTransferEngine::canTransfer(
    Tier srcTier, Tier dstTier) const noexcept {
    // All tier pairs are supported; actual capability depends on
    // whether the backends expose the right handles.
    if (srcTier == dstTier) return true;
    return true;
}

bool RawRamXDTransferEngine::transfer(
    const PhysicalAllocation& src,
    PhysicalAllocation& dst,
    size_t bytes,
    CopyToken& token) {
    token = {};

    const Tier srcTier = src.get().tier;
    const Tier dstTier = dst.get().tier;

    if (srcTier == Tier::NVMe && dstTier == Tier::RAM) {
        return transferHostToHost(src, dst, bytes);
    }
    if (srcTier == Tier::RAM && dstTier == Tier::NVMe) {
        return transferHostToHost(src, dst, bytes);
    }
    if (srcTier == Tier::RAM && dstTier == Tier::VRAM) {
        return transferHostToDevice(src, dst, bytes, token);
    }
    if (srcTier == Tier::VRAM && dstTier == Tier::RAM) {
        return transferDeviceToHost(src, dst, bytes, token);
    }
    if (srcTier == Tier::VRAM && dstTier == Tier::VRAM) {
        return transferDeviceToDevice(src, dst, bytes, token);
    }
    if (srcTier == Tier::NVMe && dstTier == Tier::VRAM) {
        // Pipeline: NVMe -> RAM -> VRAM
        // For now, fail-closed until a staging buffer is available.
        return false;
    }
    if (srcTier == Tier::VRAM && dstTier == Tier::NVMe) {
        // Pipeline: VRAM -> RAM -> NVMe
        return false;
    }

    return false;
}

bool RawRamXDTransferEngine::wait(CopyToken token) {
    // Synchronous wait: for host-to-host, token is already completed.
    // For async device transfers, this would block on the timeline value.
    return token.id != 0 && token.state == TransferState::COMPLETED;
}

bool RawRamXDTransferEngine::poll(CopyToken token) noexcept {
    return token.id != 0 && token.state == TransferState::COMPLETED;
}

bool RawRamXDTransferEngine::transferHostToHost(
    const PhysicalAllocation& src,
    PhysicalAllocation& dst,
    size_t bytes) {
    if (bytes == 0 ||
        bytes > src.get().size ||
        bytes > dst.get().size ||
        !src.get().hostPtr ||
        !dst.get().hostPtr) {
        return false;
    }

    std::memcpy(dst.get().hostPtr, src.get().hostPtr, bytes);
    return true;
}

bool RawRamXDTransferEngine::transferHostToDevice(
    const PhysicalAllocation& src,
    PhysicalAllocation& dst,
    size_t bytes,
    CopyToken& token) {
    // Placeholder: real implementation uses Vulkan staging buffer + DMA.
    // For now, if the VRAM backend exposes a mapped host pointer,
    // we can memcpy directly. Otherwise, fail closed.
    if (bytes == 0 ||
        bytes > src.get().size ||
        bytes > dst.get().size ||
        !src.get().hostPtr) {
        return false;
    }

    if (dst.get().hostPtr && (dst.get().flags & CAP_MAPPED)) {
        std::memcpy(dst.get().hostPtr, src.get().hostPtr, bytes);
        token.id = nextToken_.fetch_add(1, std::memory_order_relaxed);
        token.timelineValue = nextTimeline_.fetch_add(1, std::memory_order_relaxed);
        token.state = TransferState::COMPLETED;
        return true;
    }

    // Unmapped device memory requires real Vulkan DMA.
    return false;
}

bool RawRamXDTransferEngine::transferDeviceToHost(
    const PhysicalAllocation& src,
    PhysicalAllocation& dst,
    size_t bytes,
    CopyToken& token) {
    if (bytes == 0 ||
        bytes > src.get().size ||
        bytes > dst.get().size ||
        !dst.get().hostPtr) {
        return false;
    }

    if (src.get().hostPtr && (src.get().flags & CAP_MAPPED)) {
        std::memcpy(dst.get().hostPtr, src.get().hostPtr, bytes);
        token.id = nextToken_.fetch_add(1, std::memory_order_relaxed);
        token.timelineValue = nextTimeline_.fetch_add(1, std::memory_order_relaxed);
        token.state = TransferState::COMPLETED;
        return true;
    }

    return false;
}

bool RawRamXDTransferEngine::transferDeviceToDevice(
    const PhysicalAllocation& src,
    PhysicalAllocation& dst,
    size_t bytes,
    CopyToken& token) {
    // Peer copy requires real Vulkan vkCmdCopyBuffer.
    (void)src;
    (void)dst;
    (void)bytes;
    (void)token;
    return false;
}

// ============================================================================
// LeaseTracker (with underflow protection)
// ============================================================================

void LeaseTracker::acquire() {
    active_.fetch_add(1, std::memory_order_acq_rel);
}

void LeaseTracker::release() noexcept {
    uint64_t current = active_.load(std::memory_order_acquire);
    for (;;) {
        if (current == 0) {
            std::terminate();
        }
        if (active_.compare_exchange_weak(
                current, current - 1,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            if (current == 1) {
                std::lock_guard<std::mutex> lock(mutex_);
                cv_.notify_all();
            }
            return;
        }
    }
}

void LeaseTracker::drain() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [&] {
        return active_.load(std::memory_order_acquire) == 0;
    });
}

// ============================================================================
// MigrationTracker (P0: prevents shutdown race)
// ============================================================================

void MigrationTracker::acquire() {
    active_.fetch_add(1, std::memory_order_acq_rel);
}

void MigrationTracker::release() noexcept {
    uint64_t current = active_.load(std::memory_order_acquire);
    for (;;) {
        if (current == 0) {
            std::terminate();
        }
        if (active_.compare_exchange_weak(
                current, current - 1,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            if (current == 1) {
                std::lock_guard<std::mutex> lock(mutex_);
                cv_.notify_all();
            }
            return;
        }
    }
}

void MigrationTracker::drain() {
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait(lock, [&] {
        return active_.load(std::memory_order_acquire) == 0;
    });
}

// ============================================================================
// ResidencyBlock CAS transition (P0: v2.2 state machine)
// ============================================================================

bool ResidencyBlock::tryTransitionState(
    ResidencyState expected,
    ResidencyState desired) noexcept {
    ResidencyState exp = expected;
    return state.compare_exchange_strong(
        exp,
        desired,
        std::memory_order_acq_rel,
        std::memory_order_acquire);
}

// ============================================================================
// ResidencyLease (with reclaim callback for retired version cleanup)
// ============================================================================

ResidencyLease::ResidencyLease(
    std::shared_ptr<ResidencyBlock> block,
    std::shared_ptr<ResidencyVersion> version,
    std::shared_ptr<LeaseTracker> tracker,
    ReclaimCallback reclaim)
    : block_(std::move(block)),
      version_(std::move(version)),
      tracker_(std::move(tracker)),
      reclaim_(std::move(reclaim)) {}

ResidencyLease::~ResidencyLease() {
    reset();
}

ResidencyLease::ResidencyLease(ResidencyLease&& other) noexcept
    : block_(std::move(other.block_)),
      version_(std::move(other.version_)),
      tracker_(std::move(other.tracker_)),
      reclaim_(std::move(other.reclaim_)) {}

ResidencyLease& ResidencyLease::operator=(
    ResidencyLease&& other) noexcept {
    if (this != &other) {
        reset();
        block_ = std::move(other.block_);
        version_ = std::move(other.version_);
        tracker_ = std::move(other.tracker_);
        reclaim_ = std::move(other.reclaim_);
    }
    return *this;
}

void ResidencyLease::reset() noexcept {
    uint64_t blockId = block_ ? block_->id : 0;

    if (version_) {
        version_->readerCount.fetch_sub(
            1, std::memory_order_acq_rel);
        version_.reset();
    }
    if (tracker_) {
        tracker_->release();
        tracker_.reset();
    }
    block_.reset();

    // P1: trigger retired-version reclamation after lease release
    if (reclaim_ && blockId != 0) {
        reclaim_(blockId);
    }
}

void ResidencyLease::setReclaimCallback(ReclaimCallback cb) noexcept {
    reclaim_ = std::move(cb);
}

void* ResidencyLease::hostPtr() const noexcept {
    return version_ && version_->allocation
        ? version_->allocation->get().hostPtr
        : nullptr;
}

uint64_t ResidencyLease::deviceAddress() const noexcept {
    return version_ && version_->allocation
        ? version_->allocation->get().deviceAddress
        : 0;
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
        ? version_->allocation->get().size
        : 0;
}

// ============================================================================
// Backends
// ============================================================================

NVMeFileBackend::NVMeFileBackend(uint32_t id, uint64_t generation)
    : id_(id), generation_(generation) {}

AllocationHandle NVMeFileBackend::allocate(size_t bytes) {
    AllocationHandle h{};
    h.id = nextId_.fetch_add(1, std::memory_order_relaxed);
    h.tier = Tier::NVMe;
    h.backendGeneration = generation_;
    h.size = bytes;
    h.hostPtr = std::malloc(bytes);
    if (h.hostPtr)
        h.flags = CAP_FILE_BACKED | CAP_HOST_MEMORY;
    return h;
}

void NVMeFileBackend::release(const AllocationHandle& h) noexcept {
    std::free(h.hostPtr);
}

HostRAMBackend::HostRAMBackend(uint32_t id, uint64_t generation)
    : id_(id), generation_(generation) {}

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
    if (bytes != 0 && bytes <= std::numeric_limits<size_t>::max() - 63) {
        void* p = nullptr;
        if (posix_memalign(&p, 64, bytes) == 0)
            h.hostPtr = p;
    }
#endif

    if (h.hostPtr)
        h.flags = CAP_HOST_MEMORY | CAP_DMA;
    return h;
}

void HostRAMBackend::release(const AllocationHandle& h) noexcept {
#ifdef _WIN32
    _aligned_free(h.hostPtr);
#else
    std::free(h.hostPtr);
#endif
}

VulkanDeviceBackend::VulkanDeviceBackend(
    uint32_t id,
    uint64_t generation,
    void* user,
    AllocateFn allocateFn,
    ReleaseFn releaseFn)
    : id_(id),
      generation_(generation),
      user_(user),
      allocateFn_(allocateFn),
      releaseFn_(releaseFn) {}

AllocationHandle VulkanDeviceBackend::allocate(size_t bytes) {
    if (!allocateFn_)
        return {};

    AllocationHandle h = allocateFn_(user_, bytes);
    if (h.tier != Tier::VRAM)
        return {};

    // P1: strict size validation — do not silently normalize
    if (h.size != bytes)
        return {};

    if (h.backendGeneration != generation_)
        h.backendGeneration = generation_;
    if (h.id == 0)
        h.id = nextId_.fetch_add(1, std::memory_order_relaxed);
    return h;
}

void VulkanDeviceBackend::release(
    const AllocationHandle& handle) noexcept {
    if (releaseFn_)
        releaseFn_(user_, handle);
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
      leaseTracker_(std::make_shared<LeaseTracker>()),
      migrationTracker_(std::make_shared<MigrationTracker>()),
      blockSize_(blockSize) {
    if (!ledger_ || !nvmeBackend_ || !ramBackend_ ||
        !vramBackend_ || !transferEngine_ || blockSize_ == 0) {
        throw std::invalid_argument("RawRamXDFabric invalid dependencies");
    }
}

RawRamXDFabric::~RawRamXDFabric() {
    shutdown();
}

uint64_t RawRamXDFabric::allocate(
    size_t size,
    const char* name,
    AccessPattern pattern) {
    if (runtimeState_.load(std::memory_order_acquire) !=
        RuntimeState::RUNNING)
        return 0;

    if (size == 0)
        return 0;

    const uint64_t handleId =
        nextHandle_.fetch_add(1, std::memory_order_relaxed);

    auto handle = std::make_shared<Handle>();
    handle->id = handleId;
    handle->vaddr = handleId << 12;
    handle->size = size;
    handle->pattern = pattern;
    handle->name = name ? name : "unnamed";
    handle->blockSize = blockSize_;

    const size_t count =
        (size + blockSize_ - 1) / blockSize_;

    std::vector<std::shared_ptr<ResidencyBlock>> staged;
    staged.reserve(count);

    try {
        for (size_t i = 0; i < count; ++i) {
            const size_t offset = i * blockSize_;
            const size_t bytes =
                std::min(blockSize_, size - offset);

            CapacityReservation reservation(
                ledger_, Tier::NVMe, bytes);

            if (reservation.bytes() == 0)
                return 0;

            AllocationHandle ah =
                nvmeBackend_->allocate(bytes);

            if (!ah.hostPtr) {
                return 0;
            }

            auto physical =
                std::make_shared<PhysicalAllocation>(
                    nvmeBackend_,
                    std::move(ah),
                    ledger_);

            auto block =
                std::make_shared<ResidencyBlock>();

            block->id =
                nextBlockId_.fetch_add(1, std::memory_order_relaxed);
            block->tensorId = handleId;
            block->size = bytes;
            block->pattern = pattern;
            block->name = handle->name;
            block->state.store(
                ResidencyState::RESIDENT,
                std::memory_order_release);

            auto version =
                std::make_shared<ResidencyVersion>();

            version->blockId = block->id;
            version->generation = 1;
            version->tier = Tier::NVMe;
            version->backendId =
                nvmeBackend_->backendId();
            version->backendGeneration =
                nvmeBackend_->backendGeneration();
            version->allocation = std::move(physical);

            block->activeVersion = std::move(version);
            staged.push_back(std::move(block));

            reservation.commit();
        }
    } catch (...) {
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(blocksMutex_);
        for (const auto& block : staged)
            blocks_.emplace(block->id, block);
    }

    handle->blocks = std::move(staged);

    {
        std::lock_guard<std::mutex> lock(handlesMutex_);
        handles_.emplace(handleId, handle);
    }

    handle->active.store(true, std::memory_order_release);

    return handleId;
}

ResidencyLease RawRamXDFabric::acquire(
    uint64_t tensorId,
    uint32_t blockIndex,
    Tier targetTier) {
    if (runtimeState_.load(std::memory_order_acquire) !=
        RuntimeState::RUNNING)
        return {};

    auto block =
        resolveBlockForTensor(tensorId, blockIndex);

    if (!block)
        return {};

    if (!ensureBlockInTier(block->id, targetTier))
        return {};

    std::lock_guard<std::mutex> lock(block->blockMutex);

    return pinActiveVersionLocked(block, targetTier);
}

ResidencyLease RawRamXDFabric::pinActiveVersionLocked(
    const std::shared_ptr<ResidencyBlock>& block,
    Tier targetTier) {
    if (runtimeState_.load(std::memory_order_acquire) !=
        RuntimeState::RUNNING)
        return {};

    auto version = block->activeVersion;

    if (!version ||
        !version->allocation ||
        version->tier != targetTier ||
        block->state.load(std::memory_order_acquire) !=
            ResidencyState::RESIDENT)
        return {};

    version->readerCount.fetch_add(
        1, std::memory_order_acq_rel);

    leaseTracker_->acquire();

    // P1: bind reclaim callback so retired versions are cleaned up
    // when this lease is released
    auto reclaim = [this](uint64_t blockId) {
        onLeaseReleased(blockId);
    };

    return ResidencyLease(
        block,
        std::move(version),
        leaseTracker_,
        std::move(reclaim));
}

bool RawRamXDFabric::ensureBlockInTier(
    uint64_t blockId,
    Tier targetTier) {
    auto block = resolveBlock(blockId);
    if (!block)
        return false;

    for (;;) {
        uint64_t sourceGeneration = 0;
        uint64_t ticket = 0;

        {
            std::unique_lock<std::mutex> lock(
                block->blockMutex);

            if (runtimeState_.load(std::memory_order_acquire) !=
                RuntimeState::RUNNING)
                return false;

            auto active = block->activeVersion;

            if (active &&
                active->allocation &&
                active->tier == targetTier &&
                block->state.load(std::memory_order_acquire) ==
                    ResidencyState::RESIDENT) {
                return true;
            }

            if (block->state.load(std::memory_order_acquire) ==
                ResidencyState::MIGRATING) {
                const uint64_t waitingFor =
                    block->migrationTicket;

                block->migrationCv.wait(lock, [&] {
                    return block->state.load(
                               std::memory_order_acquire) !=
                               ResidencyState::MIGRATING ||
                           block->migrationTicket != waitingFor;
                });

                continue;
            }

            if (block->state.load(std::memory_order_acquire) ==
                ResidencyState::FAILED) {
                if (!block->activeVersion ||
                    !block->activeVersion->allocation)
                    return false;

                block->tryTransitionState(
                    ResidencyState::FAILED,
                    ResidencyState::RESIDENT);
            }

            active = block->activeVersion;
            if (!active || !active->allocation)
                return false;

            sourceGeneration = active->generation;
            ticket =
                nextMigrationTicket_.fetch_add(
                    1, std::memory_order_relaxed);

            block->migrationTarget = targetTier;
            block->migrationTicket = ticket;

            if (!block->tryTransitionState(
                    ResidencyState::RESIDENT,
                    ResidencyState::MIGRATING)) {
                // Another thread raced the transition.
                continue;
            }

            migrationsStarted_.fetch_add(
                1, std::memory_order_relaxed);
        }

        const bool success =
            performMigration(
                block,
                targetTier,
                sourceGeneration,
                ticket);

        {
            std::lock_guard<std::mutex> lock(
                block->blockMutex);

            if (success) {
                block->tryTransitionState(
                    ResidencyState::MIGRATING,
                    ResidencyState::RESIDENT);
            } else {
                if (block->activeVersion &&
                    block->activeVersion->allocation) {
                    block->tryTransitionState(
                        ResidencyState::MIGRATING,
                        ResidencyState::RESIDENT);
                } else {
                    block->tryTransitionState(
                        ResidencyState::MIGRATING,
                        ResidencyState::FAILED);
                }
            }
        }

        block->migrationCv.notify_all();

        if (success)
            return true;

        return false;
    }
}

bool RawRamXDFabric::migrate(
    uint64_t blockId,
    Tier targetTier) {
    if (runtimeState_.load(std::memory_order_acquire) !=
        RuntimeState::RUNNING)
        return false;

    return ensureBlockInTier(blockId, targetTier);
}

bool RawRamXDFabric::performMigration(
    const std::shared_ptr<ResidencyBlock>& block,
    Tier targetTier,
    uint64_t sourceGeneration,
    uint64_t ticket) {
    // P0: treat migrations as execution epochs
    migrationTracker_->acquire();
    struct MigrationGuard {
        std::shared_ptr<MigrationTracker> t;
        ~MigrationGuard() { if (t) t->release(); }
    } guard{migrationTracker_};

    if (runtimeState_.load(std::memory_order_acquire) !=
        RuntimeState::RUNNING)
        return false;

    auto targetBackend = backendFor(targetTier);
    if (!targetBackend)
        return false;

    const size_t bytes = block->size;

    if (!ledger_->tryReserve(targetTier, bytes))
        return false;

    CapacityReservation reservation(
        ledger_, targetTier, bytes);

    AllocationHandle dstHandle =
        targetBackend->allocate(bytes);

    // P1: strict backend size validation
    if (dstHandle.size != bytes ||
        (!dstHandle.hostPtr &&
         !dstHandle.nativeBuffer)) {
        return false;
    }

    auto dstPhysical =
        std::make_shared<PhysicalAllocation>(
            targetBackend,
            std::move(dstHandle),
            ledger_);

    std::shared_ptr<PhysicalAllocation> srcPhysical;
    uint32_t srcBackendId = 0;
    uint64_t srcBackendGeneration = 0;

    {
        std::lock_guard<std::mutex> lock(
            block->blockMutex);

        auto current = block->activeVersion;

        // P1: full identity + generation + ticket validation
        if (!current ||
            !current->allocation ||
            current->generation != sourceGeneration ||
            block->migrationTicket != ticket ||
            block->state.load(std::memory_order_acquire) !=
                ResidencyState::MIGRATING) {
            return false;
        }

        srcPhysical = current->allocation;
        srcBackendId = current->backendId;
        srcBackendGeneration = current->backendGeneration;
    }

    // P1: validate backend identity matches the physical allocation
    if (!srcPhysical ||
        srcPhysical->get().backendId != srcBackendId ||
        srcPhysical->get().backendGeneration != srcBackendGeneration) {
        migrationsFailed_.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }

    if (!transferEngine_->canTransfer(
            srcPhysical->get().tier,
            targetTier)) {
        migrationsFailed_.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }

    CopyToken token{};

    if (!transferEngine_->transfer(
            *srcPhysical,
            *dstPhysical,
            bytes,
            token)) {
        migrationsFailed_.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }

    if (!transferEngine_->wait(token)) {
        migrationsFailed_.fetch_add(
            1, std::memory_order_relaxed);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(
            block->blockMutex);

        auto current = block->activeVersion;

        // P0 + P1: full validation before publication
        if (!current ||
            !current->allocation ||
            current->generation != sourceGeneration ||
            current->backendId != srcBackendId ||
            current->backendGeneration != srcBackendGeneration ||
            block->migrationTicket != ticket ||
            block->state.load(std::memory_order_acquire) !=
                ResidencyState::MIGRATING) {
            migrationsFailed_.fetch_add(
                1, std::memory_order_relaxed);
            return false;
        }

        auto newVersion =
            std::make_shared<ResidencyVersion>();

        newVersion->blockId = block->id;
        newVersion->generation =
            current->generation + 1;
        newVersion->tier = targetTier;
        newVersion->backendId =
            targetBackend->backendId();
        newVersion->backendGeneration =
            targetBackend->backendGeneration();
        newVersion->allocation =
            std::move(dstPhysical);

        block->retiredVersions.push_back(
            std::move(block->activeVersion));

        block->activeVersion =
            std::move(newVersion);

        reclaimRetiredLocked(*block);
    }

    reservation.commit();

    migrationsCompleted_.fetch_add(
        1, std::memory_order_relaxed);

    return true;
}

void RawRamXDFabric::reclaimRetiredLocked(
    ResidencyBlock& block) {
    block.retiredVersions.erase(
        std::remove_if(
            block.retiredVersions.begin(),
            block.retiredVersions.end(),
            [](const std::shared_ptr<ResidencyVersion>& version) {
                return version &&
                       version->readerCount.load(
                           std::memory_order_acquire) == 0;
            }),
        block.retiredVersions.end());
}

void RawRamXDFabric::onLeaseReleased(uint64_t blockId) {
    auto block = resolveBlock(blockId);
    if (!block)
        return;

    std::lock_guard<std::mutex> lock(block->blockMutex);
    reclaimRetiredLocked(*block);
}

std::shared_ptr<ResidencyBlock>
RawRamXDFabric::resolveBlock(uint64_t blockId) const {
    std::lock_guard<std::mutex> lock(blocksMutex_);
    auto it = blocks_.find(blockId);
    return it == blocks_.end() ? nullptr : it->second;
}

std::shared_ptr<ResidencyBlock>
RawRamXDFabric::resolveBlockForTensor(
    uint64_t tensorId,
    uint32_t blockIndex) const {
    std::lock_guard<std::mutex> lock(handlesMutex_);

    auto it = handles_.find(tensorId);
    if (it == handles_.end())
        return nullptr;

    const auto& handle = it->second;
    if (!handle->active.load(std::memory_order_acquire) ||
        blockIndex >= handle->blocks.size())
        return nullptr;

    return handle->blocks[blockIndex];
}

std::shared_ptr<TierBackend>
RawRamXDFabric::backendFor(Tier tier) const {
    switch (tier) {
    case Tier::NVMe: return nvmeBackend_;
    case Tier::RAM:  return ramBackend_;
    case Tier::VRAM: return vramBackend_;
    }
    return nullptr;
}

void RawRamXDFabric::shutdown() {
    RuntimeState expected = RuntimeState::RUNNING;

    if (!runtimeState_.compare_exchange_strong(
            expected,
            RuntimeState::DRAINING,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        if (expected == RuntimeState::STOPPED)
            return;

        leaseTracker_->drain();
        migrationTracker_->drain();
        return;
    }

    {
        std::lock_guard<std::mutex> lock(handlesMutex_);
        for (auto& [id, handle] : handles_)
            handle->active.store(false, std::memory_order_release);
    }

    // P0: drain both execution leases and in-flight migrations
    leaseTracker_->drain();
    migrationTracker_->drain();

    {
        std::lock_guard<std::mutex> lock(blocksMutex_);

        for (auto& [id, block] : blocks_) {
            std::lock_guard<std::mutex> blockLock(
                block->blockMutex);

            block->state.store(
                ResidencyState::UNMAPPED,
                std::memory_order_release);
            block->activeVersion.reset();
            block->retiredVersions.clear();
        }

        blocks_.clear();
    }

    {
        std::lock_guard<std::mutex> lock(handlesMutex_);
        handles_.clear();
    }

    runtimeState_.store(
        RuntimeState::STOPPED,
        std::memory_order_release);
}

RuntimeState RawRamXDFabric::runtimeState() const noexcept {
    return runtimeState_.load(std::memory_order_acquire);
}

RawRamXDFabric::Stats RawRamXDFabric::stats() const {
    Stats s;
    s.nvmeUsed = ledger_->used(Tier::NVMe);
    s.ramUsed = ledger_->used(Tier::RAM);
    s.vramUsed = ledger_->used(Tier::VRAM);
    s.migrationsStarted =
        migrationsStarted_.load(std::memory_order_acquire);
    s.migrationsCompleted =
        migrationsCompleted_.load(std::memory_order_acquire);
    s.migrationsFailed =
        migrationsFailed_.load(std::memory_order_acquire);
    return s;
}

} // namespace rawramxd
