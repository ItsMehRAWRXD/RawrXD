// RawRamXD.hpp — minimal multi-tier memory fabric for K2 residency bridge
// NOT a generic library: only the paths K2 MLA needs (NVMe->RAM->VRAM).
#pragma once
#include <array>
#include <atomic>
#include <cstdint>
#include <cstddef>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <string>
#include <condition_variable>

namespace rawramxd {

enum class Tier : uint8_t { NVMe = 0, RAM = 1, VRAM = 2 };

struct AllocationHandle {
    uint64_t id = 0;
    Tier tier = Tier::NVMe;
    uint64_t backendGeneration = 0;
    size_t size = 0;
    void* hostPtr = nullptr;
    void* nativeBuffer = nullptr;   // VkBuffer or similar
    uint64_t deviceAddress = 0;
    uint64_t offset = 0;
    uint32_t flags = 0;
};

struct CopyToken {
    uint64_t id = 0;
    bool completed = false;
};

// ---------------------------------------------------------------------------
// CapacityLedger — lock-free atomic accounting
// ---------------------------------------------------------------------------
class CapacityLedger {
public:
    explicit CapacityLedger(const std::array<size_t, 3>& capacities);
    bool tryReserve(Tier tier, size_t bytes) noexcept;
    void release(Tier tier, size_t bytes);
    size_t used(Tier tier) const noexcept;
    size_t capacity(Tier tier) const noexcept;
private:
    std::array<size_t, 3> capacities_;
    std::array<std::atomic<size_t>, 3> used_;
};

// ---------------------------------------------------------------------------
// CapacityReservation — RAII guard for ledger reservations
// ---------------------------------------------------------------------------
class CapacityReservation {
public:
    CapacityReservation(std::shared_ptr<CapacityLedger> ledger, Tier tier, size_t bytes);
    ~CapacityReservation();
    CapacityReservation(CapacityReservation&& other) noexcept;
    CapacityReservation& operator=(CapacityReservation&& other) noexcept;
    void commit() noexcept;
private:
    std::shared_ptr<CapacityLedger> ledger_;
    Tier tier_;
    size_t bytes_;
    bool committed_;
};

// ---------------------------------------------------------------------------
// TierBackend — pluggable backend (NVMe file, RAM aligned, Vulkan VRAM)
// ---------------------------------------------------------------------------
class TierBackend {
public:
    virtual ~TierBackend() = default;
    virtual AllocationHandle allocate(size_t bytes) = 0;
    virtual void release(const AllocationHandle& h) noexcept = 0;
    uint32_t backendId() const noexcept { return id_; }
    uint64_t backendGeneration() const noexcept { return generation_; }
protected:
    uint32_t id_ = 0;
    uint64_t generation_ = 0;
    std::atomic<uint64_t> nextId_{1};
};

// ---------------------------------------------------------------------------
// TransferEngine — pluggable copy engine
// ---------------------------------------------------------------------------
class TransferEngine {
public:
    virtual ~TransferEngine() = default;
    virtual bool canTransfer(Tier src, Tier dst) const noexcept = 0;
    virtual bool transfer(const AllocationHandle& src, const AllocationHandle& dst,
                          size_t bytes, CopyToken& token) = 0;
    virtual bool wait(CopyToken token) = 0;
};

// ---------------------------------------------------------------------------
// PhysicalAllocation — owns backend + ledger reservation
// ---------------------------------------------------------------------------
class PhysicalAllocation {
public:
    PhysicalAllocation(std::shared_ptr<TierBackend> backend,
                       AllocationHandle handle,
                       std::shared_ptr<CapacityLedger> ledger) noexcept;
    ~PhysicalAllocation() noexcept;
    const AllocationHandle& get() const noexcept { return handle_; }
private:
    std::shared_ptr<TierBackend> backend_;
    AllocationHandle handle_;
    std::shared_ptr<CapacityLedger> ledger_;
};

// ---------------------------------------------------------------------------
// ResidencyVersion — immutable generation after publication
// ---------------------------------------------------------------------------
struct ResidencyVersion {
    uint64_t blockId = 0;
    uint64_t generation = 0;
    Tier tier = Tier::NVMe;
    uint32_t backendId = 0;
    uint64_t backendGeneration = 0;
    std::shared_ptr<PhysicalAllocation> allocation;
    std::atomic<uint32_t> readerCount{0};
};

// ---------------------------------------------------------------------------
// ResidencyBlock — holds active + retired versions
// ---------------------------------------------------------------------------
struct ResidencyBlock {
    uint64_t id = 0;
    uint64_t tensorId = 0;
    uint32_t size = 0;
    std::string name;
    std::shared_ptr<ResidencyVersion> activeVersion;
    std::vector<std::shared_ptr<ResidencyVersion>> retiredVersions;
    mutable std::mutex blockMutex;
    uint64_t migrationTicket = 0;
    Tier migrationTarget = Tier::NVMe;
    std::condition_variable migrationCv;
    enum class State : uint8_t { RESIDENT, MIGRATING, FAILED, UNMAPPED };
    std::atomic<State> state{State::RESIDENT};
};

// ---------------------------------------------------------------------------
// ResidencyLease — RAII pin of a version
// ---------------------------------------------------------------------------
class ResidencyLease {
public:
    ResidencyLease() = default;
    ResidencyLease(std::shared_ptr<ResidencyBlock> block,
                   std::shared_ptr<ResidencyVersion> version);
    ~ResidencyLease();
    ResidencyLease(ResidencyLease&& other) noexcept;
    ResidencyLease& operator=(ResidencyLease&& other) noexcept;
    explicit operator bool() const noexcept { return version_ != nullptr; }
    void* hostPtr() const noexcept;
    uint64_t deviceAddress() const noexcept;
    Tier tier() const noexcept;
    uint64_t generation() const noexcept;
    uint64_t blockId() const noexcept;
    size_t size() const noexcept;
private:
    void reset() noexcept;
    std::shared_ptr<ResidencyBlock> block_;
    std::shared_ptr<ResidencyVersion> version_;
};

// ---------------------------------------------------------------------------
// RawRamXDFabric — minimal fabric for K2 residency
// ---------------------------------------------------------------------------
class RawRamXDFabric {
public:
    RawRamXDFabric(std::shared_ptr<CapacityLedger> ledger,
                   std::shared_ptr<TierBackend> nvme,
                   std::shared_ptr<TierBackend> ram,
                   std::shared_ptr<TierBackend> vram,
                   std::shared_ptr<TransferEngine> transfer,
                   size_t blockSize);
    ~RawRamXDFabric();

    uint64_t allocate(size_t size, const char* name);
    ResidencyLease acquire(uint64_t tensorId, uint32_t blockIndex, Tier targetTier);
    bool migrate(uint64_t blockId, Tier targetTier);

    struct Stats {
        size_t nvmeUsed = 0, ramUsed = 0, vramUsed = 0;
        uint64_t migrationsStarted = 0, migrationsCompleted = 0, migrationsFailed = 0;
    };
    Stats stats() const;

private:
    std::shared_ptr<ResidencyBlock> resolveBlockForTensor(uint64_t tensorId, uint32_t blockIndex) const;
    std::shared_ptr<ResidencyBlock> resolveBlock(uint64_t blockId) const;
    std::shared_ptr<TierBackend> backendFor(Tier tier) const;
    bool ensureBlockInTier(uint64_t blockId, Tier targetTier);
    bool performMigration(const std::shared_ptr<ResidencyBlock>& block,
                          Tier targetTier, uint64_t sourceGeneration, uint64_t ticket);
    ResidencyLease pinActiveVersionLocked(const std::shared_ptr<ResidencyBlock>& block, Tier targetTier);
    void reclaimRetiredLocked(ResidencyBlock& block);

    std::shared_ptr<CapacityLedger> ledger_;
    std::shared_ptr<TierBackend> nvmeBackend_;
    std::shared_ptr<TierBackend> ramBackend_;
    std::shared_ptr<TierBackend> vramBackend_;
    std::shared_ptr<TransferEngine> transferEngine_;
    size_t blockSize_;

    mutable std::mutex blocksMutex_;
    std::unordered_map<uint64_t, std::shared_ptr<ResidencyBlock>> blocks_;

    mutable std::mutex handlesMutex_;
    struct Handle {
        uint64_t id = 0;
        size_t size = 0;
        std::vector<std::shared_ptr<ResidencyBlock>> blocks;
        std::atomic<bool> active{false};
    };
    std::unordered_map<uint64_t, std::shared_ptr<Handle>> handles_;

    std::atomic<uint64_t> nextHandle_{1};
    std::atomic<uint64_t> nextBlockId_{1};
    std::atomic<uint64_t> nextMigrationTicket_{1};
    std::atomic<uint64_t> migrationsStarted_{0};
    std::atomic<uint64_t> migrationsCompleted_{0};
    std::atomic<uint64_t> migrationsFailed_{0};

    enum class RuntimeState : uint8_t { RUNNING, DRAINING, STOPPED };
    std::atomic<RuntimeState> runtimeState_{RuntimeState::RUNNING};
};

// ---------------------------------------------------------------------------
// Concrete backends
// ---------------------------------------------------------------------------
class NVMeFileBackend : public TierBackend {
public:
    explicit NVMeFileBackend(uint32_t id, uint64_t generation);
    AllocationHandle allocate(size_t bytes) override;
    void release(const AllocationHandle& h) noexcept override;
};

class HostRAMBackend : public TierBackend {
public:
    explicit HostRAMBackend(uint32_t id, uint64_t generation);
    AllocationHandle allocate(size_t bytes) override;
    void release(const AllocationHandle& h) noexcept override;
};

using AllocateFn = AllocationHandle(*)(void* user, size_t bytes);
using ReleaseFn = void(*)(void* user, const AllocationHandle& h);

class VulkanDeviceBackend : public TierBackend {
public:
    VulkanDeviceBackend(uint32_t id, uint64_t generation,
                        void* user, AllocateFn allocFn, ReleaseFn relFn);
    AllocationHandle allocate(size_t bytes) override;
    void release(const AllocationHandle& h) noexcept override;
private:
    void* user_;
    AllocateFn allocFn_;
    ReleaseFn relFn_;
};

// ---------------------------------------------------------------------------
// Multi-tier transfer engine (NVMe<->RAM, RAM<->VRAM)
// ---------------------------------------------------------------------------
class MultiTierTransferEngine : public TransferEngine {
public:
    using TransferSubmitFn = bool(*)(void* ctx,
                                      const AllocationHandle& src,
                                      const AllocationHandle& dst,
                                      size_t bytes, CopyToken& token);
    using WaitFenceFn = bool(*)(void* ctx, uint64_t tokenId);

    MultiTierTransferEngine(void* vulkanContext,
                            TransferSubmitFn submitFn,
                            WaitFenceFn waitFn);
    bool canTransfer(Tier src, Tier dst) const noexcept override;
    bool transfer(const AllocationHandle& src, const AllocationHandle& dst,
                  size_t bytes, CopyToken& token) override;
    bool wait(CopyToken token) override;
private:
    void* vulkanContext_;
    TransferSubmitFn submitFn_;
    WaitFenceFn waitFn_;
    std::atomic<uint64_t> nextToken_{1};
};

} // namespace rawramxd
