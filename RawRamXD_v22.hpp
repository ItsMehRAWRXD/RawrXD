#pragma once

#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <limits>

namespace rawramxd {

enum class Tier : uint8_t { NVMe = 0, RAM = 1, VRAM = 2 };
enum class ResidencyState : uint8_t { UNMAPPED = 0, RESIDENT = 1, MIGRATING = 2, FAILED = 3 };
enum class AccessPattern : uint8_t { READ = 0, WRITE = 1, READ_WRITE = 2, PREFETCH = 3, DEQUANT = 4 };
enum class RuntimeState : uint8_t { RUNNING = 0, DRAINING = 1, STOPPED = 2 };
enum class TransferState : uint8_t { PENDING = 0, SUBMITTED = 1, COMPLETED = 2, FAILED = 3 };

constexpr uint32_t CAP_HOST_MEMORY   = 1u << 0;
constexpr uint32_t CAP_DEVICE_MEMORY = 1u << 1;
constexpr uint32_t CAP_DMA           = 1u << 2;
constexpr uint32_t CAP_FILE_BACKED   = 1u << 3;
constexpr uint32_t CAP_PEER_COPY     = 1u << 4;
constexpr uint32_t CAP_ASYNC_COPY    = 1u << 5;
constexpr uint32_t CAP_MAPPED        = 1u << 6;

struct AllocationHandle {
    uint64_t id{0};
    Tier     tier{Tier::NVMe};
    uint64_t backendGeneration{0};
    size_t   size{0};
    void*    hostPtr{nullptr};
    uint64_t deviceOffset{0};
    uint64_t nativeHandle{0};
    uint64_t nativeBuffer{0};
    uint64_t deviceAddress{0};
    uint32_t flags{0};
};

class TierBackend;
class CapacityLedger;

class CapacityReservation {
public:
    CapacityReservation() = default;
    CapacityReservation(std::shared_ptr<CapacityLedger> ledger, Tier tier, size_t bytes);
    ~CapacityReservation();

    CapacityReservation(const CapacityReservation&) = delete;
    CapacityReservation& operator=(const CapacityReservation&) = delete;
    CapacityReservation(CapacityReservation&& other) noexcept;
    CapacityReservation& operator=(CapacityReservation&& other) noexcept;

    void commit() noexcept;
    size_t bytes() const noexcept { return bytes_; }

private:
    std::shared_ptr<CapacityLedger> ledger_;
    Tier     tier_{Tier::NVMe};
    size_t   bytes_{0};
    bool     committed_{true};
};

class CapacityLedger {
public:
    explicit CapacityLedger(const std::array<size_t, 3>& capacities);

    bool tryReserve(Tier tier, size_t bytes) noexcept;
    void release(Tier tier, size_t bytes);
    size_t used(Tier tier) const noexcept;
    size_t capacity(Tier tier) const noexcept;

private:
    std::array<size_t, 3> capacities_{};
    std::array<std::atomic<size_t>, 3> used_{};
};

class TierBackend {
public:
    virtual ~TierBackend() = default;
    virtual AllocationHandle allocate(size_t bytes) = 0;
    virtual void release(const AllocationHandle& handle) noexcept = 0;
    virtual uint32_t backendId() const noexcept = 0;
    virtual uint64_t backendGeneration() const noexcept = 0;
    virtual Tier tier() const noexcept = 0;
};

class PhysicalAllocation {
public:
    PhysicalAllocation(std::shared_ptr<TierBackend> backend,
                       AllocationHandle handle,
                       std::shared_ptr<CapacityLedger> ledger) noexcept;
    ~PhysicalAllocation() noexcept;

    PhysicalAllocation(const PhysicalAllocation&) = delete;
    PhysicalAllocation& operator=(const PhysicalAllocation&) = delete;
    PhysicalAllocation(PhysicalAllocation&&) = delete;
    PhysicalAllocation& operator=(PhysicalAllocation&&) = delete;

    const AllocationHandle& get() const noexcept { return handle_; }
    std::shared_ptr<TierBackend> backend() const noexcept { return backend_; }

private:
    std::shared_ptr<TierBackend> backend_;
    AllocationHandle handle_{};
    std::shared_ptr<CapacityLedger> ledger_;
};

struct ResidencyVersion {
    uint64_t blockId{0};
    uint64_t generation{0};
    Tier     tier{Tier::NVMe};
    uint32_t backendId{0};
    uint64_t backendGeneration{0};
    std::shared_ptr<PhysicalAllocation> allocation;
    std::atomic<uint32_t> readerCount{0};
};

struct ResidencyBlock {
    uint64_t id{0};
    uint64_t tensorId{0};
    size_t   size{0};
    AccessPattern pattern{AccessPattern::READ};
    std::string name;

    mutable std::mutex blockMutex;
    std::condition_variable migrationCv;

    std::atomic<ResidencyState> state{ResidencyState::RESIDENT};
    Tier     migrationTarget{Tier::NVMe};
    uint64_t migrationTicket{0};

    std::shared_ptr<ResidencyVersion> activeVersion;
    std::vector<std::shared_ptr<ResidencyVersion>> retiredVersions;

    bool tryTransitionState(ResidencyState expected, ResidencyState desired) noexcept;
};

struct CopyToken {
    uint64_t       id{0};
    uint64_t       timelineValue{0};
    TransferState  state{TransferState::PENDING};
};

class TransferEngine {
public:
    virtual ~TransferEngine() = default;

    virtual bool canTransfer(Tier srcTier, Tier dstTier) const noexcept = 0;

    virtual bool transfer(const PhysicalAllocation& src,
                          PhysicalAllocation& dst,
                          size_t bytes,
                          CopyToken& token) = 0;

    virtual bool wait(CopyToken token) = 0;
    virtual bool poll(CopyToken token) noexcept = 0;
};

class RawRamXDTransferEngine final : public TransferEngine {
public:
    bool canTransfer(Tier srcTier, Tier dstTier) const noexcept override;
    bool transfer(const PhysicalAllocation& src,
                  PhysicalAllocation& dst,
                  size_t bytes,
                  CopyToken& token) override;
    bool wait(CopyToken token) override;
    bool poll(CopyToken token) noexcept override;

private:
    std::atomic<uint64_t> nextToken_{1};
    std::atomic<uint64_t> nextTimeline_{1};

    bool transferHostToHost(const PhysicalAllocation& src,
                            PhysicalAllocation& dst,
                            size_t bytes);
    bool transferHostToDevice(const PhysicalAllocation& src,
                              PhysicalAllocation& dst,
                              size_t bytes,
                              CopyToken& token);
    bool transferDeviceToHost(const PhysicalAllocation& src,
                              PhysicalAllocation& dst,
                              size_t bytes,
                              CopyToken& token);
    bool transferDeviceToDevice(const PhysicalAllocation& src,
                                PhysicalAllocation& dst,
                                size_t bytes,
                                CopyToken& token);
};

class LeaseTracker {
public:
    void acquire();
    void release() noexcept;
    void drain();

private:
    std::atomic<uint64_t> active_{0};
    std::mutex mutex_;
    std::condition_variable cv_;
};

class MigrationTracker {
public:
    void acquire();
    void release() noexcept;
    void drain();

private:
    std::atomic<uint64_t> active_{0};
    std::mutex mutex_;
    std::condition_variable cv_;
};

using ReclaimCallback = std::function<void(uint64_t blockId)>;

class ResidencyLease {
public:
    ResidencyLease() = default;
    ResidencyLease(std::shared_ptr<ResidencyBlock> block,
                   std::shared_ptr<ResidencyVersion> version,
                   std::shared_ptr<LeaseTracker> tracker,
                   ReclaimCallback reclaim = nullptr);

    ~ResidencyLease();

    ResidencyLease(const ResidencyLease&) = delete;
    ResidencyLease& operator=(const ResidencyLease&) = delete;
    ResidencyLease(ResidencyLease&& other) noexcept;
    ResidencyLease& operator=(ResidencyLease&& other) noexcept;

    bool valid() const noexcept { return version_ != nullptr; }
    void* hostPtr() const noexcept;
    uint64_t deviceAddress() const noexcept;
    Tier tier() const noexcept;
    uint64_t generation() const noexcept;
    uint64_t blockId() const noexcept;
    size_t size() const noexcept;

    void setReclaimCallback(ReclaimCallback cb) noexcept;

private:
    void reset() noexcept;

    std::shared_ptr<ResidencyBlock> block_;
    std::shared_ptr<ResidencyVersion> version_;
    std::shared_ptr<LeaseTracker> tracker_;
    ReclaimCallback reclaim_;
};

class NVMeFileBackend final : public TierBackend {
public:
    NVMeFileBackend(uint32_t id, uint64_t generation);
    AllocationHandle allocate(size_t bytes) override;
    void release(const AllocationHandle& handle) noexcept override;
    uint32_t backendId() const noexcept override { return id_; }
    uint64_t backendGeneration() const noexcept override { return generation_; }
    Tier tier() const noexcept override { return Tier::NVMe; }

private:
    uint32_t id_;
    uint64_t generation_;
    std::atomic<uint64_t> nextId_{1};
};

class HostRAMBackend final : public TierBackend {
public:
    HostRAMBackend(uint32_t id, uint64_t generation);
    AllocationHandle allocate(size_t bytes) override;
    void release(const AllocationHandle& handle) noexcept override;
    uint32_t backendId() const noexcept override { return id_; }
    uint64_t backendGeneration() const noexcept override { return generation_; }
    Tier tier() const noexcept override { return Tier::RAM; }

private:
    uint32_t id_;
    uint64_t generation_;
    std::atomic<uint64_t> nextId_{1};
};

class VulkanDeviceBackend final : public TierBackend {
public:
    using AllocateFn = AllocationHandle(*)(void* user, size_t bytes);
    using ReleaseFn  = void(*)(void* user, const AllocationHandle& handle) noexcept;

    VulkanDeviceBackend(uint32_t id,
                        uint64_t generation,
                        void* user,
                        AllocateFn allocateFn,
                        ReleaseFn releaseFn);

    AllocationHandle allocate(size_t bytes) override;
    void release(const AllocationHandle& handle) noexcept override;
    uint32_t backendId() const noexcept override { return id_; }
    uint64_t backendGeneration() const noexcept override { return generation_; }
    Tier tier() const noexcept override { return Tier::VRAM; }

private:
    uint32_t id_;
    uint64_t generation_;
    void* user_;
    AllocateFn allocateFn_;
    ReleaseFn  releaseFn_;
    std::atomic<uint64_t> nextId_{1};
};

class RawRamXDFabric {
public:
    struct Stats {
        size_t nvmeUsed{0};
        size_t ramUsed{0};
        size_t vramUsed{0};
        uint64_t migrationsStarted{0};
        uint64_t migrationsCompleted{0};
        uint64_t migrationsFailed{0};
    };

    RawRamXDFabric(std::shared_ptr<CapacityLedger> ledger,
                   std::shared_ptr<TierBackend> nvme,
                   std::shared_ptr<TierBackend> ram,
                   std::shared_ptr<TierBackend> vram,
                   std::shared_ptr<TransferEngine> transfer,
                   size_t blockSize = 4096);

    ~RawRamXDFabric();

    uint64_t allocate(size_t size, const char* name, AccessPattern pattern);
    ResidencyLease acquire(uint64_t tensorId, uint32_t blockIndex, Tier targetTier);

    bool ensureBlockInTier(uint64_t blockId, Tier targetTier);
    bool migrate(uint64_t blockId, Tier targetTier);

    void shutdown();
    RuntimeState runtimeState() const noexcept;
    Stats stats() const;

private:
    struct Handle {
        uint64_t id{0};
        uint64_t vaddr{0};
        size_t   size{0};
        AccessPattern pattern{AccessPattern::READ};
        std::string name;
        size_t blockSize{4096};
        std::vector<std::shared_ptr<ResidencyBlock>> blocks;
        std::atomic<bool> active{false};
    };

    std::shared_ptr<ResidencyBlock> resolveBlock(uint64_t blockId) const;
    std::shared_ptr<ResidencyBlock> resolveBlockForTensor(uint64_t tensorId,
                                                          uint32_t blockIndex) const;
    std::shared_ptr<TierBackend> backendFor(Tier tier) const;

    ResidencyLease pinActiveVersionLocked(
        const std::shared_ptr<ResidencyBlock>& block,
        Tier targetTier);

    bool performMigration(const std::shared_ptr<ResidencyBlock>& block,
                          Tier targetTier,
                          uint64_t sourceGeneration,
                          uint64_t ticket);

    void reclaimRetiredLocked(ResidencyBlock& block);
    void onLeaseReleased(uint64_t blockId);

    std::shared_ptr<CapacityLedger> ledger_;
    std::shared_ptr<TierBackend> nvmeBackend_;
    std::shared_ptr<TierBackend> ramBackend_;
    std::shared_ptr<TierBackend> vramBackend_;
    std::shared_ptr<TransferEngine> transferEngine_;
    std::shared_ptr<LeaseTracker>     leaseTracker_;
    std::shared_ptr<MigrationTracker> migrationTracker_;

    size_t blockSize_;

    std::atomic<RuntimeState> runtimeState_{RuntimeState::RUNNING};
    std::atomic<uint64_t> nextHandle_{1};
    std::atomic<uint64_t> nextBlockId_{1};
    std::atomic<uint64_t> nextMigrationTicket_{1};

    std::atomic<uint64_t> migrationsStarted_{0};
    std::atomic<uint64_t> migrationsCompleted_{0};
    std::atomic<uint64_t> migrationsFailed_{0};

    mutable std::mutex handlesMutex_;
    std::unordered_map<uint64_t, std::shared_ptr<Handle>> handles_;

    mutable std::mutex blocksMutex_;
    std::unordered_map<uint64_t, std::shared_ptr<ResidencyBlock>> blocks_;
};

} // namespace rawramxd
