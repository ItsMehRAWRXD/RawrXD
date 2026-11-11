//=============================================================================
// RawrXD Paged KV Cache - Sovereign Memory Integration
// Implementation
//=============================================================================

#include "PagedKVCache_Sovereign.hpp"
#include <cstring>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace KVCache {

//=============================================================================
// SovereignKVBlock Implementation
//=============================================================================
SovereignKVBlock::SovereignKVBlock() = default;

SovereignKVBlock::~SovereignKVBlock() {
    Shutdown();
}

SovereignKVBlock::SovereignKVBlock(SovereignKVBlock&& other) noexcept {
    kHandle_ = std::move(other.kHandle_);
    vHandle_ = std::move(other.vHandle_);
    kData_ = other.kData_;
    vData_ = other.vData_;
    tokenCount_ = other.tokenCount_;
    numaNode_ = other.numaNode_;
    kSize_ = other.kSize_;
    vSize_ = other.vSize_;
    other.Reset();
}

SovereignKVBlock& SovereignKVBlock::operator=(SovereignKVBlock&& other) noexcept {
    if (this != &other) {
        Shutdown();
        kHandle_ = std::move(other.kHandle_);
        vHandle_ = std::move(other.vHandle_);
        kData_ = other.kData_;
        vData_ = other.vData_;
        tokenCount_ = other.tokenCount_;
        numaNode_ = other.numaNode_;
        kSize_ = other.kSize_;
        vSize_ = other.vSize_;
        other.Reset();
    }
    return *this;
}

bool SovereignKVBlock::Initialize(const SovereignPagedKVConfig& config, 
                                   uint32_t numaNode,
                                   MemoryTier tier) {
    if (kHandle_.IsValid()) {
        return false;  // Already initialized
    }
    
    numaNode_ = numaNode;
    
    // Calculate sizes
    size_t tokensPerBlock = config.GetTokensPerBlock();
    kSize_ = tokensPerBlock * config.numHeads * config.headDim * sizeof(float);
    vSize_ = kSize_;  // V same size as K
    
    // Allocate K and V separately for better cache locality
    AllocFlags flags = AllocFlags::NONE;
    if (config.prefault) {
        flags = flags | AllocFlags::PREFETCH;
    }
    
    auto& allocator = GetGlobalAllocator();
    
    kHandle_ = allocator.Allocate(kSize_, tier, numaNode, flags);
    if (!kHandle_.IsValid()) {
        return false;
    }
    
    vHandle_ = allocator.Allocate(vSize_, tier, numaNode, flags);
    if (!vHandle_.IsValid()) {
        kHandle_ = MemoryResidencyHandle();  // Free K
        return false;
    }
    
    kData_ = static_cast<float*>(kHandle_.GetPtr());
    vData_ = static_cast<float*>(vHandle_.GetPtr());
    
    // Lock pages if requested
    if (config.lockPages) {
        Lock();
    }
    
    return true;
}

void SovereignKVBlock::Shutdown() {
    if (kHandle_.IsValid()) {
        Unlock();
    }
    kHandle_ = MemoryResidencyHandle();
    vHandle_ = MemoryResidencyHandle();
    Reset();
}

void SovereignKVBlock::Reset() {
    kData_ = nullptr;
    vData_ = nullptr;
    tokenCount_ = 0;
    numaNode_ = 0;
    kSize_ = 0;
    vSize_ = 0;
}

float* SovereignKVBlock::GetKToken(uint32_t tokenInBlock) {
    if (!kData_ || tokenInBlock >= tokenCount_) return nullptr;
    return kData_ + tokenInBlock * tokenCount_;  // Simplified - actual stride depends on layout
}

float* SovereignKVBlock::GetVToken(uint32_t tokenInBlock) {
    if (!vData_ || tokenInBlock >= tokenCount_) return nullptr;
    return vData_ + tokenInBlock * tokenCount_;
}

bool SovereignKVBlock::Lock() {
    bool kLocked = kHandle_.Lock();
    bool vLocked = vHandle_.Lock();
    return kLocked && vLocked;
}

void SovereignKVBlock::Unlock() {
    kHandle_.Unlock();
    vHandle_.Unlock();
}

//=============================================================================
// LockFreeBlockIndex Implementation
//=============================================================================
LockFreeBlockIndex::LockFreeBlockIndex() = default;

LockFreeBlockIndex::~LockFreeBlockIndex() {
    Shutdown();
}

bool LockFreeBlockIndex::Initialize(uint32_t numBlocks) {
    if (!entries_.empty()) return false;
    
    numBlocks_ = numBlocks;
    entries_.resize(numBlocks);
    
    // Initialize all entries as free
    for (uint32_t i = 0; i < numBlocks; i++) {
        entries_[i].blockId = i;
        entries_[i].nextFree.store(i + 1, std::memory_order_relaxed);
        entries_[i].inUse.store(false, std::memory_order_relaxed);
    }
    
    // Last entry points to invalid
    entries_[numBlocks - 1].nextFree.store(UINT32_MAX, std::memory_order_relaxed);
    
    // Set free list head
    freeHead_.store(0, std::memory_order_relaxed);
    freeCount_.store(numBlocks, std::memory_order_relaxed);
    usedCount_.store(0, std::memory_order_relaxed);
    
    return true;
}

void LockFreeBlockIndex::Shutdown() {
    entries_.clear();
    freeHead_.store(UINT32_MAX, std::memory_order_relaxed);
    freeCount_.store(0, std::memory_order_relaxed);
    usedCount_.store(0, std::memory_order_relaxed);
    numBlocks_ = 0;
}

uint32_t LockFreeBlockIndex::AllocateBlock() {
    uint32_t blockId = UINT32_MAX;
    
    // Pop from free list
    uint32_t expected = freeHead_.load(std::memory_order_relaxed);
    while (expected != UINT32_MAX) {
        uint32_t next = entries_[expected].nextFree.load(std::memory_order_relaxed);
        if (freeHead_.compare_exchange_weak(expected, next,
                                            std::memory_order_acquire,
                                            std::memory_order_relaxed)) {
            blockId = expected;
            break;
        }
    }
    
    if (blockId != UINT32_MAX) {
        entries_[blockId].inUse.store(true, std::memory_order_release);
        freeCount_.fetch_sub(1, std::memory_order_relaxed);
        usedCount_.fetch_add(1, std::memory_order_relaxed);
    }
    
    return blockId;
}

void LockFreeBlockIndex::FreeBlock(uint32_t blockId) {
    if (blockId >= numBlocks_) return;
    
    if (!entries_[blockId].inUse.load(std::memory_order_relaxed)) {
        return;  // Already free
    }
    
    entries_[blockId].inUse.store(false, std::memory_order_release);
    
    // Push onto free list
    uint32_t expected = freeHead_.load(std::memory_order_relaxed);
    do {
        entries_[blockId].nextFree.store(expected, std::memory_order_relaxed);
    } while (!freeHead_.compare_exchange_weak(expected, blockId,
                                               std::memory_order_release,
                                               std::memory_order_relaxed));
    
    usedCount_.fetch_sub(1, std::memory_order_relaxed);
    freeCount_.fetch_add(1, std::memory_order_relaxed);
}

bool LockFreeBlockIndex::IsBlockInUse(uint32_t blockId) const {
    if (blockId >= numBlocks_) return false;
    return entries_[blockId].inUse.load(std::memory_order_acquire);
}

//=============================================================================
// SovereignBlockManager Implementation
//=============================================================================
SovereignBlockManager::SovereignBlockManager() = default;

SovereignBlockManager::~SovereignBlockManager() {
    Shutdown();
}

bool SovereignBlockManager::Initialize(const SovereignPagedKVConfig& config) {
    if (blockManager_) return false;
    
    config_ = config;
    numBlocks_ = config.maxBlocks;
    
    // Determine NUMA node
    auto& allocator = GetGlobalAllocator();
    if (config.useNumaAffinity) {
        numaNode_ = allocator.GetCurrentNumaNode();
    } else {
        numaNode_ = allocator.GetPreferredNumaNode();
    }
    
    // Initialize block index
    if (!blockIndex_.Initialize(numBlocks_)) {
        return false;
    }
    
    // Pre-allocate blocks (optional - can also allocate on-demand)
    blocks_.reserve(numBlocks_);
    for (uint32_t i = 0; i < numBlocks_; i++) {
        blocks_.push_back(std::make_unique<SovereignKVBlock>());
    }
    
    return true;
}

void SovereignBlockManager::Shutdown() {
    // Free all blocks
    for (auto& block : blocks_) {
        if (block) {
            block->Shutdown();
        }
    }
    blocks_.clear();
    
    blockIndex_.Shutdown();
    numBlocks_ = 0;
}

uint32_t SovereignBlockManager::AllocateBlock() {
    uint32_t blockId = blockIndex_.AllocateBlock();
    if (blockId == UINT32_MAX) {
        return UINT32_MAX;  // Out of blocks
    }
    
    // Initialize the block if not already
    if (!blocks_[blockId]->IsValid()) {
        if (!blocks_[blockId]->Initialize(config_, numaNode_, config_.memoryTier)) {
            blockIndex_.FreeBlock(blockId);
            return UINT32_MAX;
        }
    }
    
    allocationCount_.fetch_add(1, std::memory_order_relaxed);
    return blockId;
}

void SovereignBlockManager::FreeBlock(uint32_t blockId) {
    if (blockId >= numBlocks_) return;
    
    blockIndex_.FreeBlock(blockId);
    deallocationCount_.fetch_add(1, std::memory_order_relaxed);
}

SovereignKVBlock* SovereignBlockManager::GetBlock(uint32_t blockId) {
    if (blockId >= blocks_.size()) return nullptr;
    return blocks_[blockId].get();
}

const SovereignKVBlock* SovereignBlockManager::GetBlock(uint32_t blockId) const {
    if (blockId >= blocks_.size()) return nullptr;
    return blocks_[blockId].get();
}

uint32_t SovereignBlockManager::GetFreeBlocks() const {
    return blockIndex_.GetFreeCount();
}

uint32_t SovereignBlockManager::GetUsedBlocks() const {
    return blockIndex_.GetUsedCount();
}

std::string SovereignBlockManager::GetResidencyReport() const {
    std::ostringstream report;
    
    report << "SovereignBlockManager Residency:\n";
    report << "  NUMA Node: " << numaNode_ << "\n";
    report << "  Memory Tier: " << (config_.memoryTier == MemoryTier::LARGE_PAGE_DRAM ? "Large Page" : "Standard") << "\n";
    report << "  Total Blocks: " << numBlocks_ << "\n";
    report << "  Free Blocks: " << GetFreeBlocks() << "\n";
    report << "  Used Blocks: " << GetUsedBlocks() << "\n";
    report << "  Allocations: " << allocationCount_.load() << "\n";
    report << "  Deallocations: " << deallocationCount_.load() << "\n";
    
    return report.str();
}

//=============================================================================
// SovereignPagedKVCache Implementation
//=============================================================================
SovereignPagedKVCache::SovereignPagedKVCache() = default;

SovereignPagedKVCache::~SovereignPagedKVCache() {
    Shutdown();
}

bool SovereignPagedKVCache::Initialize(const SovereignPagedKVConfig& config) {
    if (blockManager_) return false;
    
    config_ = config;
    
    // Create block manager
    blockManager_ = std::make_unique<SovereignBlockManager>();
    if (!blockManager_->Initialize(config)) {
        blockManager_.reset();
        return false;
    }
    
    currentLength_ = 0;
    
    return true;
}

void SovereignPagedKVCache::Shutdown() {
    Clear();
    blockManager_.reset();
}

void SovereignPagedKVCache::AppendToken(const float* k, const float* v) {
    uint32_t logicalBlockIdx = currentLength_ / config_.blockSize;
    uint32_t offsetInBlock = currentLength_ % config_.blockSize;
    
    // Ensure block exists
    if (!EnsureBlock(logicalBlockIdx)) {
        return;  // Out of memory
    }
    
    uint32_t physicalBlockId = blockTable_[logicalBlockIdx];
    SovereignKVBlock* block = blockManager_->GetBlock(physicalBlockId);
    if (!block) return;
    
    // Copy K and V data
    size_t tokenDataSize = config_.numHeads * config_.headDim * sizeof(float);
    
    float* kDest = block->GetK() + offsetInBlock * config_.numHeads * config_.headDim;
    float* vDest = block->GetV() + offsetInBlock * config_.numHeads * config_.headDim;
    
    memcpy(kDest, k, tokenDataSize);
    memcpy(vDest, v, tokenDataSize);
    
    // Update token count
    if (offsetInBlock + 1 > block->GetTokenCount()) {
        block->SetTokenCount(offsetInBlock + 1);
    }
    
    currentLength_++;
}

void SovereignPagedKVCache::AppendTokens(const float* k, const float* v, uint32_t numTokens) {
    for (uint32_t i = 0; i < numTokens; i++) {
        size_t tokenDataSize = config_.numHeads * config_.headDim;
        AppendToken(k + i * tokenDataSize, v + i * tokenDataSize);
    }
}

bool SovereignPagedKVCache::GetK(uint32_t tokenIdx, float* outK) {
    if (tokenIdx >= currentLength_) return false;
    
    uint32_t logicalBlockIdx = tokenIdx / config_.blockSize;
    uint32_t offsetInBlock = tokenIdx % config_.blockSize;
    
    if (logicalBlockIdx >= blockTable_.size()) return false;
    
    uint32_t physicalBlockId = blockTable_[logicalBlockIdx];
    SovereignKVBlock* block = blockManager_->GetBlock(physicalBlockId);
    if (!block) return false;
    
    size_t tokenDataSize = config_.numHeads * config_.headDim * sizeof(float);
    float* kSrc = block->GetK() + offsetInBlock * config_.numHeads * config_.headDim;
    memcpy(outK, kSrc, tokenDataSize);
    
    return true;
}

bool SovereignPagedKVCache::GetV(uint32_t tokenIdx, float* outV) {
    if (tokenIdx >= currentLength_) return false;
    
    uint32_t logicalBlockIdx = tokenIdx / config_.blockSize;
    uint32_t offsetInBlock = tokenIdx % config_.blockSize;
    
    if (logicalBlockIdx >= blockTable_.size()) return false;
    
    uint32_t physicalBlockId = blockTable_[logicalBlockIdx];
    SovereignKVBlock* block = blockManager_->GetBlock(physicalBlockId);
    if (!block) return false;
    
    size_t tokenDataSize = config_.numHeads * config_.headDim * sizeof(float);
    float* vSrc = block->GetV() + offsetInBlock * config_.numHeads * config_.headDim;
    memcpy(outV, vSrc, tokenDataSize);
    
    return true;
}

void SovereignPagedKVCache::Clear() {
    // Free all blocks
    if (blockManager_) {
        for (uint32_t blockId : blockTable_) {
            blockManager_->FreeBlock(blockId);
        }
    }
    
    blockTable_.clear();
    currentLength_ = 0;
}

bool SovereignPagedKVCache::EnsureBlock(uint32_t logicalBlockIdx) {
    while (blockTable_.size() <= logicalBlockIdx) {
        uint32_t physicalBlockId = blockManager_->AllocateBlock();
        if (physicalBlockId == UINT32_MAX) {
            return false;  // Out of memory
        }
        blockTable_.push_back(physicalBlockId);
    }
    return true;
}

std::string SovereignPagedKVCache::GetResidencyReport() const {
    std::ostringstream report;
    
    report << "╔══════════════════════════════════════════════════════════════╗\n";
    report << "║     SovereignPagedKVCache Residency Report                   ║\n";
    report << "╠══════════════════════════════════════════════════════════════╣\n";
    report << "║ Configuration:\n";
    report << "║   Block Size: " << config_.blockSize << " tokens\n";
    report << "║   Num Layers: " << config_.numLayers << "\n";
    report << "║   Num Heads: " << config_.numHeads << "\n";
    report << "║   Head Dim: " << config_.headDim << "\n";
    report << "║   Max Blocks: " << config_.maxBlocks << "\n";
    report << "╠══════════════════════════════════════════════════════════════╣\n";
    report << "║ State:\n";
    report << "║   Context Length: " << currentLength_ << "\n";
    report << "║   Logical Blocks: " << blockTable_.size() << "\n";
    
    if (blockManager_) {
        report << "║   Physical Blocks Used: " << blockManager_->GetUsedBlocks() << "\n";
        report << "║   Physical Blocks Free: " << blockManager_->GetFreeBlocks() << "\n";
    }
    
    report << "╚══════════════════════════════════════════════════════════════╝\n";
    
    return report.str();
}

} // namespace KVCache
} // namespace RawrXD
