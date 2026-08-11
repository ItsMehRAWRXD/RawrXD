// ============================================================================
// BlockTable.cpp
// ============================================================================
#include "BlockTable.hpp"
#include <cstdio>

namespace RawrXD {
namespace Memory {

BlockTable::BlockTable(size_t maxBlocks)
    : m_blocks(maxBlocks)
    , m_occupied(maxBlocks, false)
{}

bool BlockTable::insert(BlockId id, uint64_t bytes, const std::string& name) {
    std::lock_guard<std::mutex> lk(m_mtx);
    // Find first free slot
    for (size_t i = 0; i < m_blocks.size(); ++i) {
        if (!m_occupied[i]) {
            m_blocks[i].id         = id;
            m_blocks[i].bytes        = bytes;
            m_blocks[i].state        = BlockResidencyState::SSD_CLEAN;
            m_blocks[i].refCount     = 0;
            m_blocks[i].lastAccess   = 0;
            m_blocks[i].secondChance = 0;
            m_blocks[i].dataPtr      = 0;
            m_blocks[i].ssdOffset    = 0;
            m_blocks[i].debugName    = name;
            m_occupied[i] = true;
            m_count.fetch_add(1, std::memory_order_relaxed);
            m_ssdBytes.fetch_add(bytes, std::memory_order_relaxed);
            return true;
        }
    }
    return false; // table full
}

bool BlockTable::remove(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (size_t i = 0; i < m_blocks.size(); ++i) {
        if (m_occupied[i] && m_blocks[i].id == id) {
            // Update accounting
            if (m_blocks[i].residentInRam()) {
                m_ramBytes.fetch_sub(m_blocks[i].bytes, std::memory_order_relaxed);
            }
            if (m_blocks[i].residentInVram()) {
                m_vramBytes.fetch_sub(m_blocks[i].bytes, std::memory_order_relaxed);
            }
            if (m_blocks[i].residentInSsd()) {
                m_ssdBytes.fetch_sub(m_blocks[i].bytes, std::memory_order_relaxed);
            }
            m_occupied[i] = false;
            m_blocks[i] = BlockMeta{}; // zero
            m_count.fetch_sub(1, std::memory_order_relaxed);
            return true;
        }
    }
    return false;
}

bool BlockTable::acquire(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) {
            b.refCount++;
            b.lastAccess = ++m_clockTick;
            return true;
        }
    }
    return false;
}

bool BlockTable::release(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) {
            if (b.refCount > 0) b.refCount--;
            return true;
        }
    }
    return false;
}

bool BlockTable::transition(BlockId id, BlockResidencyState to) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) {
            if (!IsLegalTransition(b.state, to)) {
                std::fprintf(stderr,
                    "[BlockTable] ILLEGAL transition: %s (%s) → %s for block %llu (%s)\n",
                    StateName(b.state), b.debugName.c_str(),
                    StateName(to), static_cast<unsigned long long>(id), b.debugName.c_str());
                return false;
            }
            // Update tier byte accounting
            ResidencyTier oldTier = tierFromState(b.state);
            ResidencyTier newTier = tierFromState(to);
            if (oldTier != newTier) {
                int64_t delta = static_cast<int64_t>(b.bytes);
                if (oldTier == ResidencyTier::RAM) m_ramBytes.fetch_sub(b.bytes, std::memory_order_relaxed);
                if (oldTier == ResidencyTier::VRAM) m_vramBytes.fetch_sub(b.bytes, std::memory_order_relaxed);
                if (oldTier == ResidencyTier::SSD) m_ssdBytes.fetch_sub(b.bytes, std::memory_order_relaxed);
                if (newTier == ResidencyTier::RAM) m_ramBytes.fetch_add(b.bytes, std::memory_order_relaxed);
                if (newTier == ResidencyTier::VRAM) m_vramBytes.fetch_add(b.bytes, std::memory_order_relaxed);
                if (newTier == ResidencyTier::SSD) m_ssdBytes.fetch_add(b.bytes, std::memory_order_relaxed);
            }
            b.state = to;
            return true;
        }
    }
    return false;
}

bool BlockTable::dirty(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) {
            if (b.state != BlockResidencyState::RAM_CLEAN &&
                b.state != BlockResidencyState::SSD_WRITE_COMPLETE) {
                return false; // can only dirty clean RAM blocks
            }
            b.state = BlockResidencyState::RAM_DIRTY;
            b.generation.bumpCpu();
            return true;
        }
    }
    return false;
}

bool BlockTable::beginFlush(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) {
            if (b.state != BlockResidencyState::RAM_DIRTY) return false;
            b.state = BlockResidencyState::FLUSH_PENDING;
            return true;
        }
    }
    return false;
}

bool BlockTable::completeFlush(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) {
            if (b.state != BlockResidencyState::FLUSH_PENDING) return false;
            b.state = BlockResidencyState::SSD_WRITE_COMPLETE;
            b.generation.bumpSsd();
            return true;
        }
    }
    return false;
}

bool BlockTable::markClean(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) {
            if (b.state != BlockResidencyState::SSD_WRITE_COMPLETE) return false;
            b.state = BlockResidencyState::RAM_CLEAN;
            return true;
        }
    }
    return false;
}

BlockId BlockTable::runEvictionScan(uint64_t pressureThreshold, uint64_t& bytesFreed, size_t maxScan) {
    std::lock_guard<std::mutex> lk(m_mtx);
    bytesFreed = 0;
    size_t cap = m_blocks.size();
    if (cap == 0) return 0;

    uint64_t ramUsed = m_ramBytes.load(std::memory_order_relaxed);
    if (ramUsed <= pressureThreshold) return 0; // no pressure

    size_t scanLimit = maxScan ? maxScan : cap;
    size_t start = m_clockHand.load(std::memory_order_relaxed) % cap;

    for (size_t s = 0; s < scanLimit; ++s) {
        size_t idx = (start + s) % cap;
        if (!m_occupied[idx]) continue;

        BlockMeta& b = m_blocks[idx];
        if (!b.evictable()) {
            // If referenced recently, give a second chance
            if (b.secondChance > 0) {
                b.secondChance = 0;
            }
            continue;
        }

        // Second-chance: if accessed since last scan AND not already given a second chance
        if (b.lastAccess > b.secondChance && b.secondChance != UINT64_MAX) {
            b.secondChance = UINT64_MAX; // mark as "already had second chance"
            continue;
        }

        // Evict this block
        bytesFreed = b.bytes;
        m_ramBytes.fetch_sub(b.bytes, std::memory_order_relaxed);
        // SSD bytes already accounted for at insert time; transition just moves state

        // Advance clock hand past this block
        size_t next = (idx + 1) % cap;
        m_clockHand.store(next, std::memory_order_relaxed);

        // Finalise state to SSD_CLEAN (caller must persist data before this)
        b.state = BlockResidencyState::SSD_CLEAN;
        b.dataPtr = 0; // RAM pointer invalidated
        b.secondChance = 0;
        return b.id;
    }

    // No block evicted; advance hand anyway
    m_clockHand.store((start + scanLimit) % cap, std::memory_order_relaxed);
    return 0;
}

BlockMeta* BlockTable::find(BlockId id) {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (auto& b : m_blocks) {
        if (b.id == id) return &b;
    }
    return nullptr;
}

const BlockMeta* BlockTable::find(BlockId id) const {
    std::lock_guard<std::mutex> lk(m_mtx);
    for (const auto& b : m_blocks) {
        if (b.id == id) return &b;
    }
    return nullptr;
}

std::vector<BlockMeta> BlockTable::snapshot() const {
    std::lock_guard<std::mutex> lk(m_mtx);
    std::vector<BlockMeta> out;
    out.reserve(m_count.load(std::memory_order_relaxed));
    for (size_t i = 0; i < m_blocks.size(); ++i) {
        if (m_occupied[i]) out.push_back(m_blocks[i]);
    }
    return out;
}

} // namespace Memory
} // namespace RawrXD
