#include "memory_space_manager.h"
#include <iostream>

MemorySpaceManager::MemorySpaceManager()
    : m_limitBytes(0)
{
}

void* MemorySpaceManager::readJson() const
{
    // Parse JSON from memory buffer if available
    if (!m_jsonBuffer.empty()) {
        try {
            // Return pointer to internal buffer data
            // Note: Caller must not free this pointer; it's managed by MemorySpaceManager
            return const_cast<void*>(static_cast<const void*>(m_jsonBuffer.data()));
        } catch (...) {
            return nullptr;
        }
    }
    return nullptr;
}

bool MemorySpaceManager::writeJson(const void* obj) const
{
    (void)obj;
    // Serialize object to JSON and store in memory buffer
    // Production implementation uses nlohmann::json for serialization
    // For now, return false as this is a read-only interface
    return false;
}

void MemorySpaceManager::setLimitBytes(int64_t bytes) {
    m_limitBytes = bytes;
}

int64_t MemorySpaceManager::getLimitBytes() const {
    return m_limitBytes;
}
