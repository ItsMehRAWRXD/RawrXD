#include "memory_space_manager.h"
#include <iostream>

MemorySpaceManager::MemorySpaceManager()
    : m_limitBytes(0)
{
}

void* MemorySpaceManager::readJson() const
{
    return nullptr;
}

bool MemorySpaceManager::writeJson(const void* obj) const
{
    (void)obj;
    return true;
}

void MemorySpaceManager::setLimitBytes(int64_t bytes) {
    m_limitBytes = bytes;
}

int64_t MemorySpaceManager::getLimitBytes() const {
    return m_limitBytes;
}
