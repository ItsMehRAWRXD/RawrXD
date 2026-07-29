#include "memory_space_manager.h"
<<<<<<< HEAD
#include <iostream>

MemorySpaceManager::MemorySpaceManager()
    : m_limitBytes(0)
{
=======
MemorySpaceManager& MemorySpaceManager::instance()
{
    static MemorySpaceManager mgr;
    return mgr;
}

MemorySpaceManager::MemorySpaceManager()
{
    ensureConfig();
}

bool MemorySpaceManager::isEnabled() const
{
    return m_enabled;
}

void MemorySpaceManager::setEnabled(bool enabled)
{
    m_enabled = enabled;
    ensureConfig();
    // Persist setting
    // Settings initialization removed
    settings.setValue("memory/enabled", enabled);
    settings.sync();
}

int64_t MemorySpaceManager::limitBytes() const
{
    return m_limitBytes;
}

void MemorySpaceManager::setLimitBytes(int64_t bytes)
{
    m_limitBytes = bytes;
    ensureConfig();
    // Settings initialization removed
    settings.setValue("memory/limitBytes", bytes);
    settings.sync();
}

std::string MemorySpaceManager::settingsFilePath() const
{
    std::string base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    std::filesystem::create_directories(base);
    return base + "/RawrXD.ini";
}

std::string MemorySpaceManager::memoryFilePath() const
{
    std::string base = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    std::filesystem::create_directories(base);
    return base + "/RawrXD_memory.json";
}

void MemorySpaceManager::ensureConfig()
{
    // Settings initialization removed
    m_enabled = settings.value("memory/enabled", m_enabled).toBool();
    m_limitBytes = settings.value("memory/limitBytes", m_limitBytes).toLongLong();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void* MemorySpaceManager::readJson() const
{
<<<<<<< HEAD
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
=======
    // File operation removed);
    if (!file.exists()) {
        return void*();
    }
    if (!file.open(std::iostream::ReadOnly | std::iostream::Text)) {
        return void*();
    }
    std::vector<uint8_t> data = file.readAll();
    file.close();
    void* doc = void*::fromJson(data);
    if (!doc.isObject()) {
        return void*();
    }
    return doc.object();
}

bool MemorySpaceManager::writeJson(const void*& obj) const
{
    // File operation removed);
    if (!file.open(std::iostream::WriteOnly | std::iostream::Text)) {
        return false;
    }
    void* doc(obj);
    file.write(doc.toJson(void*::Compact));
    file.close();
    return true;
}

void MemorySpaceManager::persist(const std::map<std::string, std::any>& memoryMap)
{
    if (!m_enabled) {
        return;
    }

    void* obj;
    for (auto it = memoryMap.constBegin(); it != memoryMap.constEnd(); ++it) {
        obj[it.key()] = it.value().toString();
    }

    // Enforce size limit by pruning oldest keys if necessary
    std::stringList keys = obj.keys();
    while (!keys.empty()) {
        void* sizeProbe(obj);
        int64_t bytes = sizeProbe.toJson(void*::Compact).size();
        if (bytes <= m_limitBytes) break;
        std::string dropKey = keys.takeFirst();
        obj.remove(dropKey);
    }

    void* root;
    root["memory"] = obj;
    writeJson(root);
}

std::map<std::string, std::string> MemorySpaceManager::loadMemory() const
{
    std::map<std::string, std::string> result;
    void* root = readJson();
    if (!root.contains("memory")) return result;
    void* mem = root.value("memory").toObject();
    for (auto it = mem.constBegin(); it != mem.constEnd(); ++it) {
        result[it.key()] = it.value().toString();
    }
    return result;
}

std::stringList MemorySpaceManager::listKeys() const
{
    return loadMemory().keys();
}

bool MemorySpaceManager::deleteKey(const std::string& key)
{
    void* root = readJson();
    void* mem = root.value("memory").toObject();
    if (!mem.contains(key)) return false;
    mem.remove(key);
    root["memory"] = mem;
    return writeJson(root);
}

void MemorySpaceManager::clearAll()
{
    std::filesystem::remove(memoryFilePath());
}

int64_t MemorySpaceManager::currentSizeBytes() const
{
    // Info info(memoryFilePath());
    if (!info.exists()) return 0;
    return info.size();
}

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
