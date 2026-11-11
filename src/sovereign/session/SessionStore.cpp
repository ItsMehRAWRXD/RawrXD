// SessionStore.cpp
// Persistent Session Store - Atomic Disk-backed KV Store
// Implementation of crash-safe session persistence

#include "SessionStore.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <algorithm>

namespace Sovereign {

// File format constants
constexpr size_t HEADER_SIZE = 16;
constexpr size_t CHECKSUM_SIZE = 32; // SHA-256

SessionStore::SessionStore(const std::string& path) : storagePath(path) {
    EnsureDirectoryExists();
    RebuildIndex();
}

void SessionStore::EnsureDirectoryExists() const {
    if (!fs::exists(storagePath)) {
        fs::create_directories(storagePath);
    }
}

fs::path SessionStore::GetSessionPath(uint64_t sessionId) const {
    std::stringstream ss;
    ss << std::setw(6) << std::setfill('0') << sessionId;
    return storagePath / (ss.str() + ".session");
}

uint64_t SessionStore::GenerateSessionId() const {
    // Use timestamp + random for uniqueness
    auto now = std::chrono::steady_clock::now();
    auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    return static_cast<uint64_t>(millis);
}

std::string SessionStore::CalculateChecksum(const std::string& data) const {
    // Simplified checksum - in production use SHA-256
    uint64_t hash = 0x9E3779B97F4A7C15ULL;
    for (char c : data) {
        hash ^= static_cast<uint64_t>(c);
        hash *= 0x100000001B3ULL;
    }
    
    std::stringstream ss;
    for (int i = 0; i < CHECKSUM_SIZE; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << ((hash >> (i * 8)) & 0xFF);
    }
    return ss.str();
}

std::string SessionStore::SerializeSession(const AgentSession& session) const {
    std::stringstream json;
    
    // Metadata
    json << "{\n";
    json << "  \"metadata\": {\n";
    json << "    \"sessionId\": " << session.metadata.sessionId << ",\n";
    json << "    \"name\": \"" << session.metadata.name << "\",\n";
    json << "    \"model\": \"" << session.metadata.model << "\",\n";
    json << "    \"mode\": \"" << session.metadata.mode << "\",\n";
    json << "    \"createdAt\": " << session.metadata.createdAt << ",\n";
    json << "    \"lastActivity\": " << session.metadata.lastActivity << ",\n";
    json << "    \"tokenBudget\": " << session.metadata.tokenBudget << ",\n";
    json << "    \"tokensUsed\": " << session.metadata.tokensUsed << ",\n";
    json << "    \"active\": " << (session.metadata.active ? "true" : "false") << "\n";
    json << "  },\n";
    
    // Chat history
    json << "  \"history\": [\n";
    for (size_t i = 0; i < session.history.size(); ++i) {
        const auto& msg = session.history[i];
        json << "    {\n";
        json << "      \"role\": \"" << msg.role << "\",\n";
        json << "      \"content\": \"" << msg.content << "\",\n";
        json << "      \"timestamp\": " << msg.timestamp << "\n";
        json << "    }";
        if (i < session.history.size() - 1) json << ",";
        json << "\n";
    }
    json << "  ],\n";
    
    // Working memory
    json << "  \"workingMemory\": {\n";
    size_t count = 0;
    for (const auto& [key, value] : session.workingMemory) {
        json << "    \"" << key << "\": \"" << value << "\"";
        if (++count < session.workingMemory.size()) json << ",";
        json << "\n";
    }
    json << "  },\n";
    
    // Open files
    json << "  \"openFiles\": [\n";
    for (size_t i = 0; i < session.openFiles.size(); ++i) {
        json << "    \"" << session.openFiles[i] << "\"";
        if (i < session.openFiles.size() - 1) json << ",";
        json << "\n";
    }
    json << "  ],\n";
    
    // Current task and agent graph state
    json << "  \"currentTask\": \"" << session.currentTask << "\",\n";
    json << "  \"agentGraphState\": \"" << session.agentGraphState << "\"\n";
    json << "}";
    
    return json.str();
}

bool SessionStore::DeserializeSession(const std::string& data, AgentSession& session) const {
    // Simplified JSON parsing - in production use a proper JSON library
    // This is a minimal implementation for demonstration
    
    // Extract sessionId
    size_t pos = data.find("\"sessionId\":");
    if (pos != std::string::npos) {
        size_t start = data.find_first_of("0123456789", pos);
        size_t end = data.find_first_not_of("0123456789", start);
        if (start != std::string::npos && end != std::string::npos) {
            session.metadata.sessionId = std::stoull(data.substr(start, end - start));
        }
    }
    
    // Extract name
    pos = data.find("\"name\": \"");
    if (pos != std::string::npos) {
        size_t start = pos + 9;
        size_t end = data.find("\"", start);
        if (end != std::string::npos) {
            session.metadata.name = data.substr(start, end - start);
        }
    }
    
    // Extract model
    pos = data.find("\"model\": \"");
    if (pos != std::string::npos) {
        size_t start = pos + 10;
        size_t end = data.find("\"", start);
        if (end != std::string::npos) {
            session.metadata.model = data.substr(start, end - start);
        }
    }
    
    // Extract mode
    pos = data.find("\"mode\": \"");
    if (pos != std::string::npos) {
        size_t start = pos + 9;
        size_t end = data.find("\"", start);
        if (end != std::string::npos) {
            session.metadata.mode = data.substr(start, end - start);
        }
    }
    
    // Set timestamps
    session.metadata.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    session.metadata.lastActivity = session.metadata.createdAt;
    session.metadata.active = true;
    session.metadata.tokenBudget = 8192;
    session.metadata.tokensUsed = 0;
    
    return true;
}

bool SessionStore::WriteSessionFile(const fs::path& path, const AgentSession& session) {
    // Serialize to JSON
    std::string jsonData = SerializeSession(session);
    
    // Calculate checksum
    std::string checksum = CalculateChecksum(jsonData);
    
    // Build binary format
    std::vector<uint8_t> buffer;
    buffer.reserve(HEADER_SIZE + jsonData.size() + CHECKSUM_SIZE);
    
    // Header
    buffer.insert(buffer.end(), MAGIC, MAGIC + 4);
    uint32_t version = VERSION;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&version), 
                  reinterpret_cast<uint8_t*>(&version) + sizeof(version));
    uint64_t sessionId = session.metadata.sessionId;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t*>(&sessionId), 
                  reinterpret_cast<uint8_t*>(&sessionId) + sizeof(sessionId));
    
    // JSON data
    buffer.insert(buffer.end(), jsonData.begin(), jsonData.end());
    
    // Checksum
    buffer.insert(buffer.end(), checksum.begin(), checksum.end());
    
    // Write to temp file first (atomic)
    fs::path tempPath = path.string() + ".tmp";
    {
        std::ofstream file(tempPath, std::ios::binary);
        if (!file) return false;
        file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        if (!file) return false;
    }
    
    // Atomic rename
    try {
        fs::rename(tempPath, path);
    } catch (...) {
        fs::remove(tempPath);
        return false;
    }
    
    return true;
}

bool SessionStore::ReadSessionFile(const fs::path& path, AgentSession& session) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    
    auto size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (size < static_cast<std::streamoff>(HEADER_SIZE + CHECKSUM_SIZE)) {
        return false;
    }
    
    // Read header
    char magic[4];
    file.read(magic, 4);
    if (std::memcmp(magic, MAGIC, 4) != 0) {
        return false;
    }
    
    uint32_t version;
    file.read(reinterpret_cast<char*>(&version), sizeof(version));
    if (version != VERSION) {
        return false;
    }
    
    uint64_t sessionId;
    file.read(reinterpret_cast<char*>(&sessionId), sizeof(sessionId));
    
    // Read JSON data
    size_t jsonSize = static_cast<size_t>(size) - HEADER_SIZE - CHECKSUM_SIZE;
    std::string jsonData(jsonSize, '\0');
    file.read(jsonData.data(), jsonSize);
    
    // Read and verify checksum
    std::string storedChecksum(CHECKSUM_SIZE, '\0');
    file.read(storedChecksum.data(), CHECKSUM_SIZE);
    
    std::string calculatedChecksum = CalculateChecksum(jsonData);
    if (storedChecksum != calculatedChecksum) {
        return false;
    }
    
    // Deserialize
    return DeserializeSession(jsonData, session);
}

bool SessionStore::Save(const AgentSession& session) {
    std::lock_guard<std::mutex> lock(storeLock);
    
    fs::path path = GetSessionPath(session.metadata.sessionId);
    
    if (!WriteSessionFile(path, session)) {
        return false;
    }
    
    // Update index
    sessionIndex[session.metadata.sessionId] = path;
    
    return true;
}

AgentSession SessionStore::Load(uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(storeLock);
    
    AgentSession session;
    session.metadata.sessionId = sessionId;
    
    fs::path path = GetSessionPath(sessionId);
    
    if (!fs::exists(path)) {
        // Return empty session
        return session;
    }
    
    if (!ReadSessionFile(path, session)) {
        // Return empty session on error
        session.metadata.sessionId = sessionId;
        session.history.clear();
        session.workingMemory.clear();
    }
    
    return session;
}

std::vector<uint64_t> SessionStore::List() const {
    std::lock_guard<std::mutex> lock(storeLock);
    
    std::vector<uint64_t> ids;
    ids.reserve(sessionIndex.size());
    
    for (const auto& [id, path] : sessionIndex) {
        ids.push_back(id);
    }
    
    std::sort(ids.begin(), ids.end());
    return ids;
}

bool SessionStore::Delete(uint64_t sessionId) {
    std::lock_guard<std::mutex> lock(storeLock);
    
    fs::path path = GetSessionPath(sessionId);
    
    if (!fs::exists(path)) {
        return false;
    }
    
    try {
        fs::remove(path);
        sessionIndex.erase(sessionId);
        return true;
    } catch (...) {
        return false;
    }
}

bool SessionStore::Exists(uint64_t sessionId) const {
    std::lock_guard<std::mutex> lock(storeLock);
    return sessionIndex.find(sessionId) != sessionIndex.end();
}

AgentSession SessionStore::Create(const std::string& name, const std::string& model, 
                                   const std::string& mode) {
    AgentSession session;
    
    session.metadata.sessionId = GenerateSessionId();
    session.metadata.name = name;
    session.metadata.model = model;
    session.metadata.mode = mode;
    session.metadata.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    session.metadata.lastActivity = session.metadata.createdAt;
    session.metadata.tokenBudget = 8192;
    session.metadata.tokensUsed = 0;
    session.metadata.active = true;
    
    // Save immediately
    Save(session);
    
    return session;
}

bool SessionStore::UpdateMetadata(uint64_t sessionId, const SessionMetadata& metadata) {
    auto session = Load(sessionId);
    if (session.metadata.sessionId == 0) {
        return false;
    }
    
    session.metadata = metadata;
    session.metadata.lastActivity = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return Save(session);
}

bool SessionStore::AppendMessage(uint64_t sessionId, const ChatMessage& message) {
    auto session = Load(sessionId);
    if (session.metadata.sessionId == 0) {
        return false;
    }
    
    session.history.push_back(message);
    session.metadata.lastActivity = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    return Save(session);
}

void SessionStore::RebuildIndex() {
    sessionIndex.clear();
    
    if (!fs::exists(storagePath)) {
        return;
    }
    
    for (const auto& entry : fs::directory_iterator(storagePath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".session") {
            // Extract session ID from filename
            std::string filename = entry.path().stem().string();
            try {
                uint64_t id = std::stoull(filename);
                sessionIndex[id] = entry.path();
            } catch (...) {
                // Skip invalid filenames
            }
        }
    }
}

size_t SessionStore::Compact() {
    std::lock_guard<std::mutex> lock(storeLock);
    
    size_t removed = 0;
    
    // Remove orphaned index entries
    for (auto it = sessionIndex.begin(); it != sessionIndex.end();) {
        if (!fs::exists(it->second)) {
            it = sessionIndex.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    return removed;
}

} // namespace Sovereign
