// SessionStore.hpp
// Persistent Session Store - Atomic Disk-backed KV Store
// Feature #2: Persistent SessionStore

#ifndef SESSIONSTORE_HPP
#define SESSIONSTORE_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <fstream>
#include <chrono>
#include <filesystem>

namespace Sovereign {

namespace fs = std::filesystem;

/**
 * @struct ChatMessage
 * @brief Single message in chat history
 */
struct ChatMessage {
    std::string role;       // "user", "assistant", "system", "tool"
    std::string content;
    uint64_t timestamp;
    std::string model;      // Which model generated this
    std::vector<std::string> toolCalls;  // Tool invocations if any
};

/**
 * @struct SessionMetadata
 * @brief Session configuration and state
 */
struct SessionMetadata {
    uint64_t sessionId;
    std::string name;
    std::string model;
    std::string mode;       // "ask", "plan", "edit", "agent"
    uint64_t createdAt;
    uint64_t lastActivity;
    size_t tokenBudget;
    size_t tokensUsed;
    bool active;
    std::unordered_map<std::string, std::string> customData;
};

/**
 * @struct AgentSession
 * @brief Complete session state
 */
struct AgentSession {
    SessionMetadata metadata;
    std::vector<ChatMessage> history;
    std::unordered_map<std::string, std::string> workingMemory;  // KV store
    std::vector<std::string> openFiles;
    std::string currentTask;
    std::string agentGraphState;  // Serialized AgentGraphRuntime state
};

/**
 * @class SessionStore
 * @brief Atomic disk-backed session persistence
 * 
 * File Format (.sovereign_session):
 * [Header: 16 bytes]
 *   - Magic: "SOV\0" (4 bytes)
 *   - Version: uint32_t
 *   - SessionID: uint64_t
 * [Metadata: JSON blob]
 * [History: JSON array of messages]
 * [Working Memory: JSON KV pairs]
 * [Checksum: SHA-256]
 * 
 * Usage:
 *   SessionStore store(".sovereign/sessions/");
 *   
 *   // Save session
 *   store.Save(session);
 *   
 *   // Load session
 *   auto session = store.Load(sessionId);
 *   
 *   // List all sessions
 *   auto ids = store.List();
 */
class SessionStore {
    fs::path storagePath;
    mutable std::mutex storeLock;
    std::unordered_map<uint64_t, fs::path> sessionIndex;
    
    static constexpr const char* MAGIC = "SOV\0";
    static constexpr uint32_t VERSION = 1;
    
public:
    explicit SessionStore(const std::string& path = ".sovereign/sessions/");
    ~SessionStore() = default;
    
    /**
     * @brief Save session to disk atomically
     * @param session Session to save
     * @return true if saved successfully
     */
    bool Save(const AgentSession& session);
    
    /**
     * @brief Load session from disk
     * @param sessionId Session identifier
     * @return Loaded session, or empty session if not found
     */
    AgentSession Load(uint64_t sessionId);
    
    /**
     * @brief List all saved session IDs
     * @return Vector of session IDs
     */
    std::vector<uint64_t> List() const;
    
    /**
     * @brief Delete a session
     * @param sessionId Session to delete
     * @return true if deleted
     */
    bool Delete(uint64_t sessionId);
    
    /**
     * @brief Check if session exists
     * @param sessionId Session to check
     * @return true if exists
     */
    bool Exists(uint64_t sessionId) const;
    
    /**
     * @brief Create new session with unique ID
     * @param name Session name
     * @param model Default model
     * @param mode Session mode
     * @return New session with assigned ID
     */
    AgentSession Create(const std::string& name, 
                        const std::string& model = "default",
                        const std::string& mode = "ask");
    
    /**
     * @brief Update session metadata
     * @param sessionId Session to update
     * @param metadata New metadata
     * @return true if updated
     */
    bool UpdateMetadata(uint64_t sessionId, const SessionMetadata& metadata);
    
    /**
     * @brief Append message to session history
     * @param sessionId Session ID
     * @param message Message to append
     * @return true if appended
     */
    bool AppendMessage(uint64_t sessionId, const ChatMessage& message);
    
    /**
     * @brief Get session file path
     * @param sessionId Session ID
     * @return Path to session file
     */
    fs::path GetSessionPath(uint64_t sessionId) const;
    
    /**
     * @brief Compact storage (remove orphaned files)
     * @return Number of files removed
     */
    size_t Compact();
    
private:
    void EnsureDirectoryExists() const;
    bool WriteSessionFile(const fs::path& path, const AgentSession& session);
    bool ReadSessionFile(const fs::path& path, AgentSession& session);
    uint64_t GenerateSessionId() const;
    std::string SerializeSession(const AgentSession& session) const;
    bool DeserializeSession(const std::string& data, AgentSession& session) const;
    std::string CalculateChecksum(const std::string& data) const;
    void RebuildIndex();
};

} // namespace Sovereign

#endif // SESSIONSTORE_HPP
