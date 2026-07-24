// ============================================================================
// RemoteDevelopment.hpp - Remote Development & SSH Workspaces
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct RemoteConnection {
    std::string name;
    std::string host;
    uint16_t port = 22;
    std::string user;
    std::string authMethod; // "password", "key", "agent"
    std::string keyPath;
    std::string workspacePath;
    bool isConnected;
    uint64_t connectedAt;
    uint64_t latencyMs;
};

struct RemoteFile {
    std::string path;
    uint64_t size;
    uint64_t modified;
    bool isDirectory;
    std::string permissions;
};

class RemoteDevelopment {
public:
    RemoteDevelopment();
    ~RemoteDevelopment();

    bool Initialize();
    void Shutdown();

    // Connection management
    bool Connect(const RemoteConnection& conn);
    bool Disconnect(const std::string& name);
    bool IsConnected(const std::string& name) const;
    std::vector<RemoteConnection> GetConnections() const;

    // File operations
    std::vector<RemoteFile> ListDirectory(const std::string& connName, const std::string& path);
    std::string ReadFile(const std::string& connName, const std::string& path);
    bool WriteFile(const std::string& connName, const std::string& path, const std::string& content);
    bool DeleteFile(const std::string& connName, const std::string& path);
    bool CreateDirectory(const std::string& connName, const std::string& path);

    // Command execution
    std::string ExecuteCommand(const std::string& connName, const std::string& command);
    std::string ExecuteCommandAsync(const std::string& connName, const std::string& command);

    // Port forwarding
    bool ForwardPort(const std::string& connName, uint16_t localPort, uint16_t remotePort);
    bool StopForwarding(const std::string& connName, uint16_t localPort);

    // Tunnel
    bool CreateTunnel(const std::string& connName, const std::string& localAddr, uint16_t localPort,
                      const std::string& remoteAddr, uint16_t remotePort);

    struct RemoteStats {
        uint64_t totalConnections;
        uint64_t activeConnections;
        uint64_t filesTransferred;
        uint64_t bytesTransferred;
        uint64_t commandsExecuted;
    };
    RemoteStats GetStats() const { return stats_; }

private:
    std::unordered_map<std::string, RemoteConnection> connections_;
    RemoteStats stats_;
    mutable std::mutex mutex_;
    
    // SSH session handles
    struct SSHSession {
        void* session;
        void* channel;
        bool connected;
    };
    std::unordered_map<std::string, SSHSession> sessions_;
};

} // namespace Sovereign
