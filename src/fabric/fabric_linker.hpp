#pragma once
//=============================================================================
// Fabric Linker - VAL-031.3 2-Node PoC
// Raw Win32 socket transport for B008 distributed fabric
//=============================================================================

#include "b008_packet.hpp"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <functional>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD {
namespace Fabric {

// Forward declarations
class FabricOrchestrator;

// Fabric configuration
struct FabricConfig {
    uint8_t node_id;            // This node's ID (0, 1, 2...)
    uint16_t listen_port;       // Port to listen on
    const char* peer_address;   // Peer node IP (for client mode)
    uint16_t peer_port;         // Peer node port
    bool is_server;             // True = listen, False = connect
    
    FabricConfig() 
        : node_id(0), listen_port(31337), 
          peer_address("127.0.0.1"), peer_port(31338),
          is_server(true) {}
};

// Fabric statistics
struct FabricStats {
    std::atomic<uint64_t> packets_sent{0};
    std::atomic<uint64_t> packets_recv{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_recv{0};
    std::atomic<uint64_t> errors{0};
    std::atomic<uint64_t> timeouts{0};
    
    // Latency tracking (microseconds)
    std::atomic<uint64_t> latency_sum{0};
    std::atomic<uint64_t> latency_count{0};
    
    double GetAvgLatencyUs() const {
        uint64_t count = latency_count.load();
        if (count == 0) return 0.0;
        return static_cast<double>(latency_sum.load()) / count;
    }
};

// Fabric Linker - Raw socket transport
class FabricLinker {
public:
    // Callback for received packets
    using PacketHandler = std::function<void(const Packet& packet, void* user_data)>;
    
    FabricLinker();
    ~FabricLinker();
    
    // Initialize WinSock and create sockets
    bool Initialize(const FabricConfig& config);
    
    // Shutdown and cleanup
    void Shutdown();
    
    // Connect to peer (client mode)
    bool ConnectToPeer();
    
    // Accept peer connection (server mode)
    bool AcceptPeer();
    
    // Send packet (blocking for PoC)
    bool SendPacket(const Packet& packet);
    
    // Send packet with payload
    bool SendPacketWithPayload(const Packet& packet, const void* payload, size_t len);
    
    // Receive packet (blocking, timeout_ms)
    bool ReceivePacket(Packet& out_packet, int timeout_ms = 5000);
    
    // Non-blocking receive (for IOCP integration)
    bool ReceivePacketAsync(Packet& out_packet);
    
    // Simple ping/pong handshake
    bool PerformHandshake();
    
    // Check if connected
    bool IsConnected() const { return connected_.load(); }
    
    // Get statistics
    FabricStats GetStats() const { return stats_; }
    
    // Get last error
    int GetLastError() const { return last_error_; }
    
private:
    FabricConfig config_;
    
    // Sockets
    SOCKET listen_socket_;
    SOCKET peer_socket_;
    
    // State
    std::atomic<bool> initialized_{false};
    std::atomic<bool> connected_{false};
    std::atomic<bool> shutdown_{false};
    
    // Statistics
    FabricStats stats_;
    
    // Last error
    int last_error_;
    
    // WSADATA for WinSock
    WSADATA wsa_data_;
    
    // Helper methods
    bool InitWinSock();
    bool CreateListenSocket();
    bool SetSocketOptions(SOCKET sock);
    bool SendAll(const void* data, size_t len);
    bool RecvAll(void* data, size_t len, int timeout_ms);
};

// Global fabric linker instance
FabricLinker& GetFabricLinker();

} // namespace Fabric
} // namespace RawrXD
