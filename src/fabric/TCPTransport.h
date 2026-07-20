#pragma once

#include "FabricTransport.h"
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <atomic>
#include <memory>
#include <unordered_map>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD {
namespace Fabric {

// ============================================================================
// TCP Transport - Real Network Implementation with IOCP
// 
// Production-ready TCP transport using Windows IOCP for async I/O.
// Replaces LoopbackTransport for actual multi-node clusters.
// ============================================================================

// Per-connection context
struct alignas(64) TCPConnection {
    SOCKET socket;
    uint32_t nodeId;
    
    // IOCP overlapped structures
    OVERLAPPED recvOverlap;
    OVERLAPPED sendOverlap;
    
    // Buffers
    WSABUF recvBuf;
    WSABUF sendBuf;
    
    // State
    std::atomic<bool> connected{false};
    std::atomic<bool> closing{false};
    
    // Receive buffer (circular)
    static constexpr size_t RECV_BUF_SIZE = 65536;
    uint8_t recvBuffer[RECV_BUF_SIZE];
    size_t recvHead{0};
    size_t recvTail{0};
    
    // Pending sends queue
    std::vector<FabricMessage> sendQueue;
    std::mutex sendMutex;
    bool sendPending{false};
    
    TCPConnection();
    ~TCPConnection();
    
    bool Initialize(SOCKET sock, uint32_t node);
    void Close();
    
    // Buffer management
    size_t GetRecvAvailable() const;
    bool AppendRecvData(const void* data, size_t len);
    bool ExtractMessage(FabricMessage& msg);
};

// IOCP operation types
enum class IOCPOpType : uint32_t {
    ACCEPT = 1,
    RECEIVE = 2,
    SEND = 3,
    CONNECT = 4
};

// Per-operation context
struct alignas(64) IOCPContext {
    OVERLAPPED overlap;
    IOCPOpType opType;
    TCPConnection* connection;
    WSABUF buffer;
    uint8_t data[256];  // Small buffer for accepts
    
    IOCPContext(IOCPOpType type) : opType(type), connection(nullptr) {
        memset(&overlap, 0, sizeof(overlap));
    }
};

// ============================================================================
// TCP Transport Implementation
// ============================================================================
class TCPTransport : public FabricTransport {
public:
    TCPTransport();
    ~TCPTransport() override;
    
    // FabricTransport interface
    bool Initialize(uint32_t nodeId) override;
    void Shutdown() override;
    
    bool ConnectToNode(uint32_t nodeId, const char* address) override;
    void DisconnectNode(uint32_t nodeId) override;
    bool IsConnected(uint32_t nodeId) override;
    
    bool Send(uint32_t dstNodeId, const FabricMessage& msg) override;
    bool Broadcast(const FabricMessage& msg) override;
    
    void SetMessageHandler(MessageHandler handler) override;
    void SetErrorHandler(ErrorHandler handler) override;
    
    uint64_t GetBytesSent() const override;
    uint64_t GetBytesReceived() const override;
    uint64_t GetMessagesSent() const override;
    uint64_t GetMessagesReceived() const override;
    uint32_t GetLatencyUs() const override;
    
    const char* GetTransportName() const override { return "TCP"; }
    
    // TCP-specific
    bool Listen(const char* bindAddress, uint16_t port);
    bool SetNagle(bool enabled);  // false = disable Nagle for low latency
    bool SetBufferSizes(int sendSize, int recvSize);
    
private:
    uint32_t localNodeId_;
    bool initialized_;
    bool shutdown_;
    
    // Winsock
    WSADATA wsaData_;
    
    // IOCP
    HANDLE hIOCP_;
    
    // Listening socket (for server mode)
    SOCKET listenSocket_;
    uint16_t listenPort_;
    
    // Connections
    std::unordered_map<uint32_t, std::unique_ptr<TCPConnection>> connections_;
    std::shared_mutex connectionsMutex_;
    
    // Worker threads
    std::vector<HANDLE> workerThreads_;
    static constexpr int NUM_WORKERS = 4;
    static DWORD WINAPI WorkerThreadProc(LPVOID param);
    void WorkerLoop();
    
    // Accept thread
    HANDLE hAcceptThread_;
    static DWORD WINAPI AcceptThreadProc(LPVOID param);
    void AcceptLoop();
    
    // Connection management
    bool PostAccept();
    bool PostReceive(TCPConnection* conn);
    bool PostSend(TCPConnection* conn, const FabricMessage& msg);
    void OnAcceptComplete(IOCPContext* ctx, DWORD bytes);
    void OnReceiveComplete(IOCPContext* ctx, DWORD bytes);
    void OnSendComplete(IOCPContext* ctx, DWORD bytes);
    void OnConnectComplete(IOCPContext* ctx, DWORD bytes);
    void CloseConnection(TCPConnection* conn);
    
    // Statistics
    alignas(64) std::atomic<uint64_t> bytesSent_{0};
    alignas(64) std::atomic<uint64_t> bytesReceived_{0};
    alignas(64) std::atomic<uint64_t> messagesSent_{0};
    alignas(64) std::atomic<uint64_t> messagesReceived_{0};
    alignas(64) std::atomic<uint64_t> totalLatencyUs_{0};
    alignas(64) std::atomic<uint64_t> latencyCount_{0};
    
    // Handlers
    MessageHandler messageHandler_;
    ErrorHandler errorHandler_;
    
    // Sequence counter
    std::atomic<uint32_t> sequenceCounter_{0};
    
    // Helper
    uint32_t CalculateCRC32(const void* data, size_t len);
    uint64_t GetTimestampUs() const;
};

// Factory function
FabricTransport* CreateTCPTransport();

} // namespace Fabric
} // namespace RawrXD
