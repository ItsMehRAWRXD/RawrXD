// NodeManager.cpp - Phase 9, Batch 1: IOCP-based Swarm Node Manager
// Zero-dependency, bare-metal RPC layer for RawrXD distributed inference

#include "RawrXD_RPC.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <vector>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

namespace RawrXD {
namespace Distributed {

// Maximum nodes in the swarm ring
constexpr uint16_t MAX_SWARM_NODES = 64;
constexpr uint16_t DEFAULT_DISCOVERY_PORT = 31337;
constexpr uint32_t IOCP_WORKER_THREADS = 4;
constexpr uint32_t RECV_BUFFER_SIZE = 65536; // 64KB for tensor chunks

// Per-node state in the ring
struct NodeState {
    uint16_t nodeId;
    uint32_t ipAddress;
    uint16_t port;
    std::atomic<uint64_t> lastHeartbeat;
    std::atomic<bool> isActive;
    uint32_t capabilities; // Bitmask: GPU type, memory, etc.
};

// IOCP context for overlapped operations
struct PerIoData {
    OVERLAPPED overlapped;
    WSABUF wsaBuf;
    char buffer[RECV_BUFFER_SIZE];
    DWORD bytesTransferred;
    DWORD flags;
    sockaddr_in clientAddr;
    int clientAddrLen;
    bool isRecv;
};

class NodeManager {
private:
    SOCKET udpSocket;
    HANDLE iocpHandle;
    std::vector<HANDLE> workerThreads;
    std::vector<NodeState> nodeRing;
    std::atomic<bool> isRunning;
    std::atomic<uint16_t> localNodeId;
    uint16_t listenPort;

    // Worker thread pool for IOCP
    static DWORD WINAPI IocpWorkerThread(LPVOID param) {
        NodeManager* manager = static_cast<NodeManager*>(param);
        return manager->ProcessIocpEvents();
    }

    DWORD ProcessIocpEvents() {
        DWORD bytesTransferred;
        ULONG_PTR completionKey;
        LPOVERLAPPED overlapped;

        while (isRunning.load()) {
            BOOL result = GetQueuedCompletionStatus(
                iocpHandle,
                &bytesTransferred,
                &completionKey,
                &overlapped,
                INFINITE
            );

            if (!result) {
                DWORD error = GetLastError();
                if (error == ERROR_ABANDONED_WAIT_0) {
                    break; // IOCP closed
                }
                // Handle error but continue
                continue;
            }

            if (completionKey == 0 && overlapped == nullptr) {
                // Shutdown signal
                break;
            }

            PerIoData* ioData = CONTAINING_RECORD(overlapped, PerIoData, overlapped);
            
            if (ioData->isRecv) {
                // Process received packet
                ProcessPacket(ioData, bytesTransferred);
                
                // Re-post receive
                PostRecv(ioData);
            } else {
                // Send completed - cleanup
                delete ioData;
            }
        }

        return 0;
    }

    void ProcessPacket(PerIoData* ioData, DWORD bytesTransferred) {
        if (bytesTransferred < sizeof(RawrPacket)) {
            return; // Packet too small
        }

        RawrPacket* packet = reinterpret_cast<RawrPacket*>(ioData->buffer);
        
        // Validate magic
        if (packet->magic != 0x5241575258443031ULL) { // 'RAWRXD01' in little-endian
            return; // Invalid magic
        }

        // Route by command
        switch (packet->cmd) {
            case CMD_NODE_DISCOVER:
                HandleNodeDiscover(packet, &ioData->clientAddr);
                break;
            case CMD_NODE_ACKNOWLEDGE:
                HandleNodeAcknowledge(packet);
                break;
            case CMD_HEARTBEAT_PING:
                HandleHeartbeatPing(packet, &ioData->clientAddr);
                break;
            case CMD_HEARTBEAT_PONG:
                HandleHeartbeatPong(packet);
                break;
            case CMD_INFERENCE_REQ:
                HandleInferenceRequest(packet);
                break;
            case CMD_TENSOR_XFER_CHUNK:
                HandleTensorChunk(packet, ioData->buffer + sizeof(RawrPacket), 
                                  bytesTransferred - sizeof(RawrPacket));
                break;
            case CMD_PANIC_ABORT:
                HandlePanicAbort(packet);
                break;
            default:
                // Unknown command - log and ignore
                break;
        }
    }

    void HandleNodeDiscover(RawrPacket* packet, sockaddr_in* sender) {
        // Send acknowledgment back
        RawrPacket ack = {};
        ack.magic = 0x5241575258443031ULL; // 'RAWRXD01'
        ack.cmd = CMD_NODE_ACKNOWLEDGE;
        ack.seq = packet->seq;
        ack.len = 0;
        ack.flags = FLAG_SYNC;
        ack.node_id = localNodeId.load();

        SendPacket(&ack, sender);
        
        // Add to ring if new
        RegisterNode(packet->node_id, sender);
    }

    void HandleNodeAcknowledge(RawrPacket* packet) {
        // Update node as acknowledged
        for (auto& node : nodeRing) {
            if (node.nodeId == packet->node_id) {
                node.isActive.store(true);
                node.lastHeartbeat.store(GetTickCount64());
                break;
            }
        }
    }

    void HandleHeartbeatPing(RawrPacket* packet, sockaddr_in* sender) {
        // Send pong response
        RawrPacket pong = {};
        pong.magic = 0x5241575258443031ULL;
        pong.cmd = CMD_HEARTBEAT_PONG;
        pong.seq = packet->seq;
        pong.len = 0;
        pong.flags = FLAG_ASYNC;
        pong.node_id = localNodeId.load();

        SendPacket(&pong, sender);
    }

    void HandleHeartbeatPong(RawrPacket* packet) {
        // Update last seen for the node
        for (auto& node : nodeRing) {
            if (node.nodeId == packet->node_id) {
                node.lastHeartbeat.store(GetTickCount64());
                break;
            }
        }
    }

    void HandleInferenceRequest(RawrPacket* packet) {
        // Queue inference work - would integrate with inference engine
        // For now, just acknowledge
        RawrPacket ack = {};
        ack.magic = 0x5241575258443031ULL;
        ack.cmd = CMD_INFERENCE_ACK;
        ack.seq = packet->seq;
        ack.len = 0;
        ack.flags = FLAG_SYNC;
        ack.node_id = localNodeId.load();

        // Find requesting node and send ACK
        for (const auto& node : nodeRing) {
            if (node.nodeId == packet->node_id && node.isActive.load()) {
                sockaddr_in addr = {};
                addr.sin_family = AF_INET;
                addr.sin_addr.s_addr = node.ipAddress;
                addr.sin_port = htons(node.port);
                SendPacket(&ack, &addr);
                break;
            }
        }
    }

    void HandleTensorChunk(RawrPacket* packet, char* payload, DWORD payloadLen) {
        // Zero-copy: payload points directly into the IOCP buffer
        // In production, this would DMA to GPU VRAM or pin for RDMA
        
        if (packet->flags & FLAG_BARRIER) {
            // Synchronous barrier - wait for all chunks
            // Implementation would track partial receives
        }
        
        // Acknowledge receipt if SYNC flag set
        if (packet->flags & FLAG_SYNC) {
            RawrPacket ack = {};
            ack.magic = 0x5241575258443031ULL;
            ack.cmd = CMD_TENSOR_XFER_CHUNK;
            ack.seq = packet->seq;
            ack.len = 0;
            ack.flags = FLAG_ASYNC;
            ack.node_id = localNodeId.load();

            for (const auto& node : nodeRing) {
                if (node.nodeId == packet->node_id && node.isActive.load()) {
                    sockaddr_in addr = {};
                    addr.sin_family = AF_INET;
                    addr.sin_addr.s_addr = node.ipAddress;
                    addr.sin_port = htons(node.port);
                    SendPacket(&ack, &addr);
                    break;
                }
            }
        }
    }

    void HandlePanicAbort(RawrPacket* packet) {
        // Emergency shutdown - stop all operations
        isRunning.store(false);
        
        // Signal all worker threads to exit
        for (size_t i = 0; i < workerThreads.size(); i++) {
            PostQueuedCompletionStatus(iocpHandle, 0, 0, nullptr);
        }
    }

    void RegisterNode(uint16_t nodeId, sockaddr_in* addr) {
        for (auto& node : nodeRing) {
            if (node.nodeId == nodeId) {
                // Update existing
                node.ipAddress = addr->sin_addr.s_addr;
                node.port = ntohs(addr->sin_port);
                node.isActive.store(true);
                node.lastHeartbeat.store(GetTickCount64());
                return;
            }
        }
        
        // Add new node if space available
        for (auto& node : nodeRing) {
            if (!node.isActive.load()) {
                node.nodeId = nodeId;
                node.ipAddress = addr->sin_addr.s_addr;
                node.port = ntohs(addr->sin_port);
                node.isActive.store(true);
                node.lastHeartbeat.store(GetTickCount64());
                node.capabilities = 0; // Would be populated from discovery
                break;
            }
        }
    }

    bool PostRecv(PerIoData* ioData) {
        ioData->isRecv = true;
        ioData->wsaBuf.buf = ioData->buffer;
        ioData->wsaBuf.len = RECV_BUFFER_SIZE;
        ioData->clientAddrLen = sizeof(sockaddr_in);
        ioData->flags = 0;
        
        ZeroMemory(&ioData->overlapped, sizeof(OVERLAPPED));

        DWORD bytesRecv = 0;
        DWORD flags = 0;
        
        int result = WSARecvFrom(
            udpSocket,
            &ioData->wsaBuf,
            1,
            &bytesRecv,
            &flags,
            reinterpret_cast<sockaddr*>(&ioData->clientAddr),
            &ioData->clientAddrLen,
            &ioData->overlapped,
            nullptr
        );

        if (result == SOCKET_ERROR) {
            DWORD error = WSAGetLastError();
            if (error != WSA_IO_PENDING) {
                return false;
            }
        }

        return true;
    }

    void SendPacket(RawrPacket* packet, sockaddr_in* dest) {
        PerIoData* ioData = new PerIoData();
        ZeroMemory(&ioData->overlapped, sizeof(OVERLAPPED));
        ioData->isRecv = false;
        
        memcpy(ioData->buffer, packet, sizeof(RawrPacket));
        ioData->wsaBuf.buf = ioData->buffer;
        ioData->wsaBuf.len = sizeof(RawrPacket);

        WSASendTo(
            udpSocket,
            &ioData->wsaBuf,
            1,
            nullptr,
            0,
            reinterpret_cast<sockaddr*>(dest),
            sizeof(sockaddr_in),
            &ioData->overlapped,
            nullptr
        );
    }

public:
    NodeManager() : udpSocket(INVALID_SOCKET), iocpHandle(nullptr), 
                    isRunning(false), localNodeId(0), listenPort(0) {
        nodeRing.resize(MAX_SWARM_NODES);
    }

    ~NodeManager() {
        Shutdown();
    }

    bool Initialize(uint16_t nodeId, uint16_t port = DEFAULT_DISCOVERY_PORT) {
        // Initialize Winsock
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            return false;
        }

        localNodeId.store(nodeId);
        listenPort = port;

        // Create UDP socket
        udpSocket = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                               nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (udpSocket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }

        // Bind to port
        sockaddr_in bindAddr = {};
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_addr.s_addr = INADDR_ANY;
        bindAddr.sin_port = htons(port);

        if (bind(udpSocket, reinterpret_cast<sockaddr*>(&bindAddr), 
                 sizeof(bindAddr)) == SOCKET_ERROR) {
            closesocket(udpSocket);
            WSACleanup();
            return false;
        }

        // Create IOCP
        iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 
                                            IOCP_WORKER_THREADS);
        if (iocpHandle == nullptr) {
            closesocket(udpSocket);
            WSACleanup();
            return false;
        }

        // Associate socket with IOCP
        if (CreateIoCompletionPort(reinterpret_cast<HANDLE>(udpSocket), 
                                   iocpHandle, 1, 0) == nullptr) {
            CloseHandle(iocpHandle);
            closesocket(udpSocket);
            WSACleanup();
            return false;
        }

        // Start worker threads
        isRunning.store(true);
        for (uint32_t i = 0; i < IOCP_WORKER_THREADS; i++) {
            HANDLE thread = CreateThread(nullptr, 0, IocpWorkerThread, this, 0, nullptr);
            if (thread) {
                workerThreads.push_back(thread);
            }
        }

        // Post initial receives
        for (uint32_t i = 0; i < IOCP_WORKER_THREADS * 2; i++) {
            PerIoData* ioData = new PerIoData();
            if (!PostRecv(ioData)) {
                delete ioData;
            }
        }

        return true;
    }

    void Shutdown() {
        if (!isRunning.exchange(false)) {
            return;
        }

        // Signal shutdown
        for (size_t i = 0; i < workerThreads.size(); i++) {
            PostQueuedCompletionStatus(iocpHandle, 0, 0, nullptr);
        }

        // Wait for workers
        WaitForMultipleObjects(static_cast<DWORD>(workerThreads.size()), 
                               workerThreads.data(), TRUE, 5000);

        // Cleanup
        for (auto& handle : workerThreads) {
            CloseHandle(handle);
        }
        workerThreads.clear();

        if (iocpHandle) {
            CloseHandle(iocpHandle);
            iocpHandle = nullptr;
        }

        if (udpSocket != INVALID_SOCKET) {
            closesocket(udpSocket);
            udpSocket = INVALID_SOCKET;
        }

        WSACleanup();
    }

    bool BroadcastDiscovery() {
        // Broadcast discovery packet to local subnet
        RawrPacket packet = {};
        packet.magic = 0x5241575258443031ULL; // 'RAWRXD01'
        packet.cmd = CMD_NODE_DISCOVER;
        packet.seq = 0;
        packet.len = 0;
        packet.flags = FLAG_ASYNC;
        packet.node_id = localNodeId.load();

        sockaddr_in broadcastAddr = {};
        broadcastAddr.sin_family = AF_INET;
        broadcastAddr.sin_addr.s_addr = INADDR_BROADCAST;
        broadcastAddr.sin_port = htons(listenPort);

        SendPacket(&packet, &broadcastAddr);
        return true;
    }

    size_t GetActiveNodeCount() const {
        size_t count = 0;
        for (const auto& node : nodeRing) {
            if (node.isActive.load()) {
                count++;
            }
        }
        return count;
    }

    uint16_t GetLocalNodeId() const {
        return localNodeId.load();
    }
};

} // namespace Distributed
} // namespace RawrXD

// Simple test main
#ifdef RAWRXD_NODE_MANAGER_TEST
int main() {
    using namespace RawrXD::Distributed;
    
    printf("RawrXD NodeManager - Phase 9 Test\n");
    printf("==================================\n\n");

    NodeManager manager;
    
    if (!manager.Initialize(1, 31337)) {
        printf("Failed to initialize NodeManager\n");
        return 1;
    }

    printf("✓ NodeManager initialized (Node ID: %d)\n", manager.GetLocalNodeId());
    printf("✓ Listening on port 31337\n");
    printf("✓ IOCP with %d worker threads\n", IOCP_WORKER_THREADS);
    
    printf("\nBroadcasting discovery...\n");
    manager.BroadcastDiscovery();
    
    printf("Running for 10 seconds...\n");
    Sleep(10000);
    
    printf("\nActive nodes discovered: %zu\n", manager.GetActiveNodeCount());
    
    printf("\nShutting down...\n");
    manager.Shutdown();
    
    printf("✓ Test complete\n");
    return 0;
}
#endif
