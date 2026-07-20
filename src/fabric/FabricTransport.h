#pragma once

#include "FabricMessages.h"
#include <cstdint>
#include <functional>

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Transport Callback Types
// ============================================================================
using MessageHandler = std::function<void(const FabricMessage& msg, uint32_t fromNode)>;
using ErrorHandler = std::function<void(uint32_t nodeId, const char* error)>;

// ============================================================================
// Fabric Transport Interface
// Abstract base for all transport implementations
// ============================================================================
class FabricTransport {
public:
    virtual ~FabricTransport() = default;
    
    // Lifecycle
    virtual bool Initialize(uint32_t nodeId) = 0;
    virtual void Shutdown() = 0;
    
    // Connection Management
    virtual bool ConnectToNode(uint32_t nodeId, const char* address) = 0;
    virtual void DisconnectNode(uint32_t nodeId) = 0;
    virtual bool IsConnected(uint32_t nodeId) = 0;
    
    // Messaging
    virtual bool Send(uint32_t dstNodeId, const FabricMessage& msg) = 0;
    virtual bool Broadcast(const FabricMessage& msg) = 0;
    
    // Configuration
    virtual void SetMessageHandler(MessageHandler handler) = 0;
    virtual void SetErrorHandler(ErrorHandler handler) = 0;
    
    // Statistics
    virtual uint64_t GetBytesSent() const = 0;
    virtual uint64_t GetBytesReceived() const = 0;
    virtual uint64_t GetMessagesSent() const = 0;
    virtual uint64_t GetMessagesReceived() const = 0;
    virtual uint32_t GetLatencyUs() const = 0;  // Average round-trip
    
    // Transport identification
    virtual const char* GetTransportName() const = 0;
};

// Factory function declarations
FabricTransport* CreateLoopbackTransport();
FabricTransport* CreateTCPTransport();

} // namespace Fabric
} // namespace RawrXD
