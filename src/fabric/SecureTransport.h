#pragma once

#include "FabricTransport.h"
#include "TCPTransport.h"
#include <Windows.h>
#include <Schannel.h>
#include <security.h>
#include <sspi.h>

#pragma comment(lib, "secur32.lib")

namespace RawrXD {
namespace Fabric {

// ============================================================================
// Secure Transport - TLS 1.3 Encrypted Fabric Communication
// 
// Wraps TCPTransport with TLS encryption using Windows Schannel.
// Provides certificate-based authentication and encrypted transport.
// ============================================================================

enum class AuthMode {
    NONE = 0,           // No authentication (testing only)
    CERTIFICATE = 1,    // X.509 certificate authentication
    TOKEN = 2           // Pre-shared token authentication
};

struct SecurityConfig {
    AuthMode authMode = AuthMode::CERTIFICATE;
    std::string certThumbprint;     // Certificate to use
    std::string caStore = "ROOT";   // CA trust store
    bool verifyPeer = true;         // Require valid peer cert
    bool mutualAuth = true;         // Require client certificates
    
    // Cipher suites (TLS 1.3)
    bool tls13Only = true;          // Enforce TLS 1.3
    bool disableCompression = true; // CRIME attack prevention
};

struct SecureContext {
    CredHandle credHandle;
    CtxtHandle contextHandle;
    SecPkgContext_StreamSizes streamSizes;
    
    // Buffers
    std::vector<uint8_t> readBuffer;
    std::vector<uint8_t> writeBuffer;
    std::vector<uint8_t> decryptBuffer;
    
    // State
    bool initialized = false;
    bool handshakeComplete = false;
    bool encrypting = false;
};

// ============================================================================
// Secure Transport Implementation
// ============================================================================
class SecureTransport : public FabricTransport {
public:
    SecureTransport();
    ~SecureTransport() override;
    
    // Configuration
    bool Configure(const SecurityConfig& config);
    
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
    
    const char* GetTransportName() const override { return "TLS"; }
    
    // Security-specific
    bool IsSecure(uint32_t nodeId) const;
    std::string GetPeerIdentity(uint32_t nodeId) const;
    bool RotateCertificate(const std::string& newThumbprint);
    
private:
    uint32_t localNodeId_;
    bool initialized_;
    bool shutdown_;
    
    SecurityConfig config_;
    
    // Underlying TCP transport
    std::unique_ptr<TCPTransport> tcpTransport_;
    
    // Security contexts per connection
    mutable std::shared_mutex contextsMutex_;
    std::unordered_map<uint32_t, std::unique_ptr<SecureContext>> contexts_;
    
    // SSPI handles
    CredHandle serverCredHandle_;
    CredHandle clientCredHandle_;
    bool haveServerCreds_;
    bool haveClientCreds_;
    
    // Handlers
    MessageHandler messageHandler_;
    ErrorHandler errorHandler_;
    
    // Statistics
    alignas(64) std::atomic<uint64_t> bytesSent_{0};
    alignas(64) std::atomic<uint64_t> bytesReceived_{0};
    alignas(64) std::atomic<uint64_t> messagesSent_{0};
    alignas(64) std::atomic<uint64_t> messagesReceived_{0};
    
    // Security operations
    bool InitializeCredentials();
    bool PerformHandshake(uint32_t nodeId, SecureContext* ctx, bool asServer);
    bool EncryptMessage(SecureContext* ctx, const void* data, size_t len, 
                        std::vector<uint8_t>& output);
    bool DecryptMessage(SecureContext* ctx, const void* data, size_t len,
                        std::vector<uint8_t>& output);
    void CleanupContext(SecureContext* ctx);
    
    // Certificate helpers
    PCCERT_CONTEXT FindCertificate(const std::string& thumbprint);
    bool VerifyCertificate(PCCERT_CONTEXT cert);
    
    // Message handling wrapper
    void OnTCPMessage(const FabricMessage& msg, uint32_t fromNode);
    void OnTCPError(uint32_t nodeId, const char* error);
};

// Factory function
FabricTransport* CreateSecureTransport();

} // namespace Fabric
} // namespace RawrXD
