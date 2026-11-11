#include "SecureTransport.h"
#include <iostream>
#include <sstream>
#include <iomanip>

namespace RawrXD {
namespace Fabric {

// TLS 1.3 protocol flags
static const DWORD TLS1_3_PROTOCOL = SP_PROT_TLS1_3_SERVER | SP_PROT_TLS1_3_CLIENT;

// ============================================================================
// SecureTransport Implementation
// ============================================================================

SecureTransport::SecureTransport()
    : localNodeId_(0)
    , initialized_(false)
    , shutdown_(false)
    , haveServerCreds_(false)
    , haveClientCreds_(false)
    , messageHandler_(nullptr)
    , errorHandler_(nullptr) {
    memset(&serverCredHandle_, 0, sizeof(serverCredHandle_));
    memset(&clientCredHandle_, 0, sizeof(clientCredHandle_));
}

SecureTransport::~SecureTransport() {
    Shutdown();
}

bool SecureTransport::Configure(const SecurityConfig& config) {
    config_ = config;
    return true;
}

bool SecureTransport::Initialize(uint32_t nodeId) {
    if (initialized_) {
        return false;
    }
    
    localNodeId_ = nodeId;
    
    // Initialize underlying TCP transport
    tcpTransport_ = std::make_unique<TCPTransport>();
    if (!tcpTransport_->Initialize(nodeId)) {
        return false;
    }
    
    // Set up TCP handlers
    tcpTransport_->SetMessageHandler(
        [this](const FabricMessage& msg, uint32_t fromNode) {
            OnTCPMessage(msg, fromNode);
        }
    );
    
    tcpTransport_->SetErrorHandler(
        [this](uint32_t nodeId, const char* error) {
            OnTCPError(nodeId, error);
        }
    );
    
    // Initialize TLS credentials
    if (config_.authMode == AuthMode::CERTIFICATE) {
        if (!InitializeCredentials()) {
            return false;
        }
    }
    
    initialized_ = true;
    return true;
}

void SecureTransport::Shutdown() {
    if (!initialized_) {
        return;
    }
    
    shutdown_ = true;
    
    // Clean up all security contexts
    {
        std::unique_lock<std::shared_mutex> lock(contextsMutex_);
        for (auto& [nodeId, ctx] : contexts_) {
            if (ctx) {
                CleanupContext(ctx.get());
            }
        }
        contexts_.clear();
    }
    
    // Free credentials
    if (haveServerCreds_) {
        FreeCredentialsHandle(&serverCredHandle_);
        haveServerCreds_ = false;
    }
    if (haveClientCreds_) {
        FreeCredentialsHandle(&clientCredHandle_);
        haveClientCreds_ = false;
    }
    
    // Shutdown TCP transport
    if (tcpTransport_) {
        tcpTransport_->Shutdown();
        tcpTransport_.reset();
    }
    
    initialized_ = false;
}

bool SecureTransport::ConnectToNode(uint32_t nodeId, const char* address) {
    if (!initialized_ || !tcpTransport_) {
        return false;
    }
    
    // Connect underlying TCP
    if (!tcpTransport_->ConnectToNode(nodeId, address)) {
        return false;
    }
    
    // Create security context
    auto ctx = std::make_unique<SecureContext>();
    
    // Perform TLS handshake as client
    if (config_.authMode == AuthMode::CERTIFICATE) {
        if (!PerformHandshake(nodeId, ctx.get(), false)) {
            tcpTransport_->DisconnectNode(nodeId);
            return false;
        }
    }
    
    // Store context
    {
        std::unique_lock<std::shared_mutex> lock(contextsMutex_);
        contexts_[nodeId] = std::move(ctx);
    }
    
    return true;
}

void SecureTransport::DisconnectNode(uint32_t nodeId) {
    // Clean up security context
    {
        std::unique_lock<std::shared_mutex> lock(contextsMutex_);
        auto it = contexts_.find(nodeId);
        if (it != contexts_.end() && it->second) {
            CleanupContext(it->second.get());
            contexts_.erase(it);
        }
    }
    
    // Disconnect TCP
    if (tcpTransport_) {
        tcpTransport_->DisconnectNode(nodeId);
    }
}

bool SecureTransport::IsConnected(uint32_t nodeId) {
    if (!tcpTransport_) {
        return false;
    }
    
    return tcpTransport_->IsConnected(nodeId);
}

bool SecureTransport::Send(uint32_t dstNodeId, const FabricMessage& msg) {
    if (!initialized_ || !tcpTransport_) {
        return false;
    }
    
    // Get security context
    SecureContext* ctx = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(contextsMutex_);
        auto it = contexts_.find(dstNodeId);
        if (it != contexts_.end()) {
            ctx = it->second.get();
        }
    }
    
    // Prepare message
    FabricMessage msgCopy = msg;
    msgCopy.header.srcNodeId = localNodeId_;
    msgCopy.header.dstNodeId = dstNodeId;
    msgCopy.header.timestamp = GetTickCount64() * 1000;
    
    // Encrypt if TLS enabled
    if (ctx && ctx->encrypting) {
        std::vector<uint8_t> encrypted;
        if (!EncryptMessage(ctx, &msgCopy, sizeof(msgCopy), encrypted)) {
            if (errorHandler_) {
                errorHandler_(dstNodeId, "Encryption failed");
            }
            return false;
        }
        
        // Send encrypted data via TCP
        // Note: This requires TCPTransport to support raw byte sends
        // For now, we use the message-based interface
    }
    
    // Send via TCP
    bool sent = tcpTransport_->Send(dstNodeId, msgCopy);
    if (sent) {
        messagesSent_.fetch_add(1, std::memory_order_relaxed);
        bytesSent_.fetch_add(sizeof(msgCopy), std::memory_order_relaxed);
    }
    
    return sent;
}

bool SecureTransport::Broadcast(const FabricMessage& msg) {
    if (!tcpTransport_) {
        return false;
    }
    
    return tcpTransport_->Broadcast(msg);
}

void SecureTransport::SetMessageHandler(MessageHandler handler) {
    messageHandler_ = handler;
}

void SecureTransport::SetErrorHandler(ErrorHandler handler) {
    errorHandler_ = handler;
}

uint64_t SecureTransport::GetBytesSent() const {
    return bytesSent_.load(std::memory_order_relaxed);
}

uint64_t SecureTransport::GetBytesReceived() const {
    return bytesReceived_.load(std::memory_order_relaxed);
}

uint64_t SecureTransport::GetMessagesSent() const {
    return messagesSent_.load(std::memory_order_relaxed);
}

uint64_t SecureTransport::GetMessagesReceived() const {
    return messagesReceived_.load(std::memory_order_relaxed);
}

uint32_t SecureTransport::GetLatencyUs() const {
    if (!tcpTransport_) {
        return 0;
    }
    return tcpTransport_->GetLatencyUs();
}

bool SecureTransport::IsSecure(uint32_t nodeId) const {
    std::shared_lock<std::shared_mutex> lock(contextsMutex_);
    
    auto it = contexts_.find(nodeId);
    if (it == contexts_.end() || !it->second) {
        return false;
    }
    
    return it->second->handshakeComplete;
}

std::string SecureTransport::GetPeerIdentity(uint32_t nodeId) const {
    // In production: extract from peer certificate
    return "node-" + std::to_string(nodeId);
}

bool SecureTransport::RotateCertificate(const std::string& newThumbprint) {
    // Update configuration
    config_.certThumbprint = newThumbprint;
    
    // Re-initialize credentials
    if (haveServerCreds_) {
        FreeCredentialsHandle(&serverCredHandle_);
        haveServerCreds_ = false;
    }
    if (haveClientCreds_) {
        FreeCredentialsHandle(&clientCredHandle_);
        haveClientCreds_ = false;
    }
    
    return InitializeCredentials();
}

// ============================================================================
// Security Operations
// ============================================================================

bool SecureTransport::InitializeCredentials() {
    SCHANNEL_CRED schannelCred;
    memset(&schannelCred, 0, sizeof(schannelCred));
    schannelCred.dwVersion = SCHANNEL_CRED_VERSION;
    
    // Protocols
    if (config_.tls13Only) {
        schannelCred.grbitEnabledProtocols = SP_PROT_TLS1_3;
    } else {
        schannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2 | SP_PROT_TLS1_3;
    }
    
    // Certificate
    PCCERT_CONTEXT cert = FindCertificate(config_.certThumbprint);
    if (!cert) {
        return false;
    }
    
    schannelCred.cCreds = 1;
    schannelCred.paCred = &cert;
    
    // Flags
    schannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    if (config_.mutualAuth) {
        schannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }
    
    // Acquire server credentials
    SECURITY_STATUS status = AcquireCredentialsHandle(
        nullptr,                  // Principal
        UNISP_NAME,               // Package
        SECPKG_CRED_INBOUND,      // Server
        nullptr,                  // Logon ID
        &schannelCred,            // Auth data
        nullptr, nullptr,         // Get key function
        &serverCredHandle_,       // Handle
        nullptr                   // Expiry
    );
    
    if (status != SEC_E_OK) {
        CertFreeCertificateContext(cert);
        return false;
    }
    haveServerCreds_ = true;
    
    // Acquire client credentials
    status = AcquireCredentialsHandle(
        nullptr,
        UNISP_NAME,
        SECPKG_CRED_OUTBOUND,     // Client
        nullptr,
        &schannelCred,
        nullptr, nullptr,
        &clientCredHandle_,
        nullptr
    );
    
    CertFreeCertificateContext(cert);
    
    if (status != SEC_E_OK) {
        FreeCredentialsHandle(&serverCredHandle_);
        haveServerCreds_ = false;
        return false;
    }
    haveClientCreds_ = true;
    
    return true;
}

bool SecureTransport::PerformHandshake(uint32_t nodeId, SecureContext* ctx, bool asServer) {
    // Simplified handshake - production would do full TLS handshake
    // with proper token exchange
    
    ctx->handshakeComplete = true;
    ctx->encrypting = true;
    
    return true;
}

bool SecureTransport::EncryptMessage(SecureContext* ctx, const void* data, size_t len,
                                     std::vector<uint8_t>& output) {
    if (!ctx || !ctx->encrypting) {
        return false;
    }
    
    // In production: use EncryptMessage API
    // For now: just copy (placeholder)
    output.resize(len);
    memcpy(output.data(), data, len);
    
    return true;
}

bool SecureTransport::DecryptMessage(SecureContext* ctx, const void* data, size_t len,
                                     std::vector<uint8_t>& output) {
    if (!ctx) {
        return false;
    }
    
    // In production: use DecryptMessage API
    output.resize(len);
    memcpy(output.data(), data, len);
    
    return true;
}

void SecureTransport::CleanupContext(SecureContext* ctx) {
    if (!ctx) return;
    
    if (ctx->initialized) {
        DeleteSecurityContext(&ctx->contextHandle);
    }
    
    ctx->initialized = false;
    ctx->handshakeComplete = false;
    ctx->encrypting = false;
}

PCCERT_CONTEXT SecureTransport::FindCertificate(const std::string& thumbprint) {
    // Open certificate store
    HCERTSTORE store = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY"
    );
    
    if (!store) {
        return nullptr;
    }
    
    // Convert thumbprint to binary
    std::vector<uint8_t> thumbprintBin;
    for (size_t i = 0; i < thumbprint.length(); i += 2) {
        std::string byte = thumbprint.substr(i, 2);
        uint8_t val = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
        thumbprintBin.push_back(val);
    }
    
    // Find certificate
    PCCERT_CONTEXT cert = CertFindCertificateInStore(
        store,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_HASH,
        thumbprintBin.data(),
        nullptr
    );
    
    CertCloseStore(store, 0);
    return cert;
}

bool SecureTransport::VerifyCertificate(PCCERT_CONTEXT cert) {
    // In production: validate chain, expiration, etc.
    return cert != nullptr;
}

// ============================================================================
// Message Handling
// ============================================================================

void SecureTransport::OnTCPMessage(const FabricMessage& msg, uint32_t fromNode) {
    messagesReceived_.fetch_add(1, std::memory_order_relaxed);
    bytesReceived_.fetch_add(sizeof(msg), std::memory_order_relaxed);
    
    // Decrypt if needed
    SecureContext* ctx = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(contextsMutex_);
        auto it = contexts_.find(fromNode);
        if (it != contexts_.end()) {
            ctx = it->second.get();
        }
    }
    
    FabricMessage decrypted = msg;
    if (ctx && ctx->encrypting) {
        std::vector<uint8_t> plaintext;
        if (!DecryptMessage(ctx, &msg, sizeof(msg), plaintext)) {
            if (errorHandler_) {
                errorHandler_(fromNode, "Decryption failed");
            }
            return;
        }
        if (plaintext.size() >= sizeof(FabricMessage)) {
            memcpy(&decrypted, plaintext.data(), sizeof(FabricMessage));
        }
    }
    
    // Deliver to handler
    if (messageHandler_) {
        messageHandler_(decrypted, fromNode);
    }
}

void SecureTransport::OnTCPError(uint32_t nodeId, const char* error) {
    if (errorHandler_) {
        errorHandler_(nodeId, error);
    }
}

// Factory function
FabricTransport* CreateSecureTransport() {
    return new SecureTransport();
}

} // namespace Fabric
} // namespace RawrXD
