// ============================================================================
// AWSBedrockClient.hpp — Native Win32 AWS Bedrock Client with Schannel TLS
// ============================================================================
//
// Purpose: Direct AWS Bedrock integration without Node.js/Python overhead
//
// Architecture:
//   - WinSock2 + Schannel/SSPI for native TLS (no OpenSSL)
//   - AWS SigV4 request signing (HMAC-SHA256)
//   - Async worker thread for network I/O
//   - Shared memory bridge to IDE main thread
//
// Pattern: Zero-copy where possible, lock-free shared memory
// Threading: Network worker thread + IDE UI thread
// ============================================================================

#pragma once

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <schannel.h>
#include <security.h>
#include <sspi.h>
#include <string>
#include <vector>
#include <atomic>
#include <functional>
#include <memory>

// Link with required libraries
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")

namespace RawrXD {
namespace AWS {

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

class SigV4Signer;
class SchannelTLS;
struct BedrockRequest;
struct BedrockResponse;

// ============================================================================
// CONFIGURATION
// ============================================================================

struct AWSConfig {
    std::string accessKeyId;
    std::string secretAccessKey;
    std::string sessionToken;      // Optional for STS
    std::string region = "us-east-1";
    std::string service = "bedrock-runtime";
    std::string modelId = "anthropic.claude-3-5-sonnet-20241022-v2:0";
    
    // Endpoint configuration
    std::string GetEndpoint() const {
        return "bedrock-runtime." + region + ".amazonaws.com";
    }
    
    // Validate configuration
    bool IsValid() const {
        return !accessKeyId.empty() && !secretAccessKey.empty();
    }
};

// ============================================================================
// EXECUTION PROVENANCE
// ============================================================================

enum class ExecutionMode {
    LocalCPU = 0,
    LocalGPU = 1,
    RemoteAWS = 2,
    QAgent = 3
};

struct ExecutionProvenance {
    ExecutionMode mode;
    uint64_t requestId;
    uint64_t timestamp;
    std::string backendEndpoint;
    std::string modelId;
    bool authenticated;
};

// ============================================================================
// BEDROCK REQUEST/RESPONSE
// ============================================================================

struct Message {
    std::string role;    // "user", "assistant", "system"
    std::string content;
};

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string inputSchema;  // JSON schema
};

struct BedrockRequest {
    std::string modelId;
    std::vector<Message> messages;
    std::vector<ToolDefinition> tools;
    float temperature = 0.7f;
    int maxTokens = 4096;
    std::string systemPrompt;
    
    // Serialize to JSON for Bedrock InvokeModel API
    std::string ToJson() const;
};

struct BedrockResponse {
    bool success;
    std::string errorMessage;
    std::string content;
    std::string stopReason;
    uint32_t inputTokens;
    uint32_t outputTokens;
    
    // Tool use detection
    bool HasToolUse() const;
    std::string GetToolName() const;
    std::string GetToolInput() const;
};

// ============================================================================
// AWS BEDROCK CLIENT
// ============================================================================

class AWSBedrockClient {
public:
    // Callback types
    using ResponseCallback = std::function<void(const BedrockResponse&)>;
    using StreamCallback = std::function<void(const std::string& chunk)>;
    using ToolCallCallback = std::function<std::string(const std::string& toolName, const std::string& toolInput)>;
    
    AWSBedrockClient();
    ~AWSBedrockClient();
    
    // Initialization
    bool Initialize(const AWSConfig& config);
    void Shutdown();
    
    // Synchronous request (blocking)
    BedrockResponse InvokeModel(const BedrockRequest& request);
    
    // Asynchronous request (non-blocking, uses callback)
    bool InvokeModelAsync(const BedrockRequest& request, ResponseCallback callback);
    
    // Streaming request (for real-time completions)
    bool InvokeModelStream(const BedrockRequest& request, StreamCallback chunkCallback);
    
    // Tool-enabled conversation loop
    bool RunAgentLoop(const BedrockRequest& initialRequest, 
                      ToolCallCallback toolHandler,
                      ResponseCallback finalResponseCallback);
    
    // Connection state
    bool IsConnected() const { return m_connected.load(); }
    const ExecutionProvenance& GetLastProvenance() const { return m_lastProvenance; }
    
    // Shared memory integration
    void SetSharedMemoryBridge(class SovereignSharedMemoryServer* bridge);
    
private:
    // Implementation details
    class Impl;
    std::unique_ptr<Impl> m_impl;
    
    std::atomic<bool> m_connected{false};
    std::atomic<bool> m_initialized{false};
    ExecutionProvenance m_lastProvenance;
    AWSConfig m_config;
};

// ============================================================================
// SIGV4 SIGNER
// ============================================================================

class SigV4Signer {
public:
    SigV4Signer(const AWSConfig& config);
    
    // Sign an HTTP request
    struct SignedRequest {
        std::string method;
        std::string uri;
        std::vector<std::pair<std::string, std::string>> headers;
        std::string body;
        std::string authorizationHeader;
    };
    
    SignedRequest SignRequest(
        const std::string& method,
        const std::string& uri,
        const std::vector<std::pair<std::string, std::string>>& queryParams,
        const std::string& body,
        const std::string& timestamp = ""  // ISO8601 format, auto-generated if empty
    );
    
private:
    AWSConfig m_config;
    
    // SigV4 implementation helpers
    std::string GetCredentialScope(const std::string& dateStamp) const;
    std::string CalculateSignature(const std::string& stringToSign, const std::string& dateStamp) const;
    std::string GetSignatureKey(const std::string& dateStamp) const;
    std::string Sha256Hash(const std::string& data) const;
    std::string HmacSha256(const std::string& key, const std::string& data) const;
    std::string HexEncode(const std::vector<uint8_t>& data) const;
};

// ============================================================================
// SCHANNEL TLS WRAPPER
// ============================================================================

class SchannelTLS {
public:
    SchannelTLS();
    ~SchannelTLS();
    
    bool Connect(const std::string& hostname, uint16_t port);
    void Disconnect();
    
    bool Send(const void* data, size_t len);
    bool Send(const std::string& data) { return Send(data.data(), data.length()); }
    
    // Receive with timeout (milliseconds)
    int Receive(void* buffer, size_t maxLen, DWORD timeoutMs = 5000);
    
    bool IsConnected() const { return m_connected; }
    
private:
    SOCKET m_socket{INVALID_SOCKET};
    CredHandle m_hCreds;
    CtxtHandle m_hContext;
    bool m_connected{false};
    bool m_initialized{false};
    
    // Schannel buffers
    SecPkgContext_StreamSizes m_streamSizes;
    std::vector<uint8_t> m_readBuffer;
    size_t m_readBufferOffset{0};
    
    bool PerformHandshake(const std::string& hostname);
    bool EncryptSend(const void* data, size_t len);
    int DecryptReceive(void* buffer, size_t maxLen);
};

// ============================================================================
// SHARED MEMORY BRIDGE
// ============================================================================

class AWSBedrockSharedMemoryBridge {
public:
    struct SharedBuffer {
        static constexpr size_t BUFFER_SIZE = 256 * 1024;  // 256KB chunks
        
        std::atomic<uint64_t> sequenceId{0};
        std::atomic<uint32_t> dataLength{0};
        std::atomic<uint32_t> flags{0};  // Bit 0: new data, Bit 1: complete, Bit 2: error
        std::atomic<uint64_t> timestamp{0};
        
        char data[BUFFER_SIZE];
        
        // Flag constants
        static constexpr uint32_t FLAG_NEW_DATA = 0x01;
        static constexpr uint32_t FLAG_COMPLETE = 0x02;
        static constexpr uint32_t FLAG_ERROR = 0x04;
        static constexpr uint32_t FLAG_TOOL_CALL = 0x08;
    };
    
    AWSBedrockSharedMemoryBridge();
    ~AWSBedrockSharedMemoryBridge();
    
    bool Initialize(const std::string& segmentName);
    void Shutdown();
    
    // Producer (network thread) writes
    bool WriteChunk(const std::string& data, bool isComplete = false, bool isError = false);
    bool WriteToolCall(const std::string& toolName, const std::string& toolInput);
    
    // Consumer (IDE thread) reads
    bool ReadChunk(std::string& outData, bool& outComplete, bool& outError);
    bool PollForData(DWORD timeoutMs = 100);
    
    // Execution mode tracking
    void SetExecutionMode(ExecutionMode mode);
    ExecutionMode GetExecutionMode() const;
    
private:
    HANDLE m_hMapFile{nullptr};
    SharedBuffer* m_pBuffer{nullptr};
    uint64_t m_lastSequenceId{0};
    std::atomic<ExecutionMode> m_executionMode{ExecutionMode::LocalCPU};
};

// ============================================================================
// WORKER THREAD
// ============================================================================

class AWSBedrockWorker {
public:
    using RequestQueue = std::vector<std::pair<BedrockRequest, AWSBedrockClient::ResponseCallback>>;
    
    AWSBedrockWorker();
    ~AWSBedrockWorker();
    
    bool Start(const AWSConfig& config);
    void Stop();
    
    // Queue a request for async processing
    bool QueueRequest(const BedrockRequest& request, AWSBedrockClient::ResponseCallback callback);
    
    // Check if worker is running
    bool IsRunning() const { return m_running.load(); }
    
    // Set shared memory bridge for zero-copy output
    void SetSharedMemoryBridge(AWSBedrockSharedMemoryBridge* bridge);
    
private:
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_stopRequested{false};
    HANDLE m_hThread{nullptr};
    AWSConfig m_config;
    AWSBedrockSharedMemoryBridge* m_bridge{nullptr};
    
    // Request queue synchronization
    CRITICAL_SECTION m_queueLock;
    HANDLE m_hQueueEvent{nullptr};
    RequestQueue m_requestQueue;
    
    static DWORD WINAPI WorkerThreadProc(LPVOID param);
    void ProcessRequests();
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

namespace Utils {
    // Get current UTC timestamp in ISO8601 format (YYYYMMDD'T'HHMMSS'Z')
    std::string GetAmzDate();
    std::string GetDateStamp();
    
    // SHA256 hashing
    std::string Sha256Hex(const std::string& data);
    
    // HMAC-SHA256
    std::string HmacSha256Hex(const std::string& key, const std::string& data);
    
    // Trim whitespace
    std::string Trim(const std::string& str);
    
    // URI encoding for SigV4
    std::string UriEncode(const std::string& value, bool encodeSlash = false);
}

} // namespace AWS
} // namespace RawrXD
