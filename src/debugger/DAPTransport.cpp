// DAPTransport.cpp
// Phase 25: DAP Adapter - Transport Implementation
// ============================================================================

#include "DAPTransport.h"
#include <sstream>
#include <iomanip>
#include <memory>

namespace RawrXD {
namespace DAP {

// ============================================================================
// Implementation
// ============================================================================
class DAPTransport::Impl {
public:
    DAPTransportConfig config_;
    MessageCallback messageCallback_;
    ErrorCallback errorCallback_;
    bool initialized_ = false;
    
    std::string readBuffer_;
    size_t expectedLength_ = 0;
    bool readingHeader_ = true;
};

DAPTransport::DAPTransport() : pImpl_(std::make_unique<Impl>()) {}
DAPTransport::~DAPTransport() = default;

bool DAPTransport::Initialize(const DAPTransportConfig& config) {
    pImpl_->config_ = config;
    
    // Use stdin/stdout if not provided
    if (!pImpl_->config_.hInput) {
        pImpl_->config_.hInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    if (!pImpl_->config_.hOutput) {
        pImpl_->config_.hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    }
    
    // Set stdin to non-blocking mode for polling
    DWORD mode = 0;
    if (GetConsoleMode(pImpl_->config_.hInput, &mode)) {
        mode &= ~ENABLE_LINE_INPUT;
        mode &= ~ENABLE_ECHO_INPUT;
        SetConsoleMode(pImpl_->config_.hInput, mode);
    }
    
    pImpl_->initialized_ = true;
    return true;
}

void DAPTransport::Shutdown() {
    pImpl_->initialized_ = false;
}

// ============================================================================
// Message Formatting (Content-Length protocol)
// ============================================================================
std::string DAPTransport::CreateMessage(const std::string& json) {
    std::ostringstream oss;
    oss << "Content-Length: " << json.length() << "\r\n\r\n" << json;
    return oss.str();
}

bool DAPTransport::ParseHeader(const std::string& header, size_t& outLength) {
    // Parse "Content-Length: XXX\r\n"
    const std::string prefix = "Content-Length: ";
    auto pos = header.find(prefix);
    if (pos == std::string::npos) {
        return false;
    }
    
    auto endPos = header.find("\r\n", pos + prefix.length());
    if (endPos == std::string::npos) {
        return false;
    }
    
    try {
        outLength = std::stoull(header.substr(pos + prefix.length(), 
                                               endPos - pos - prefix.length()));
        return true;
    } catch (...) {
        return false;
    }
}

// ============================================================================
// Send Message
// ============================================================================
bool DAPTransport::SendMessage(const std::string& json) {
    return SendMessage(json.c_str(), json.length());
}

bool DAPTransport::SendMessage(const char* json, size_t length) {
    if (!pImpl_->initialized_) return false;
    
    // Format with Content-Length header
    std::string message = CreateMessage(std::string(json, length));
    
    // Write to stdout
    DWORD written = 0;
    BOOL result = WriteFile(pImpl_->config_.hOutput, 
                            message.c_str(), 
                            static_cast<DWORD>(message.length()), 
                            &written, 
                            nullptr);
    
    return result && written == message.length();
}

// ============================================================================
// Read Message (Blocking)
// ============================================================================
std::string DAPTransport::ReadMessage() {
    std::string result;
    ReadMessage(result);
    return result;
}

bool DAPTransport::ReadMessage(std::string& outJson) {
    if (!pImpl_->initialized_) return false;
    
    // Read header line
    std::string header;
    char ch;
    DWORD read = 0;
    
    // Read until we get \r\n\r\n (end of header + blank line)
    while (true) {
        if (!ReadFile(pImpl_->config_.hInput, &ch, 1, &read, nullptr) || read == 0) {
            return false;
        }
        
        header += ch;
        
        // Check for end of header (\r\n\r\n)
        if (header.length() >= 4 && 
            header.substr(header.length() - 4) == "\r\n\r\n") {
            break;
        }
        
        // Prevent infinite growth
        if (header.length() > 1024) {
            return false;
        }
    }
    
    // Parse Content-Length
    size_t contentLength = 0;
    if (!ParseHeader(header, contentLength)) {
        return false;
    }
    
    // Read JSON payload
    outJson.resize(contentLength);
    size_t totalRead = 0;
    
    while (totalRead < contentLength) {
        if (!ReadFile(pImpl_->config_.hInput, 
                      &outJson[totalRead], 
                      static_cast<DWORD>(contentLength - totalRead), 
                      &read, 
                      nullptr)) {
            return false;
        }
        if (read == 0) {
            return false;
        }
        totalRead += read;
    }
    
    return true;
}

// ============================================================================
// Event-Driven Mode
// ============================================================================
void DAPTransport::SetMessageCallback(MessageCallback callback) {
    pImpl_->messageCallback_ = callback;
}

void DAPTransport::SetErrorCallback(ErrorCallback callback) {
    pImpl_->errorCallback_ = callback;
}

void DAPTransport::Poll() {
    if (!pImpl_->initialized_) return;
    
    // Check if data available
    DWORD available = 0;
    if (!PeekNamedPipe(pImpl_->config_.hInput, nullptr, 0, nullptr, &available, nullptr)) {
        return;
    }
    
    if (available == 0) return;
    
    // Try to read a complete message
    std::string message;
    if (ReadMessage(message)) {
        if (pImpl_->messageCallback_) {
            pImpl_->messageCallback_(message);
        }
    }
}

bool DAPTransport::IsInitialized() const {
    return pImpl_->initialized_;
}

// ============================================================================
// Global Access
// ============================================================================
static std::unique_ptr<DAPTransport> g_dapTransport;

DAPTransport* GetDAPTransport() {
    return g_dapTransport.get();
}

bool InitializeDAPTransport() {
    g_dapTransport = std::make_unique<DAPTransport>();
    DAPTransportConfig config;
    return g_dapTransport->Initialize(config);
}

void ShutdownDAPTransport() {
    if (g_dapTransport) {
        g_dapTransport->Shutdown();
        g_dapTransport.reset();
    }
}

} // namespace DAP
} // namespace RawrXD
