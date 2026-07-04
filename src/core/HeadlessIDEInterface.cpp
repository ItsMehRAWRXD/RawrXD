#include "HeadlessIDEInterface.hpp"
#include "SharedSessionLayout.hpp"
#include "Version.hpp"
#include <cstdio>
#include <cstring>

namespace RawrXD {

HeadlessIDEInterface::HeadlessIDEInterface() noexcept
    : m_session(nullptr)
    , m_eventBus(nullptr)
    , m_initialized(false)
    , m_eventCallback(nullptr)
    , m_activeBufferIndex(static_cast<size_t>(-1))
{
}

HeadlessIDEInterface::~HeadlessIDEInterface() {
    Shutdown();
}

IDEResult HeadlessIDEInterface::Initialize() {
    if (m_initialized) {
        return IDEResult::Success;
    }
    
    // Create session state
    m_session = new (std::nothrow) UnifiedSessionState();
    if (!m_session) {
        return IDEResult::ErrorBusy;
    }
    
    // Initialize shared memory (create if doesn't exist)
    if (!m_session->Initialize(true)) {
        delete m_session;
        m_session = nullptr;
        return IDEResult::ErrorDisconnected;
    }
    
    // Create event bus
    m_eventBus = new (std::nothrow) IDEEventBus();
    if (!m_eventBus) {
        Shutdown();
        return IDEResult::ErrorBusy;
    }
    
    if (!m_eventBus->Initialize(m_session)) {
        Shutdown();
        return IDEResult::ErrorDisconnected;
    }
    
    // Subscribe to events
    m_eventBus->SubscribeAll([this](const SharedEventFrame& frame) {
        OnEvent(frame);
    });
    
    m_initialized = true;
    
    // Set as global interface
    if (!GetGlobalIDEInterface()) {
        SetGlobalIDEInterface(this);
    }
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::Shutdown() {
    if (GetGlobalIDEInterface() == this) {
        SetGlobalIDEInterface(nullptr);
    }
    
    if (m_eventBus) {
        m_eventBus->Shutdown();
        delete m_eventBus;
        m_eventBus = nullptr;
    }
    
    if (m_session) {
        m_session->Shutdown();
        delete m_session;
        m_session = nullptr;
    }
    
    m_buffers.clear();
    m_activeBufferIndex = static_cast<size_t>(-1);
    m_initialized = false;
    
    return IDEResult::Success;
}

bool HeadlessIDEInterface::IsReady() const {
    return m_initialized && m_session && m_session->IsInitialized();
}

// File Operations

IDEResult HeadlessIDEInterface::OpenFile(const wchar_t* filePath, BufferHandle* outBuffer) {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    if (!filePath || !outBuffer) return IDEResult::ErrorInvalidArgument;
    
    // Create new buffer
    BufferData data;
    data.path = filePath;
    data.modified = false;
    
    // Try to load file content
    FILE* file = nullptr;
    if (_wfopen_s(&file, filePath, L"rb") == 0 && file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);
        
        if (size > 0) {
            data.content.resize(size);
            fread(data.content.data(), 1, size, file);
        }
        fclose(file);
    }
    
    m_buffers.push_back(std::move(data));
    size_t index = m_buffers.size() - 1;
    *outBuffer = reinterpret_cast<BufferHandle>(index + 1); // 1-based index
    
    m_activeBufferIndex = index;
    
    // Update session state
    m_session->SetActiveFilePath(filePath);
    m_eventBus->PublishFileChanged(std::string(filePath, filePath + wcslen(filePath)));
    
    // Output to stdout
    wprintf(L"[Headless] Opened file: %s\n", filePath);
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::CloseFile(BufferHandle buffer) {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    
    size_t index = reinterpret_cast<size_t>(buffer) - 1;
    if (index >= m_buffers.size()) return IDEResult::ErrorNotFound;
    
    wprintf(L"[Headless] Closed file: %s\n", m_buffers[index].path.c_str());
    
    // Mark as closed (don't erase to keep indices valid)
    m_buffers[index].path.clear();
    m_buffers[index].content.clear();
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::GetActiveFile(wchar_t* outPath, size_t maxLen) {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    if (!outPath || maxLen == 0) return IDEResult::ErrorInvalidArgument;
    
    auto path = m_session->GetActiveFilePath();
    if (path.empty()) {
        outPath[0] = L'\0';
        return IDEResult::ErrorNotFound;
    }
    
    wcsncpy_s(outPath, maxLen, path.c_str(), _TRUNCATE);
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::SetActiveFile(const wchar_t* filePath) {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    if (!filePath) return IDEResult::ErrorInvalidArgument;
    
    m_session->SetActiveFilePath(filePath);
    m_eventBus->PublishFileChanged(std::string(filePath, filePath + wcslen(filePath)));
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::GetFileInfo(const wchar_t* filePath, FileInfo* outInfo) {
    if (!filePath || !outInfo) return IDEResult::ErrorInvalidArgument;
    
    WIN32_FILE_ATTRIBUTE_DATA attrs;
    if (!GetFileAttributesExW(filePath, GetFileExInfoStandard, &attrs)) {
        return IDEResult::ErrorNotFound;
    }
    
    outInfo->path = filePath;
    outInfo->size = (static_cast<uint64_t>(attrs.nFileSizeHigh) << 32) | attrs.nFileSizeLow;
    outInfo->modifiedTime = (static_cast<uint64_t>(attrs.ftLastWriteTime.dwHighDateTime) << 32) 
                           | attrs.ftLastWriteTime.dwLowDateTime;
    outInfo->isDirectory = (attrs.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    outInfo->isReadOnly = (attrs.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0;
    
    return IDEResult::Success;
}

// Buffer Operations

IDEResult HeadlessIDEInterface::GetBufferContent(BufferHandle buffer, char* outData, size_t* inOutLen) {
    if (!inOutLen) return IDEResult::ErrorInvalidArgument;
    
    size_t index = reinterpret_cast<size_t>(buffer) - 1;
    if (index >= m_buffers.size()) return IDEResult::ErrorNotFound;
    
    const auto& data = m_buffers[index];
    size_t toCopy = std::min(data.content.size(), *inOutLen);
    
    if (outData && toCopy > 0) {
        memcpy(outData, data.content.data(), toCopy);
    }
    
    *inOutLen = data.content.size();
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::SetBufferContent(BufferHandle buffer, const char* data, size_t len) {
    if (!data) return IDEResult::ErrorInvalidArgument;
    
    size_t index = reinterpret_cast<size_t>(buffer) - 1;
    if (index >= m_buffers.size()) return IDEResult::ErrorNotFound;
    
    m_buffers[index].content.assign(data, len);
    m_buffers[index].modified = true;
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::GetBufferLength(BufferHandle buffer, size_t* outLen) {
    if (!outLen) return IDEResult::ErrorInvalidArgument;
    
    size_t index = reinterpret_cast<size_t>(buffer) - 1;
    if (index >= m_buffers.size()) return IDEResult::ErrorNotFound;
    
    *outLen = m_buffers[index].content.size();
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::InsertText(BufferHandle buffer, TextPosition pos, const char* text) {
    // Simplified implementation
    return IDEResult::ErrorNotImplemented;
}

IDEResult HeadlessIDEInterface::DeleteText(BufferHandle buffer, TextRange range) {
    // Simplified implementation
    return IDEResult::ErrorNotImplemented;
}

IDEResult HeadlessIDEInterface::GetTextRange(BufferHandle buffer, TextRange range, char* outData, size_t* inOutLen) {
    // Simplified implementation
    return IDEResult::ErrorNotImplemented;
}

// Command Execution

IDEResult HeadlessIDEInterface::ExecuteCommand(const char* command, const char* args, char* outResult, size_t* inOutLen) {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    if (!command) return IDEResult::ErrorInvalidArgument;
    
    wprintf(L"[Headless] Executing command: %hs", command);
    if (args) {
        wprintf(L" %hs", args);
    }
    wprintf(L"\n");
    
    // Publish command executed event
    if (m_eventBus) {
        m_eventBus->PublishCommandExecuted(command);
    }
    
    // Return success
    if (outResult && inOutLen && *inOutLen > 0) {
        const char* msg = "Command executed";
        size_t len = strlen(msg);
        if (*inOutLen > len) {
            strcpy_s(outResult, *inOutLen, msg);
        }
        *inOutLen = len;
    }
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::ExecuteCommandAsync(const char* command, const char* args, CommandCallback callback) {
    // For headless, execute synchronously and call callback
    char result[256];
    size_t resultLen = sizeof(result);
    IDEResult status = ExecuteCommand(command, args, result, &resultLen);
    
    if (callback) {
        callback(result, status);
    }
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::DispatchEvent(EventType type, const void* data, size_t dataSize) {
    if (!IsReady() || !m_eventBus) return IDEResult::ErrorDisconnected;
    
    std::string_view payload(static_cast<const char*>(data), dataSize);
    m_eventBus->Publish(type, payload);
    
    return IDEResult::Success;
}

// Event Subscription

IDEResult HeadlessIDEInterface::SubscribeEvents(IDEEventCallback callback) {
    m_eventCallback = callback;
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::UnsubscribeEvents() {
    m_eventCallback = nullptr;
    return IDEResult::Success;
}

void HeadlessIDEInterface::OnEvent(const SharedEventFrame& frame) {
    if (m_eventCallback) {
        m_eventCallback(static_cast<EventType>(frame.eventType), 
                       frame.payload, frame.payloadLength);
    }
}

// Model Management

IDEResult HeadlessIDEInterface::LoadModel(const char* modelPath, const char* options) {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    if (!modelPath) return IDEResult::ErrorInvalidArgument;
    
    wprintf(L"[Headless] Loading model: %hs\n", modelPath);
    
    // Update session state
    m_session->SetActiveModel(modelPath, 0);
    m_eventBus->PublishModelLoaded(modelPath);
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::UnloadModel() {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    
    wprintf(L"[Headless] Unloading model\n");
    
    m_session->SetActiveModel("", 0);
    m_eventBus->PublishModelUnloaded();
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::GetModelStatus(char* outStatus, size_t* inOutLen) {
    if (!IsReady() || !outStatus || !inOutLen) return IDEResult::ErrorInvalidArgument;
    
    auto hash = m_session->GetActiveModelHash();
    if (hash.empty()) {
        const char* msg = "No model loaded";
        if (*inOutLen > strlen(msg)) {
            strcpy_s(outStatus, *inOutLen, msg);
        }
        *inOutLen = strlen(msg);
    } else {
        std::string status = "Model: " + hash;
        if (*inOutLen > status.length()) {
            strcpy_s(outStatus, *inOutLen, status.c_str());
        }
        *inOutLen = status.length();
    }
    
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::ExecuteInference(const char* prompt, char* outResult, size_t* inOutLen) {
    if (!IsReady()) return IDEResult::ErrorDisconnected;
    if (!prompt) return IDEResult::ErrorInvalidArgument;
    
    wprintf(L"[Headless] Inference prompt: %hs\n", prompt);
    
    // Stub response
    const char* response = "[Inference result would appear here]";
    if (outResult && inOutLen && *inOutLen > strlen(response)) {
        strcpy_s(outResult, *inOutLen, response);
    }
    if (inOutLen) {
        *inOutLen = strlen(response);
    }
    
    return IDEResult::Success;
}

// UI Operations

IDEResult HeadlessIDEInterface::ShowMessage(const wchar_t* title, const wchar_t* message, uint32_t flags) {
    // In headless mode, print to stdout
    wprintf(L"[Message: %s] %s\n", title ? title : L"", message ? message : L"");
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::SetStatusText(const wchar_t* text) {
    // In headless mode, print to stderr
    fwprintf(stderr, L"[Status] %s\n", text ? text : L"");
    return IDEResult::Success;
}

IDEResult HeadlessIDEInterface::ShowWindow(bool show) {
    // No-op in headless mode
    return IDEResult::Success;
}

// Version/Protocol

uint32_t HeadlessIDEInterface::GetVersion() const {
    return GetVersionPacked();
}

uint32_t HeadlessIDEInterface::GetProtocolVersion() const {
    return RawrXD::GetProtocolVersion();
}

bool HeadlessIDEInterface::IsProtocolCompatible(uint32_t otherVersion) const {
    return otherVersion == GetProtocolVersion();
}

// Factory function
IIDEInterface* CreateHeadlessIDEInterface() noexcept {
    return new (std::nothrow) HeadlessIDEInterface();
}

} // namespace RawrXD
