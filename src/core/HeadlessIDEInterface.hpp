#pragma once
#include "IIDEInterface.hpp"
#include "SharedSessionLayout.hpp"
#include "UnifiedSessionState.hpp"
#include "IDEEventBus.hpp"
#include <vector>
#include <string>

namespace RawrXD {

// Headless IDE Interface Implementation
// Routes all operations through shared memory and stdout/stderr
class HeadlessIDEInterface : public IIDEInterface {
public:
    HeadlessIDEInterface() noexcept;
    virtual ~HeadlessIDEInterface();

    // Disable copy/move
    HeadlessIDEInterface(const HeadlessIDEInterface&) = delete;
    HeadlessIDEInterface& operator=(const HeadlessIDEInterface&) = delete;
    HeadlessIDEInterface(HeadlessIDEInterface&&) = delete;
    HeadlessIDEInterface& operator=(HeadlessIDEInterface&&) = delete;

    // --- IIDEInterface Implementation ---
    
    IDEResult Initialize() override;
    IDEResult Shutdown() override;
    bool IsReady() const override;
    uint32_t GetInterfaceType() const override { return 3; } // Headless

    // File Operations
    IDEResult OpenFile(const wchar_t* filePath, BufferHandle* outBuffer) override;
    IDEResult CloseFile(BufferHandle buffer) override;
    IDEResult GetActiveFile(wchar_t* outPath, size_t maxLen) override;
    IDEResult SetActiveFile(const wchar_t* filePath) override;
    IDEResult GetFileInfo(const wchar_t* filePath, FileInfo* outInfo) override;

    // Buffer Operations
    IDEResult GetBufferContent(BufferHandle buffer, char* outData, size_t* inOutLen) override;
    IDEResult SetBufferContent(BufferHandle buffer, const char* data, size_t len) override;
    IDEResult GetBufferLength(BufferHandle buffer, size_t* outLen) override;
    IDEResult InsertText(BufferHandle buffer, TextPosition pos, const char* text) override;
    IDEResult DeleteText(BufferHandle buffer, TextRange range) override;
    IDEResult GetTextRange(BufferHandle buffer, TextRange range, char* outData, size_t* inOutLen) override;

    // Command Execution
    IDEResult ExecuteCommand(const char* command, const char* args, char* outResult, size_t* inOutLen) override;
    IDEResult ExecuteCommandAsync(const char* command, const char* args, CommandCallback callback) override;
    IDEResult DispatchEvent(EventType type, const void* data, size_t dataSize) override;

    // Event Subscription
    IDEResult SubscribeEvents(IDEEventCallback callback) override;
    IDEResult UnsubscribeEvents() override;

    // Model Management
    IDEResult LoadModel(const char* modelPath, const char* options) override;
    IDEResult UnloadModel() override;
    IDEResult GetModelStatus(char* outStatus, size_t* inOutLen) override;
    IDEResult ExecuteInference(const char* prompt, char* outResult, size_t* inOutLen) override;

    // UI Operations (redirected to stdout/stderr)
    IDEResult ShowMessage(const wchar_t* title, const wchar_t* message, uint32_t flags) override;
    IDEResult SetStatusText(const wchar_t* text) override;
    IDEResult ShowWindow(bool show) override;
    bool IsWindowVisible() const override { return true; }

    // Version/Protocol
    uint32_t GetVersion() const override;
    uint32_t GetProtocolVersion() const override;
    bool IsProtocolCompatible(uint32_t otherVersion) const override;

private:
    UnifiedSessionState* m_session;
    IDEEventBus* m_eventBus;
    bool m_initialized;
    IDEEventCallback m_eventCallback;
    
    // Simple buffer storage for headless mode
    struct BufferData {
        std::wstring path;
        std::string content;
        bool modified;
    };
    std::vector<BufferData> m_buffers;
    size_t m_activeBufferIndex;
    
    void OnEvent(const SharedEventFrame& frame);
};

} // namespace RawrXD
