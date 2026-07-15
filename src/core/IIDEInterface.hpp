#pragma once
#include <string_view>
#include <functional>
#include <stdint.h>

namespace RawrXD {

// Forward declarations
struct SharedEventFrame;
enum class EventType : uint32_t;

// Result codes for IDE operations
enum class IDEResult : int32_t {
    Success = 0,
    ErrorNotImplemented = -1,
    ErrorInvalidArgument = -2,
    ErrorNotFound = -3,
    ErrorPermissionDenied = -4,
    ErrorBusy = -5,
    ErrorDisconnected = -6,
    ErrorProtocolMismatch = -7
};

// Buffer handle (opaque)
using BufferHandle = void*;

// Text position (line, column)
struct TextPosition {
    uint32_t line;
    uint32_t column;
};

// Text range
struct TextRange {
    TextPosition start;
    TextPosition end;
};

// File information
struct FileInfo {
    const wchar_t* path;
    uint64_t size;
    uint64_t modifiedTime;
    bool isDirectory;
    bool isReadOnly;
};

// Command result callback
using CommandCallback = std::function<void(const char* result, IDEResult status)>;

// Event callback
using IDEEventCallback = std::function<void(EventType type, const void* data, size_t dataSize)>;

// ============================================================================
// IIDEInterface - Pure Virtual Interface for IDE Abstraction
// ============================================================================
// This interface decouples the ExtensionHost from HWND/GUI dependencies,
// allowing extensions to work in CLI, GUI, and Headless modes.
//
// Implementations:
//   - Win32IDEInterface    : GUI mode with window handles
//   - HeadlessIDEInterface : Pipes/TCP for headless server
//   - MockIDEInterface     : Testing/simulation
// ============================================================================

struct IIDEInterface {
    // --- Lifecycle ---
    
    // Initialize the interface
    virtual IDEResult Initialize() = 0;
    
    // Shutdown and cleanup
    virtual IDEResult Shutdown() = 0;
    
    // Check if interface is ready
    virtual bool IsReady() const = 0;
    
    // Get interface type (GUI=1, CLI=2, Headless=3, Mock=4)
    virtual uint32_t GetInterfaceType() const = 0;

    // --- File Operations ---
    
    // Open file in IDE
    virtual IDEResult OpenFile(const wchar_t* filePath, BufferHandle* outBuffer) = 0;
    
    // Close file
    virtual IDEResult CloseFile(BufferHandle buffer) = 0;
    
    // Get active file
    virtual IDEResult GetActiveFile(wchar_t* outPath, size_t maxLen) = 0;
    
    // Set active file
    virtual IDEResult SetActiveFile(const wchar_t* filePath) = 0;
    
    // Get file info
    virtual IDEResult GetFileInfo(const wchar_t* filePath, FileInfo* outInfo) = 0;

    // --- Buffer Operations ---
    
    // Get buffer content
    virtual IDEResult GetBufferContent(BufferHandle buffer, char* outData, size_t* inOutLen) = 0;
    
    // Set buffer content
    virtual IDEResult SetBufferContent(BufferHandle buffer, const char* data, size_t len) = 0;
    
    // Get buffer length
    virtual IDEResult GetBufferLength(BufferHandle buffer, size_t* outLen) = 0;
    
    // Insert text at position
    virtual IDEResult InsertText(BufferHandle buffer, TextPosition pos, const char* text) = 0;
    
    // Delete text range
    virtual IDEResult DeleteText(BufferHandle buffer, TextRange range) = 0;
    
    // Get text range
    virtual IDEResult GetTextRange(BufferHandle buffer, TextRange range, char* outData, size_t* inOutLen) = 0;

    // --- Command Execution ---
    
    // Execute IDE command
    virtual IDEResult ExecuteCommand(const char* command, const char* args, char* outResult, size_t* inOutLen) = 0;
    
    // Execute command async (with callback)
    virtual IDEResult ExecuteCommandAsync(const char* command, const char* args, CommandCallback callback) = 0;
    
    // Dispatch raw event (for extensions to trigger IDE actions)
    virtual IDEResult DispatchEvent(EventType type, const void* data, size_t dataSize) = 0;

    // --- Event Subscription ---
    
    // Subscribe to IDE events
    virtual IDEResult SubscribeEvents(IDEEventCallback callback) = 0;
    
    // Unsubscribe from events
    virtual IDEResult UnsubscribeEvents() = 0;

    // --- Model Management ---
    
    // Load model
    virtual IDEResult LoadModel(const char* modelPath, const char* options) = 0;
    
    // Unload current model
    virtual IDEResult UnloadModel() = 0;
    
    // Get model status
    virtual IDEResult GetModelStatus(char* outStatus, size_t* inOutLen) = 0;
    
    // Execute inference
    virtual IDEResult ExecuteInference(const char* prompt, char* outResult, size_t* inOutLen) = 0;

    // --- UI Operations (GUI only) ---
    
    // Show message box (GUI) or print to stdout (CLI/Headless)
    virtual IDEResult ShowMessage(const wchar_t* title, const wchar_t* message, uint32_t flags) = 0;
    
    // Set status bar text (GUI) or print to stderr (CLI/Headless)
    virtual IDEResult SetStatusText(const wchar_t* text) = 0;
    
    // Show/hide window (GUI only, no-op in CLI/Headless)
    virtual IDEResult ShowWindow(bool show) = 0;
    
    // Get window visibility (always true in CLI/Headless)
    virtual bool IsWindowVisible() const = 0;

    // --- Version/Protocol ---
    
    // Get interface version
    virtual uint32_t GetVersion() const = 0;
    
    // Get protocol version
    virtual uint32_t GetProtocolVersion() const = 0;
    
    // Check protocol compatibility
    virtual bool IsProtocolCompatible(uint32_t otherVersion) const = 0;

    // Virtual destructor
    virtual ~IIDEInterface() = default;
};

// Interface factory functions
IIDEInterface* CreateWin32IDEInterface() noexcept;
IIDEInterface* CreateHeadlessIDEInterface() noexcept;
IIDEInterface* CreateMockIDEInterface() noexcept;

// Global interface accessor
IIDEInterface* GetGlobalIDEInterface() noexcept;
void SetGlobalIDEInterface(IIDEInterface* iface) noexcept;

} // namespace RawrXD
