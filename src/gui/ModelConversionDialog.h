// ============================================================================
// ModelConversionDialog.h — Pure Win32 Native Model Conversion Dialog
// ============================================================================
// Dialog for model quantization conversion. Detects unsupported quantization
// types and orchestrates conversion via external script. Shows real-time
// progress, terminal output monitoring, ETA, and auto-verification.
//
// Pattern: C-style extern "C" API + OOP internal
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================
#pragma once

<<<<<<< HEAD
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

// ============================================================================
// Result codes
// ============================================================================
enum class ConversionResult {
    Cancelled,
    ConversionSucceeded,
    ConversionFailed
};

// ============================================================================
// ConversionConfig — passed into the dialog
// ============================================================================
struct ConversionConfig {
    const wchar_t* unsupportedTypes[16];   // Null-terminated array of type names
    int             unsupportedCount;
    wchar_t         recommendedType[64];
    wchar_t         modelPath[MAX_PATH];
};

// ============================================================================
// Class: ModelConversionDialog
// ============================================================================
class ModelConversionDialog {
public:
    explicit ModelConversionDialog(HWND parent, const ConversionConfig& cfg);
    ~ModelConversionDialog();

    // Show modal — returns ConversionResult
    ConversionResult showModal();

    // Public getters
    const wchar_t* convertedPath() const { return m_convertedPath; }

private:
    // Window management
    static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
    void registerClass(HINSTANCE hInst);
    void createControls(HWND hwnd);

    // Paint
    void paint(HDC hdc, const RECT& rc);
    void paintHeader(HDC hdc, int x, int y, int w);
    void paintProgressBar(HDC hdc, int x, int y, int w, int h);
    void paintOutputLog(HDC hdc, int x, int y, int w, int h);

    // Conversion logic
    void startConversion();
    void cancelConversion();
    void pollProcess();
    void parseOutputLine(const char* line);
    void updateProgressFromChunks(int current, int total);
    bool verifyConvertedModel();
    void logConversionHistory(bool success, DWORD durationMs);

    // Append to output log
    void appendOutput(const wchar_t* text, COLORREF color = 0);

    // Timer callback
    static void CALLBACK timerProc(HWND hwnd, UINT, UINT_PTR, DWORD);

    // Instance data
    HWND        m_hwnd            = nullptr;
    HWND        m_parent          = nullptr;
    HINSTANCE   m_hInst           = nullptr;
    HFONT       m_fontTitle       = nullptr;
    HFONT       m_fontBody        = nullptr;
    HFONT       m_fontMono        = nullptr;
    HDC         m_backDC          = nullptr;
    HBITMAP     m_backBuf         = nullptr;
    int         m_bufW = 0, m_bufH = 0;
    UINT_PTR    m_timerId         = 0;

    // Buttons
    HWND m_btnConvert       = nullptr;
    HWND m_btnCancel        = nullptr;
    HWND m_btnCancelConvert = nullptr;
    HWND m_btnMoreInfo      = nullptr;

    // Process
    HANDLE m_hProcess    = nullptr;
    HANDLE m_hThread     = nullptr;
    HANDLE m_hReadPipe   = nullptr;
    HANDLE m_hWritePipe  = nullptr;

    // State
    ConversionConfig  m_config     = {};
    ConversionResult  m_result     = ConversionResult::Cancelled;
    bool              m_converting = false;
    bool              m_infoShown  = false;
    int               m_progress   = 0;         // 0..100
    int               m_stage      = 0;
    int               m_chunksProcessed = 0;
    int               m_totalChunks     = 0;
    DWORD             m_startTick       = 0;
    wchar_t           m_convertedPath[MAX_PATH] = {};
    wchar_t           m_statusText[256]         = L"Ready";

    // Output log ring buffer
    struct LogEntry {
        wchar_t  text[512];
        COLORREF color;
    };
    static constexpr int MAX_LOG_LINES = 200;
    LogEntry m_log[MAX_LOG_LINES] = {};
    int      m_logCount = 0;
    int      m_logScroll = 0;

    // Class registration
    static bool s_classRegistered;
};

// ============================================================================
// C API for Win32IDE integration
// ============================================================================
extern "C" {
    int  ModelConversionDialog_ShowModal(HWND parent, const ConversionConfig* cfg);
    const wchar_t* ModelConversionDialog_GetConvertedPath();
}
=======
#include <string>
#include <vector>
#include <windows.h>
#include <filesystem>
#include <optional>
#include <chrono>
#include <functional>
#include <memory>
#include <atomic>

namespace fs = std::filesystem;

struct ConversionConfig {
    fs::path converterPath;
    fs::path modelsDirectory;
    bool showUI = true;
    std::optional<fs::path> logFile;
    std::chrono::seconds timeout = std::chrono::hours(1);
    std::optional<std::string> apiKey;
    std::vector<std::string> allowedExtensions = {".gguf", ".bin", ".pth"};
};

struct ConversionResult {
    bool success = false;
    std::optional<int> exitCode;
    std::chrono::milliseconds duration{0};
    fs::path convertedModelPath;
    std::string errorOutput;
    std::string output;
};

enum class ConversionError {
    None,
    ConverterNotFound,
    InvalidConverterPath,
    PathTraversalDetected,
    InvalidModelPath,
    CommandExecutionFailed
};

class ProcessHandle {
public:
    explicit ProcessHandle(HANDLE h = nullptr) : m_handle(h) {}
    ~ProcessHandle();
    ProcessHandle(ProcessHandle&& other) noexcept;
    ProcessHandle& operator=(ProcessHandle&& other) noexcept;
    
    // Disable copy
    ProcessHandle(const ProcessHandle&) = delete;
    ProcessHandle& operator=(const ProcessHandle&) = delete;
    
    bool isValid() const { return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE; }
    HANDLE get() const { return m_handle; }
    void close();
private:
    HANDLE m_handle;
};

class ModelConversionDialog {
public:
    enum Result {
        Converted,
        Cancelled,
        Failed
    };

    ModelConversionDialog(const std::vector<std::string>& unsupportedTypes,
                          std::string_view recommendedType,
                          const fs::path& modelPath,
                          HWND parent,
                          const ConversionConfig& config = {});
    
    Result exec();
    void execAsync(std::function<void(Result, const ConversionResult&)> callback);

    const ConversionResult& getConversionResult() const { return m_conversionResult; }
    
    static bool needsConversion(const fs::path& modelPath);
    static std::pair<fs::path, ConversionError> findConverter(const fs::path& searchRoot);

private:
    std::vector<std::string> m_unsupportedTypes;
    std::string m_recommendedType;
    fs::path m_modelPath;
    HWND m_parent;
    ConversionConfig m_config;
    
    ConversionResult m_conversionResult;
    ProcessHandle m_processHandle;
    std::atomic<bool> m_cancelRequested{false};

    // Validation
    std::pair<bool, ConversionError> validatePaths() const;
    std::pair<bool, ConversionError> validateModelPath() const;
    
    // Logic
    std::string buildUserMessage() const;
    std::string buildConverterNotFoundMessage() const;
    std::pair<std::string, ConversionError> buildCommandLine() const;
    
    // Execution
    std::pair<ProcessHandle, ConversionError> executeConverter(const std::string& commandLine) const;
    void monitorProcess(ProcessHandle& handle, std::chrono::seconds timeout);
    Result handleConversionResult();
    
    // Helpers
    std::string readPipeOutput(HANDLE hPipe) const;
    void showInfoDialog(const std::string& message) const;
    void showErrorDialog(const std::string& message) const;
    bool askUserPermission(const std::string& message) const;
    
    void log(const std::string& message, bool isError = false) const;
};


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
