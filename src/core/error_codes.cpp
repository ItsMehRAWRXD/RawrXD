// Production implementation for error_codes.cpp
// Comprehensive error code handling for RawrXD Core Runtime
#define RAWRXD_CURRENT_DOMAIN RAWRXD_DOMAIN_CORE_RUNTIME
#include "core_runtime/symbol_ownership.h"
#include <windows.h>
#include <string>

namespace RawrXD { namespace Core {

// RawrXD Core Error Codes (0-999 reserved for core runtime)
enum class CoreErrorCode : int {
    // Success (0)
    Success = 0,
    
    // General errors (1-99)
    UnknownError = 1,
    InvalidArgument = 2,
    NullPointer = 3,
    OutOfMemory = 4,
    NotImplemented = 5,
    NotSupported = 6,
    AccessDenied = 7,
    Timeout = 8,
    Cancelled = 9,
    AlreadyExists = 10,
    NotFound = 11,
    
    // File I/O errors (100-199)
    FileNotFound = 100,
    FileAccessDenied = 101,
    FileAlreadyExists = 102,
    FileTooLarge = 103,
    FileCorrupted = 104,
    PathNotFound = 105,
    PathTooLong = 106,
    DiskFull = 107,
    
    // Memory errors (200-299)
    MemoryAllocationFailed = 200,
    MemoryMapFailed = 201,
    MemoryUnmapFailed = 202,
    InvalidMemoryAlignment = 203,
    MemoryProtectionFailed = 204,
    
    // Thread/Process errors (300-399)
    ThreadCreationFailed = 300,
    ThreadTerminationFailed = 301,
    ProcessCreationFailed = 302,
    ProcessTerminationFailed = 303,
    
    // Network errors (400-499)
    NetworkUnavailable = 400,
    ConnectionFailed = 401,
    ConnectionReset = 402,
    ConnectionTimeout = 403,
    HostNotFound = 404,
    
    // GPU/Compute errors (500-599)
    GPUDeviceNotFound = 500,
    GPUInitializationFailed = 501,
    GPUMemoryAllocationFailed = 502,
    GPUKernelExecutionFailed = 503,
    GPUSynchronizationFailed = 504,
    
    // Model/Inference errors (600-699)
    ModelLoadFailed = 600,
    ModelInvalidFormat = 601,
    ModelVersionMismatch = 602,
    TokenizerLoadFailed = 603,
    InferenceFailed = 604,
    ContextLengthExceeded = 605,
    
    // Configuration errors (700-799)
    ConfigParseFailed = 700,
    ConfigInvalidValue = 701,
    ConfigMissingRequired = 702,
    
    // Security errors (800-899)
    SecurityViolation = 800,
    CertificateInvalid = 801,
    EncryptionFailed = 802,
    
    // System errors (900-999)
    SystemCallFailed = 900,
    ResourceExhausted = 901,
    ServiceNotRunning = 902
};

// Error message lookup table
struct ErrorMessageEntry {
    int code;
    const char* message;
};

static const ErrorMessageEntry s_errorMessages[] = {
    // Success
    {0, "Success"},
    
    // General errors
    {1, "Unknown error occurred"},
    {2, "Invalid argument provided"},
    {3, "Null pointer dereference"},
    {4, "Out of memory"},
    {5, "Feature not implemented"},
    {6, "Operation not supported"},
    {7, "Access denied"},
    {8, "Operation timed out"},
    {9, "Operation cancelled"},
    {10, "Object already exists"},
    {11, "Object not found"},
    
    // File I/O errors
    {100, "File not found"},
    {101, "File access denied"},
    {102, "File already exists"},
    {103, "File too large"},
    {104, "File corrupted"},
    {105, "Path not found"},
    {106, "Path too long"},
    {107, "Disk full"},
    
    // Memory errors
    {200, "Memory allocation failed"},
    {201, "Memory map failed"},
    {202, "Memory unmap failed"},
    {203, "Invalid memory alignment"},
    {204, "Memory protection failed"},
    
    // Thread/Process errors
    {300, "Thread creation failed"},
    {301, "Thread termination failed"},
    {302, "Process creation failed"},
    {303, "Process termination failed"},
    
    // Network errors
    {400, "Network unavailable"},
    {401, "Connection failed"},
    {402, "Connection reset"},
    {403, "Connection timeout"},
    {404, "Host not found"},
    
    // GPU/Compute errors
    {500, "GPU device not found"},
    {501, "GPU initialization failed"},
    {502, "GPU memory allocation failed"},
    {503, "GPU kernel execution failed"},
    {504, "GPU synchronization failed"},
    
    // Model/Inference errors
    {600, "Model load failed"},
    {601, "Invalid model format"},
    {602, "Model version mismatch"},
    {603, "Tokenizer load failed"},
    {604, "Inference failed"},
    {605, "Context length exceeded"},
    
    // Configuration errors
    {700, "Configuration parse failed"},
    {701, "Invalid configuration value"},
    {702, "Missing required configuration"},
    
    // Security errors
    {800, "Security violation"},
    {801, "Invalid certificate"},
    {802, "Encryption failed"},
    
    // System errors
    {900, "System call failed"},
    {901, "Resource exhausted"},
    {902, "Service not running"},
    
    // Sentinel
    {-1, nullptr}
};

// Thread-local buffer for formatted error messages
thread_local char s_errorBuffer[256];

const char* GetErrorString(int code) {
    // First check RawrXD error codes
    for (const auto& entry : s_errorMessages) {
        if (entry.code == code) {
            return entry.message;
        }
        if (entry.code == -1) {
            break;
        }
    }
    
    // If not a RawrXD error code, try Windows system error codes
    // Format the Windows error message
    DWORD dwError = static_cast<DWORD>(code);
    if (dwError != 0) {
        LPWSTR lpMsgBuf = nullptr;
        DWORD result = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            dwError,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&lpMsgBuf),
            0,
            nullptr
        );
        
        if (result != 0 && lpMsgBuf != nullptr) {
            // Convert wide string to UTF-8
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0, lpMsgBuf, -1, nullptr, 0, nullptr, nullptr);
            if (utf8Len > 0 && utf8Len < sizeof(s_errorBuffer)) {
                WideCharToMultiByte(CP_UTF8, 0, lpMsgBuf, -1, s_errorBuffer, sizeof(s_errorBuffer), nullptr, nullptr);
                // Remove trailing newline if present
                size_t len = strlen(s_errorBuffer);
                while (len > 0 && (s_errorBuffer[len-1] == '\n' || s_errorBuffer[len-1] == '\r')) {
                    s_errorBuffer[--len] = '\0';
                }
                LocalFree(lpMsgBuf);
                return s_errorBuffer;
            }
            LocalFree(lpMsgBuf);
        }
    }
    
    // Fallback: return formatted code
    snprintf(s_errorBuffer, sizeof(s_errorBuffer), "Unknown error code: %d", code);
    return s_errorBuffer;
}

// Get error category for grouping
const char* GetErrorCategory(int code) {
    if (code == 0) return "Success";
    if (code >= 1 && code <= 99) return "General";
    if (code >= 100 && code <= 199) return "File I/O";
    if (code >= 200 && code <= 299) return "Memory";
    if (code >= 300 && code <= 399) return "Thread/Process";
    if (code >= 400 && code <= 499) return "Network";
    if (code >= 500 && code <= 599) return "GPU/Compute";
    if (code >= 600 && code <= 699) return "Model/Inference";
    if (code >= 700 && code <= 799) return "Configuration";
    if (code >= 800 && code <= 899) return "Security";
    if (code >= 900 && code <= 999) return "System";
    return "Unknown";
}

// Check if error is recoverable
bool IsRecoverableError(int code) {
    switch (code) {
        case 0:  // Success
        case 8:  // Timeout
        case 9:  // Cancelled
        case 400: // Network unavailable
        case 401: // Connection failed
        case 403: // Connection timeout
        case 500: // GPU device not found
        case 501: // GPU initialization failed
        case 902: // Service not running
            return true;
        default:
            return false;
    }
}

}} // namespace RawrXD::Core
