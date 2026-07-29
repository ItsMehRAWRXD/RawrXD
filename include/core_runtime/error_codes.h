#ifndef RAWRXD_CORE_ERROR_CODES_H
#define RAWRXD_CORE_ERROR_CODES_H
#include "core_export.h"

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

// Get human-readable error message for an error code
RAWRXD_CORE_EXPORT const char* GetErrorString(int code);

// Get error category for grouping related errors
RAWRXD_CORE_EXPORT const char* GetErrorCategory(int code);

// Check if error is recoverable (can be retried)
RAWRXD_CORE_EXPORT bool IsRecoverableError(int code);

}} // namespace RawrXD::Core
#endif // RAWRXD_CORE_ERROR_CODES_H
