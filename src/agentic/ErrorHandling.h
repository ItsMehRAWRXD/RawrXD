/**
 * @file ErrorHandling.h
 * @brief Error handling and exception types for agentic system
 * 
 * Part of Production Framework - Phase 5
 * Provides standardized error codes and exception types.
 * 
 * @copyright RawrXD 2026
 */

#pragma once

#include <string>
#include <stdexcept>
#include <optional>

namespace RawrXD {
namespace Agentic {

/**
 * @brief Error codes for agentic operations
 */
enum class ErrorCode {
    Success = 0,
    Unknown = 1,
    InvalidArgument = 2,
    NotFound = 3,
    AlreadyExists = 4,
    NotInitialized = 5,
    AlreadyInitialized = 6,
    OutOfMemory = 7,
    Timeout = 8,
    Cancelled = 9,
    InternalError = 10,
    NotSupported = 11,
    InvalidState = 12,
    NetworkError = 13,
    ParseError = 14,
    ValidationError = 15,
    ResourceExhausted = 16,
    PermissionDenied = 17,
    Unauthenticated = 18
};

/**
 * @brief Get string representation of error code
 */
inline const char* ErrorCodeToString(ErrorCode code) {
    switch (code) {
        case ErrorCode::Success: return "Success";
        case ErrorCode::Unknown: return "Unknown";
        case ErrorCode::InvalidArgument: return "InvalidArgument";
        case ErrorCode::NotFound: return "NotFound";
        case ErrorCode::AlreadyExists: return "AlreadyExists";
        case ErrorCode::NotInitialized: return "NotInitialized";
        case ErrorCode::AlreadyInitialized: return "AlreadyInitialized";
        case ErrorCode::OutOfMemory: return "OutOfMemory";
        case ErrorCode::Timeout: return "Timeout";
        case ErrorCode::Cancelled: return "Cancelled";
        case ErrorCode::InternalError: return "InternalError";
        case ErrorCode::NotSupported: return "NotSupported";
        case ErrorCode::InvalidState: return "InvalidState";
        case ErrorCode::NetworkError: return "NetworkError";
        case ErrorCode::ParseError: return "ParseError";
        case ErrorCode::ValidationError: return "ValidationError";
        case ErrorCode::ResourceExhausted: return "ResourceExhausted";
        case ErrorCode::PermissionDenied: return "PermissionDenied";
        case ErrorCode::Unauthenticated: return "Unauthenticated";
        default: return "Unknown";
    }
}

/**
 * @brief Agentic exception base class
 */
class AgenticException : public std::exception {
public:
    AgenticException(ErrorCode code, const std::string& message)
        : m_code(code), m_message(message) {}
    
    ErrorCode Code() const { return m_code; }
    const char* what() const noexcept override { return m_message.c_str(); }
    
private:
    ErrorCode m_code;
    std::string m_message;
};

/**
 * @brief Result type for operations that can fail
 */
template<typename T>
class Result {
public:
    Result() : m_code(ErrorCode::Unknown), m_hasValue(false) {}
    
    static Result Ok(const T& value) {
        Result r;
        r.m_code = ErrorCode::Success;
        r.m_value = value;
        r.m_hasValue = true;
        return r;
    }
    
    static Result Ok(T&& value) {
        Result r;
        r.m_code = ErrorCode::Success;
        r.m_value = std::move(value);
        r.m_hasValue = true;
        return r;
    }
    
    static Result Err(ErrorCode code, const std::string& message = "") {
        Result r;
        r.m_code = code;
        r.m_message = message;
        r.m_hasValue = false;
        return r;
    }
    
    bool IsOk() const { return m_code == ErrorCode::Success; }
    bool IsErr() const { return !IsOk(); }
    
    ErrorCode Code() const { return m_code; }
    const std::string& Message() const { return m_message; }
    
    T& Value() { return m_value; }
    const T& Value() const { return m_value; }
    
    T* operator->() { return &m_value; }
    const T* operator->() const { return &m_value; }
    
    T& operator*() { return m_value; }
    const T& operator*() const { return m_value; }
    
private:
    ErrorCode m_code;
    std::string m_message;
    T m_value;
    bool m_hasValue;
};

/**
 * @brief Void result type for operations without return value
 */
template<>
class Result<void> {
public:
    Result() : m_code(ErrorCode::Unknown) {}
    
    static Result Ok() {
        Result r;
        r.m_code = ErrorCode::Success;
        return r;
    }
    
    static Result Err(ErrorCode code, const std::string& message = "") {
        Result r;
        r.m_code = code;
        r.m_message = message;
        return r;
    }
    
    bool IsOk() const { return m_code == ErrorCode::Success; }
    bool IsErr() const { return !IsOk(); }
    
    ErrorCode Code() const { return m_code; }
    const std::string& Message() const { return m_message; }
    
private:
    ErrorCode m_code;
    std::string m_message;
};

} // namespace Agentic
} // namespace RawrXD
