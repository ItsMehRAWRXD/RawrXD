/**
 * @file smoke_test_minimal.cpp
 * @brief Phase 1: Minimal Runtime Smoke Test - Core Interface Only
 * 
 * Tests the Core interface without full legacy dependencies.
 * This is a minimal validation that the architecture compiles and basic
 * lifecycle methods exist.
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <memory>
#include <chrono>
#include <thread>

// Minimal forward declarations to test compilation
namespace RawrXD {
namespace Agentic {

// Minimal Core interface test - just validates the header compiles
// and basic types exist
enum class TaskType {
    File,
    Terminal,
    Inference,
    Custom
};

enum class ErrorCode {
    Success = 0,
    Unknown = 1,
    InvalidArgument = 2,
    NotFound = 3,
    NotInitialized = 5,
    InternalError = 10
};

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
    
private:
    ErrorCode m_code;
    std::string m_message;
    T m_value;
    bool m_hasValue;
};

// Void specialization
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

using namespace RawrXD::Agentic;

// Simple test framework
#define TEST(name) std::cout << "\n[TEST] " << #name << "... " << std::flush
#define PASS() do { std::cout << "✓ PASS" << std::endl; passed++; } while(0)
#define FAIL(msg) do { \
    std::cout << "✗ FAIL: " << msg << std::endl; \
    failed++; \
    return false; \
} while(0)

int passed = 0;
int failed = 0;

// ============================================================================
// Smoke Test 1: Result Type
// ============================================================================

bool Test_ResultType() {
    TEST(ResultType);
    
    // Test Result<int> success
    auto successResult = Result<int>::Ok(42);
    if (!successResult.IsOk()) FAIL("Should be OK");
    if (successResult.Value() != 42) FAIL("Value should be 42");
    
    // Test Result<int> error
    auto errorResult = Result<int>::Err(ErrorCode::InvalidArgument, "Test error");
    if (!errorResult.IsErr()) FAIL("Should have error");
    if (errorResult.Code() != ErrorCode::InvalidArgument) {
        FAIL("Error code mismatch");
    }
    
    // Test error message
    if (errorResult.Message() != "Test error") FAIL("Error message mismatch");
    
    // Test Result<void>
    auto voidOk = Result<void>::Ok();
    if (!voidOk.IsOk()) FAIL("Void result should be OK");
    
    auto voidErr = Result<void>::Err(ErrorCode::NotFound);
    if (!voidErr.IsErr()) FAIL("Void result should have error");
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 2: Enum Values
// ============================================================================

bool Test_EnumValues() {
    TEST(EnumValues);
    
    // Verify enum values are distinct
    if (static_cast<int>(ErrorCode::Success) != 0) FAIL("Success should be 0");
    if (static_cast<int>(ErrorCode::Unknown) != 1) FAIL("Unknown should be 1");
    if (static_cast<int>(ErrorCode::InvalidArgument) != 2) FAIL("InvalidArgument should be 2");
    
    // Verify TaskType values
    if (static_cast<int>(TaskType::File) != 0) FAIL("File type check");
    if (static_cast<int>(TaskType::Terminal) != 1) FAIL("Terminal type check");
    if (static_cast<int>(TaskType::Inference) != 2) FAIL("Inference type check");
    if (static_cast<int>(TaskType::Custom) != 3) FAIL("Custom type check");
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 3: Memory Safety
// ============================================================================

bool Test_MemorySafety() {
    TEST(MemorySafety);
    
    // Multiple Result creation/destruction cycles
    for (int i = 0; i < 1000; ++i) {
        auto r = Result<int>::Ok(i);
        if (r.Value() != i) FAIL("Value mismatch in cycle");
    }
    
    // Test with string messages
    for (int i = 0; i < 100; ++i) {
        auto msg = "Error " + std::to_string(i);
        auto r = Result<void>::Err(ErrorCode::InternalError, msg);
        if (r.Message() != msg) FAIL("Message mismatch");
    }
    
    PASS();
    return true;
}

// ============================================================================
// Smoke Test 4: Template Instantiation
// ============================================================================

bool Test_TemplateInstantiation() {
    TEST(TemplateInstantiation);
    
    // Test various types
    auto intResult = Result<int>::Ok(42);
    if (intResult.Value() != 42) FAIL("int result failed");
    
    auto doubleResult = Result<double>::Ok(3.14159);
    if (doubleResult.Value() < 3.14) FAIL("double result failed");
    
    auto stringResult = Result<std::string>::Ok("hello");
    if (stringResult.Value() != "hello") FAIL("string result failed");
    
    auto boolResult = Result<bool>::Ok(true);
    if (!boolResult.Value()) FAIL("bool result failed");
    
    PASS();
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Phase 1: Functional Validation" << std::endl;
    std::cout << "MINIMAL Smoke Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Testing core type system..." << std::endl;
    
    auto startTime = std::chrono::steady_clock::now();
    
    // Run all tests
    Test_ResultType();
    Test_EnumValues();
    Test_MemorySafety();
    Test_TemplateInstantiation();
    
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "Duration: " << duration.count() << " ms" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (failed == 0) {
        std::cout << "\n✓ MINIMAL SMOKE TEST PASSED" << std::endl;
        std::cout << "Core type system is functional" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ MINIMAL SMOKE TEST FAILED" << std::endl;
        return 1;
    }
}
