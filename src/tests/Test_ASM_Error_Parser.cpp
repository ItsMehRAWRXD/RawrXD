// Test_ASM_Error_Parser.cpp
// Phase 22: Unit tests for MASM Error Parser
// ============================================================================

#include "build/ASM_Error_Parser.h"
#include <iostream>
#include <assert>

using namespace RawrXD::Build;

void TestErrorPattern() {
    MASMErrorParser parser;
    assert(parser.IsValid());
    
    // Test error pattern
    std::wstring errorLine = L"ApplyLoRA_Fixed.asm(45) : error A2008: syntax error : .code";
    auto error = parser.ParseLine(errorLine);
    
    assert(error.has_value());
    assert(error->filePath == L"ApplyLoRA_Fixed.asm");
    assert(error->lineNumber == 45);
    assert(error->severity == L"error");
    assert(error->errorCode == L"A2008");
    assert(error->message == L"syntax error : .code");
    
    std::wcout << L"✓ Error pattern test passed\n";
}

void TestWarningPattern() {
    MASMErrorParser parser;
    
    // Test warning pattern
    std::wstring warningLine = L"kernel.asm(120) : warning A6004: procedure argument not referenced";
    auto warning = parser.ParseLine(warningLine);
    
    assert(warning.has_value());
    assert(warning->filePath == L"kernel.asm");
    assert(warning->lineNumber == 120);
    assert(warning->severity == L"warning");
    assert(warning->errorCode == L"A6004");
    
    std::wcout << L"✓ Warning pattern test passed\n";
}

void TestVSFormat() {
    MASMErrorParser parser;
    
    std::wstring errorLine = L"test.asm(10) : error A2013: invalid use of register";
    auto error = parser.ParseLine(errorLine);
    
    assert(error.has_value());
    std::wstring vsFormat = error->ToVSFormat();
    assert(vsFormat == L"test.asm(10): error A2013: invalid use of register");
    
    std::wcout << L"✓ VS format test passed\n";
}

void TestJSONOutput() {
    MASMErrorParser parser;
    
    std::wstring errorLine = L"main.asm(25) : error A2070: invalid instruction operands";
    auto error = parser.ParseLine(errorLine);
    
    assert(error.has_value());
    std::wstring json = error->ToJSON();
    
    // Verify JSON contains expected fields
    assert(json.find(L"\"file\":\"main.asm\"") != std::wstring::npos);
    assert(json.find(L"\"line\":25") != std::wstring::npos);
    assert(json.find(L"\"severity\":\"error\"") != std::wstring::npos);
    
    std::wcout << L"✓ JSON output test passed\n";
}

void TestMultipleErrors() {
    MASMErrorParser parser;
    
    std::wstring multiErrorOutput = 
        L"ApplyLoRA_Fixed.asm(45) : error A2008: syntax error\n"
        L"ApplyLoRA_Fixed.asm(67) : warning A6001: unused variable\n"
        L"kernel.asm(12) : error A2013: invalid register\n";
    
    auto errors = parser.Parse(multiErrorOutput);
    
    assert(errors.size() == 3);
    assert(errors[0].errorCode == L"A2008");
    assert(errors[1].errorCode == L"A6001");
    assert(errors[2].errorCode == L"A2013");
    
    std::wcout << L"✓ Multiple errors test passed\n";
}

void TestErrorExplanations() {
    MASMErrorParser parser;
    
    // Test known error code
    std::wstring explanation = parser.GetErrorExplanation(L"A2008");
    assert(!explanation.empty());
    assert(explanation.find(L"Syntax error") != std::wstring::npos);
    
    // Test unknown error code
    std::wstring unknown = parser.GetErrorExplanation(L"Z9999");
    assert(unknown == L"Unknown error code");
    
    std::wcout << L"✓ Error explanations test passed\n";
}

int wmain() {
    std::wcout << L"=== Phase 22: ASM Error Parser Tests ===\n\n";
    
    try {
        TestErrorPattern();
        TestWarningPattern();
        TestVSFormat();
        TestJSONOutput();
        TestMultipleErrors();
        TestErrorExplanations();
        
        std::wcout << L"\n=== All tests passed! ===\n";
        return 0;
    } catch (const std::exception& e) {
        std::wcerr << L"\n✗ Test failed: " << e.what() << L"\n";
        return 1;
    }
}
