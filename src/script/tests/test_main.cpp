// RawrXD-Script Test Suite
// Comprehensive tests for lexer, parser, bytecode emitter, and interpreter

#include "../lexer/lexer.hpp"
#include "../parser/parser.hpp"
#include "../bytecode/bytecode.hpp"
#include "../compiler/bytecode_emitter.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <vector>
#include <functional>

using namespace RawrXD::Script;

// Test result tracking
struct TestResults {
    int passed = 0;
    int failed = 0;
    std::vector<std::string> failures;
    
    void Pass() { passed++; }
    void Fail(const std::string& msg) { 
        failed++; 
        failures.push_back(msg);
        std::cerr << "  FAIL: " << msg << std::endl;
    }
};

TestResults g_results;

// Test macros
#define TEST(name) std::cout << "\n[Test] " << #name << std::endl;
#define ASSERT(cond) if (!(cond)) { g_results.Fail("Assertion failed: " #cond); } else { g_results.Pass(); }
#define ASSERT_EQ(a, b) if ((a) != (b)) { \
    std::stringstream ss; \
    ss << "Expected " << (b) << " but got " << (a); \
    g_results.Fail(ss.str()); \
} else { g_results.Pass(); }

// Test functions
// ============================================================================
// Lexer Tests
// ============================================================================

void TestLexerBasics() {
    TEST(LexerBasics);
    
    Lexer lexer;
    
    // Test empty input
    LexerResult result = lexer.Tokenize("");
    ASSERT(result.Success());
    
    // Test whitespace
    result = lexer.Tokenize("   \t\n  ");
    ASSERT(result.Success());
    
    // Test single tokens
    result = lexer.Tokenize("+");
    ASSERT(result.Success());
    ASSERT(result.tokens.size() > 0);
    
    result = lexer.Tokenize("-");
    ASSERT(result.Success());
    
    result = lexer.Tokenize("*");
    ASSERT(result.Success());
    
    result = lexer.Tokenize("/");
    ASSERT(result.Success());
    
    std::cout << "  Lexer basics: " << g_results.passed << " assertions passed" << std::endl;
}

void TestLexerNumbers() {
    TEST(LexerNumbers);
    
    Lexer lexer;
    LexerResult result;
    
    // Integer
    result = lexer.Tokenize("42");
    ASSERT(result.Success());
    
    // Float
    result = lexer.Tokenize("3.14");
    ASSERT(result.Success());
    
    // Scientific notation
    result = lexer.Tokenize("1e10");
    ASSERT(result.Success());
    
    result = lexer.Tokenize("2.5e-3");
    ASSERT(result.Success());
    
    // Hex
    result = lexer.Tokenize("0xFF");
    ASSERT(result.Success());
    
    std::cout << "  Lexer numbers: " << g_results.passed << " assertions passed" << std::endl;
}

void TestLexerStrings() {
    TEST(LexerStrings);
    
    Lexer lexer;
    LexerResult result;
    
    // Simple string
    result = lexer.Tokenize("'hello'");
    ASSERT(result.Success());
    
    // Double quoted
    result = lexer.Tokenize("\"world\"");
    ASSERT(result.Success());
    
    std::cout << "  Lexer strings: " << g_results.passed << " assertions passed" << std::endl;
}

void TestLexerKeywords() {
    TEST(LexerKeywords);
    
    Lexer lexer;
    LexerResult result;
    
    result = lexer.Tokenize("function var if else while for return");
    ASSERT(result.Success());
    ASSERT(result.tokens.size() >= 7);
    
    std::cout << "  Lexer keywords: " << g_results.passed << " assertions passed" << std::endl;
}

void TestLexerOperators() {
    TEST(LexerOperators);
    
    Lexer lexer;
    LexerResult result;
    
    result = lexer.Tokenize("+ - * / % == != === !== < > <= >= && ||");
    ASSERT(result.Success());
    
    std::cout << "  Lexer operators: " << g_results.passed << " assertions passed" << std::endl;
}

// ============================================================================
// Parser Tests
// ============================================================================

void TestParserExpressions() {
    TEST(ParserExpressions);
    
    Parser parser;
    
    // Simple binary expression
    auto result = parser.Parse("1 + 2");
    ASSERT(result.success);
    ASSERT(result.ast != nullptr);
    
    // Complex expression
    result = parser.Parse("a + b * c");
    ASSERT(result.success);
    
    // Parenthesized
    result = parser.Parse("(1 + 2) * 3");
    ASSERT(result.success);
    
    // Unary
    result = parser.Parse("-x");
    ASSERT(result.success);
    
    result = parser.Parse("!flag");
    ASSERT(result.success);
    
    std::cout << "  Parser expressions: " << g_results.passed << " assertions passed" << std::endl;
}

void TestParserStatements() {
    TEST(ParserStatements);
    
    Parser parser;
    
    // Variable declaration
    auto result = parser.Parse("var x = 5;");
    ASSERT(result.success);
    
    // Function declaration
    result = parser.Parse("function foo() { return 42; }");
    ASSERT(result.success);
    
    // If statement
    result = parser.Parse("if (x > 0) { y = 1; }");
    ASSERT(result.success);
    
    result = parser.Parse("if (x) { y = 1; } else { y = 2; }");
    ASSERT(result.success);
    
    // While loop
    result = parser.Parse("while (i < 10) { i++; }");
    ASSERT(result.success);
    
    // For loop
    result = parser.Parse("for (var i = 0; i < 10; i++) { }");
    ASSERT(result.success);
    
    std::cout << "  Parser statements: " << g_results.passed << " assertions passed" << std::endl;
}

void TestParserErrors() {
    TEST(ParserErrors);
    
    Parser parser;
    
    // Empty input
    auto result = parser.Parse("");
    // Should handle gracefully
    
    // Invalid syntax (should fail gracefully)
    result = parser.Parse("function");
    // May fail, but shouldn't crash
    
    std::cout << "  Parser errors: " << g_results.passed << " assertions passed" << std::endl;
}

// ============================================================================
// Bytecode Tests
// ============================================================================

void TestBytecodeFormat() {
    TEST(BytecodeFormat);
    
    Bytecode::BytecodeModule module;
    
    // Test header
    auto data = module.Serialize();
    ASSERT(data.size() > 0);
    
    // Test instruction encoding
    Bytecode::Instruction inst(Bytecode::Opcode::OP_ADD, 0, 1, 2);
    ASSERT(inst.GetOpcode() == Bytecode::Opcode::OP_ADD);
    
    // Test constant pool
    Bytecode::Constant c;
    c.type = Bytecode::ConstantType::Int32;
    c.int32_value = 42;
    uint32_t idx = module.AddConstant(c);
    ASSERT(idx == 0);
    
    // Test string table
    uint32_t strIdx = module.AddString("hello");
    ASSERT(strIdx == 0);
    
    std::cout << "  Bytecode format: " << g_results.passed << " assertions passed" << std::endl;
}

void TestBytecodeSerialization() {
    TEST(BytecodeSerialization);
    
    Bytecode::BytecodeModule module;
    
    // Add some instructions
    module.AppendInstruction(Bytecode::Instruction(Bytecode::Opcode::OP_LOAD_INT, 0, 0, 0));
    module.AppendInstruction(Bytecode::Instruction(Bytecode::Opcode::OP_LOAD_INT, 1, 0, 0));
    module.AppendInstruction(Bytecode::Instruction(Bytecode::Opcode::OP_ADD, 2, 0, 1));
    module.AppendInstruction(Bytecode::Instruction(Bytecode::Opcode::OP_RETURN, 0, 2, 0));
    
    // Add constants
    Bytecode::Constant c1, c2;
    c1.type = Bytecode::ConstantType::Int32;
    c1.int32_value = 10;
    c2.type = Bytecode::ConstantType::Int32;
    c2.int32_value = 20;
    module.AddConstant(c1);
    module.AddConstant(c2);
    
    // Serialize
    auto data = module.Serialize();
    ASSERT(data.size() > 0);
    
    // Deserialize
    Bytecode::BytecodeModule module2;
    bool success = module2.Deserialize(data.data(), data.size());
    ASSERT(success);
    
    std::cout << "  Bytecode serialization: " << g_results.passed << " assertions passed" << std::endl;
}

// ============================================================================
// Emitter Tests
// ============================================================================

void TestEmitterBasics() {
    TEST(EmitterBasics);
    
    BytecodeEmitter emitter;
    Parser parser;
    
    // Simple expression
    auto result = parser.Parse("1 + 2");
    ASSERT(result.success);
    
    Bytecode::BytecodeModule module;
    bool success = emitter.Emit(result.ast.get(), &module);
    ASSERT(success);
    ASSERT(module.GetCode().size() > 0);
    
    // Variable declaration
    result = parser.Parse("var x = 42;");
    module = Bytecode::BytecodeModule();
    success = emitter.Emit(result.ast.get(), &module);
    ASSERT(success);
    
    std::cout << "  Emitter basics: " << g_results.passed << " assertions passed" << std::endl;
}

void TestEmitterControlFlow() {
    TEST(EmitterControlFlow);
    
    BytecodeEmitter emitter;
    Parser parser;
    
    // If statement
    auto result = parser.Parse("if (x) { y = 1; }");
    Bytecode::BytecodeModule module;
    bool success = emitter.Emit(result.ast.get(), &module);
    ASSERT(success);
    
    // While loop
    result = parser.Parse("while (i < 10) { i = i + 1; }");
    module = Bytecode::BytecodeModule();
    success = emitter.Emit(result.ast.get(), &module);
    ASSERT(success);
    
    std::cout << "  Emitter control flow: " << g_results.passed << " assertions passed" << std::endl;
}

// ============================================================================
// Integration Tests
// ============================================================================

void TestFullPipeline() {
    TEST(FullPipeline);
    
    // Complete pipeline: source -> tokens -> AST -> bytecode
    const char* source = R"(
        function factorial(n) {
            if (n <= 1) {
                return 1;
            }
            return n * factorial(n - 1);
        }
        
        var result = factorial(5);
    )";
    
    // Lex
    Lexer lexer;
    auto lexResult = lexer.Tokenize(source);
    ASSERT(lexResult.Success());
    ASSERT(lexResult.tokens.size() > 0);
    
    // Parse
    Parser parser;
    auto parseResult = parser.Parse(source);
    ASSERT(parseResult.success);
    ASSERT(parseResult.ast != nullptr);
    
    // Emit
    BytecodeEmitter emitter;
    Bytecode::BytecodeModule module;
    bool success = emitter.Emit(parseResult.ast.get(), &module);
    ASSERT(success);
    ASSERT(module.GetCode().size() > 0);
    
    std::cout << "  Full pipeline: " << g_results.passed << " assertions passed" << std::endl;
}
    
    std::cout << "PASSED\n";
    return true;
}

bool TestParserFunction() {
    std::cout << "Test: Parser Function... ";
    
    Parser parser;
    ParserResult result = parser.Parse(R"(
        function add(a, b) {
            return a + b;
        }
    )");
    
    TEST_ASSERT(result.success);
    TEST_ASSERT(result.ast != nullptr);
    
    std::cout << "PASSED\n";
    return true;
}

bool TestParserIfStatement() {
    std::cout << "Test: Parser If Statement... ";
    
    Parser parser;
    ParserResult result = parser.Parse(R"(
        if (x > 0) {
            return x;
        } else {
            return -x;
        }
    )");
    
    TEST_ASSERT(result.success);
    TEST_ASSERT(result.ast != nullptr);
    
    std::cout << "PASSED\n";
    return true;
}

bool TestParserWhileLoop() {
    std::cout << "Test: Parser While Loop... ";
    
    Parser parser;
    ParserResult result = parser.Parse(R"(
        while (i < 10) {
            i = i + 1;
        }
    )");
    
    TEST_ASSERT(result.success);
    TEST_ASSERT(result.ast != nullptr);
    
    std::cout << "PASSED\n";
    return true;
}

bool TestParserForLoop() {
    std::cout << "Test: Parser For Loop... ";
    
    Parser parser;
    ParserResult result = parser.Parse(R"(
        for (var i = 0; i < 10; i++) {
            console.log(i);
        }
    )");
    
    TEST_ASSERT(result.success);
    TEST_ASSERT(result.ast != nullptr);
    
    std::cout << "PASSED\n";
    return true;
}

bool TestBytecodeHeader() {
    std::cout << "Test: Bytecode Header... ";
    
    Bytecode::BytecodeModule module;
    std::vector<uint8_t> data = module.Serialize();
    
    TEST_ASSERT(data.size() >= sizeof(Bytecode::BytecodeHeader));
    
    // Check magic number
    uint32_t magic = *reinterpret_cast<const uint32_t*>(data.data());
    TEST_ASSERT_EQ(magic, Bytecode::kBytecodeMagic);
    
    std::cout << "PASSED\n";
    return true;
}

bool TestBytecodeInstructions() {
    std::cout << "Test: Bytecode Instructions... ";
    
    Bytecode::BytecodeModule module;
    
    // Add some instructions
    module.AppendInstruction(Bytecode::Instruction(
        Bytecode::Opcode::OP_LOAD_INT, 0, 0, 0));
    module.AppendInstruction(Bytecode::Instruction(
        Bytecode::Opcode::OP_LOAD_INT, 1, 0, 0));
    module.AppendInstruction(Bytecode::Instruction(
        Bytecode::Opcode::OP_ADD, 2, 0, 1));
    module.AppendInstruction(Bytecode::Instruction(
        Bytecode::Opcode::OP_RETURN, 0, 2, 0));
    
    TEST_ASSERT_EQ(module.GetCode().size(), 4);
    
    std::cout << "PASSED\n";
    return true;
}

bool TestBytecodeConstants() {
    std::cout << "Test: Bytecode Constants... ";
    
    Bytecode::BytecodeModule module;
    
    Bytecode::Constant c1;
    c1.type = Bytecode::ConstantType::Int32;
    c1.int32_value = 42;
    
    Bytecode::Constant c2;
    c2.type = Bytecode::ConstantType::Float64;
    c2.float64_value = 3.14159;
    
    uint32_t idx1 = module.AddConstant(c1);
    uint32_t idx2 = module.AddConstant(c2);
    
    TEST_ASSERT_EQ(idx1, 0);
    TEST_ASSERT_EQ(idx2, 1);
    
    std::cout << "PASSED\n";
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD-Script Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int initialPassed = g_results.passed;
    
    // Lexer tests
    TestLexerBasics();
    TestLexerNumbers();
    TestLexerStrings();
    TestLexerKeywords();
    TestLexerOperators();
    
    // Parser tests
    TestParserExpressions();
    TestParserStatements();
    TestParserErrors();
    
    // Bytecode tests
    TestBytecodeFormat();
    TestBytecodeSerialization();
    
    // Emitter tests
    TestEmitterBasics();
    TestEmitterControlFlow();
    
    // Integration tests
    TestFullPipeline();
    
    // Summary
    std::cout << "\n========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Passed: " << g_results.passed << std::endl;
    std::cout << "Failed: " << g_results.failed << std::endl;
    
    if (!g_results.failures.empty()) {
        std::cout << "\nFailures:" << std::endl;
        for (const auto& f : g_results.failures) {
            std::cout << "  - " << f << std::endl;
        }
    }
    
    std::cout << "\n========================================" << std::endl;
    
    return g_results.failed > 0 ? 1 : 0;
}
