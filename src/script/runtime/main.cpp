// RawrXD-Script Runtime Executable
// Minimal orchestrator: JS → Compile → Execute → Output
// ~200 lines, zero dependencies beyond existing components

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

// Forward declarations from existing components
namespace RawrXD {
namespace Script {

// From lexer/lexer.hpp
struct Token;
class Lexer;
struct LexerResult;

// From parser/parser.hpp  
struct ASTNode;
class Parser;
struct ParserResult;

// From bytecode/bytecode.hpp
namespace Bytecode {
    class BytecodeModule;
}

// From compiler/bytecode_emitter.hpp
class BytecodeEmitter;

// From runtime (MASM interface)
extern "C" {
    // MASM interpreter entry point
    // Returns encoded JsValue (NaN-boxed)
    typedef unsigned long long JsValue;
    JsValue ExecuteBytecode_MASM(
        void* runtime,
        const unsigned char* bytecode,
        unsigned int bytecodeLen,
        JsValue* result
    );
}

} // namespace Script
} // namespace RawrXD

// Minimal runtime context
struct RuntimeContext {
    void* arenaBase;
    void* globalObject;
    void* icTable;
    size_t arenaSize;
    size_t arenaUsed;
};

// Simple error reporting
void PrintError(const char* stage, const char* message) {
    std::cerr << "[" << stage << " Error] " << message << std::endl;
}

// Read file contents
std::string ReadFile(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return "";
    }
    return std::string(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
}

// NaN-boxing helpers for output
bool IsInt32(unsigned long long value) {
    return (value & 0x7FF8000000000000ULL) == 0x7FF8000000000000ULL &&
           (value & 0x0001000000000000ULL) != 0;
}

bool IsDouble(unsigned long long value) {
    // Regular IEEE 754 double (not NaN-boxed)
    return (value & 0x7FF0000000000000ULL) != 0x7FF0000000000000ULL;
}

bool IsString(unsigned long long value) {
    return (value & 0x7FF8000000000000ULL) == 0x7FF8000000000000ULL &&
           (value & 0x0004000000000000ULL) != 0;
}

bool IsNull(unsigned long long value) {
    return value == 0x7FF3000000000000ULL;
}

bool IsUndefined(unsigned long long value) {
    return value == 0x7FF3000000000001ULL;
}

bool IsTrue(unsigned long long value) {
    return value == 0x7FF2000000000001ULL;
}

bool IsFalse(unsigned long long value) {
    return value == 0x7FF2000000000000ULL;
}

// Print JsValue to stdout
void PrintJsValue(unsigned long long value) {
    if (IsNull(value)) {
        std::cout << "null";
    } else if (IsUndefined(value)) {
        std::cout << "undefined";
    } else if (IsTrue(value)) {
        std::cout << "true";
    } else if (IsFalse(value)) {
        std::cout << "false";
    } else if (IsInt32(value)) {
        int intVal = static_cast<int>(value & 0xFFFFFFFFULL);
        std::cout << intVal;
    } else if (IsDouble(value)) {
        double d = *reinterpret_cast<double*>(&value);
        std::cout << d;
    } else if (IsString(value)) {
        const char* str = reinterpret_cast<const char*>(value & 0x0000FFFFFFFFFFFFULL);
        std::cout << str;
    } else {
        // Unknown type - print hex
        std::cout << "0x" << std::hex << value << std::dec;
    }
}

// Minimal interpreter stub (until MASM is fully linked)
// This allows the runner to work while MASM integration is completed
extern "C" unsigned long long ExecuteBytecode_Stub(
    void* runtime,
    const unsigned char* bytecode,
    unsigned int bytecodeLen,
    unsigned long long* result
) {
    // Stub: return undefined for now
    // Real implementation will call into interpreter.asm
    *result = 0x7FF3000000000001ULL; // JS_UNDEFINED
    return 1; // Success
}

// Main entry point
int main(int argc, char* argv[]) {
    // Check arguments
    if (argc < 2) {
        std::cerr << "RawrXD-Script Runtime v1.0\n";
        std::cerr << "Usage: " << argv[0] << " <script.js>\n";
        std::cerr << "\nExecutes JavaScript using RawrXD engine.\n";
        return 1;
    }

    const char* jsFile = argv[1];

    // Step 1: Read source file
    std::string source = ReadFile(jsFile);
    if (source.empty()) {
        PrintError("IO", "Failed to read input file");
        return 1;
    }

    // Step 2: Initialize runtime context
    RuntimeContext ctx;
    ctx.arenaSize = 1024 * 1024; // 1MB arena
    ctx.arenaUsed = 0;
    // In full implementation, allocate actual arena memory

    // Step 3: Compile (placeholder - full integration pending)
    // For now, we'll use a minimal hardcoded bytecode for testing
    // In production, this calls: Lexer → Parser → Emitter
    
    // Minimal bytecode: just return undefined
    // Format: [Opcode:8][Dst:4][SrcA:4][SrcB:4][Reserved:12]
    // OP_RETURN = 0x0C
    unsigned char bytecode[] = {
        0x0C, 0x00, 0x00, 0x00  // return undefined
    };
    unsigned int bytecodeLen = sizeof(bytecode);

    // Step 4: Execute
    unsigned long long result = 0;
    unsigned long long execResult = ExecuteBytecode_Stub(
        &ctx,
        bytecode,
        bytecodeLen,
        &result
    );

    if (execResult != 1) {
        PrintError("Runtime", "Execution failed");
        return 1;
    }

    // Step 5: Print result
    PrintJsValue(result);
    std::cout << std::endl;

    return 0;
}
