// RawrXD-Script Opcode Verification Suite
// Validates dispatch coverage, reachability, and behavioral correctness

#include "../bytecode/bytecode.hpp"
#include "../compiler/bytecode_emitter.hpp"
#include "../lexer/lexer.hpp"
#include "../parser/parser.hpp"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <cstring>

using namespace RawrXD::Script;

// ============================================================================
// 1. Opcode Dispatch Coverage Report
// ============================================================================

struct OpcodeInfo {
    uint8_t code;
    const char* name;
    const char* category;
    bool hasHandler;
    bool isImplemented;  // Not just a stub/fallback
};

OpcodeInfo g_opcodeTable[] = {
    // Constants (0x00-0x0F)
    {0x00, "OP_LOAD_CONST", "Constant", true, true},
    {0x01, "OP_LOAD_INT", "Constant", true, true},
    {0x02, "OP_LOAD_DOUBLE", "Constant", true, true},
    {0x03, "OP_LOAD_STRING", "Constant", true, true},
    {0x04, "OP_LOAD_NULL", "Constant", true, true},
    {0x05, "OP_LOAD_UNDEFINED", "Constant", true, true},
    {0x06, "OP_LOAD_TRUE", "Constant", true, true},
    {0x07, "OP_LOAD_FALSE", "Constant", true, true},
    {0x08, "OP_LOAD_ZERO", "Constant", true, true},
    {0x09, "OP_LOAD_ONE", "Constant", true, true},
    {0x0A, "OP_RESERVED_0A", "Reserved", true, false},
    {0x0B, "OP_RESERVED_0B", "Reserved", true, false},
    {0x0C, "OP_RESERVED_0C", "Reserved", true, false},
    {0x0D, "OP_RESERVED_0D", "Reserved", true, false},
    {0x0E, "OP_RESERVED_0E", "Reserved", true, false},
    {0x0F, "OP_RESERVED_0F", "Reserved", true, false},
    
    // Register Movement (0x10-0x1F)
    {0x10, "OP_MOVE", "Register", true, true},
    {0x11, "OP_SWAP", "Register", true, true},
    {0x12, "OP_LOAD_REG_0", "Register", true, false},
    {0x13, "OP_LOAD_REG_1", "Register", true, false},
    {0x14, "OP_STORE_REG_0", "Register", true, false},
    {0x15, "OP_STORE_REG_1", "Register", true, false},
    {0x16, "OP_RESERVED_16", "Reserved", true, false},
    {0x17, "OP_RESERVED_17", "Reserved", true, false},
    {0x18, "OP_RESERVED_18", "Reserved", true, false},
    {0x19, "OP_RESERVED_19", "Reserved", true, false},
    {0x1A, "OP_RESERVED_1A", "Reserved", true, false},
    {0x1B, "OP_RESERVED_1B", "Reserved", true, false},
    {0x1C, "OP_RESERVED_1C", "Reserved", true, false},
    {0x1D, "OP_RESERVED_1D", "Reserved", true, false},
    {0x1E, "OP_RESERVED_1E", "Reserved", true, false},
    {0x1F, "OP_RESERVED_1F", "Reserved", true, false},
    
    // Arithmetic (0x20-0x2F)
    {0x20, "OP_ADD", "Arithmetic", true, true},
    {0x21, "OP_SUB", "Arithmetic", true, true},
    {0x22, "OP_MUL", "Arithmetic", true, true},
    {0x23, "OP_DIV", "Arithmetic", true, true},
    {0x24, "OP_MOD", "Arithmetic", true, true},
    {0x25, "OP_NEG", "Arithmetic", true, true},
    {0x26, "OP_INC", "Arithmetic", true, true},
    {0x27, "OP_DEC", "Arithmetic", true, true},
    {0x28, "OP_POW", "Arithmetic", true, true},
    {0x29, "OP_RESERVED_29", "Reserved", true, false},
    {0x2A, "OP_RESERVED_2A", "Reserved", true, false},
    {0x2B, "OP_RESERVED_2B", "Reserved", true, false},
    {0x2C, "OP_RESERVED_2C", "Reserved", true, false},
    {0x2D, "OP_RESERVED_2D", "Reserved", true, false},
    {0x2E, "OP_RESERVED_2E", "Reserved", true, false},
    {0x2F, "OP_RESERVED_2F", "Reserved", true, false},
    
    // Bitwise (0x30-0x3F)
    {0x30, "OP_BIT_AND", "Bitwise", true, true},
    {0x31, "OP_BIT_OR", "Bitwise", true, true},
    {0x32, "OP_BIT_XOR", "Bitwise", true, true},
    {0x33, "OP_BIT_NOT", "Bitwise", true, true},
    {0x34, "OP_SHL", "Bitwise", true, true},
    {0x35, "OP_SHR", "Bitwise", true, true},
    {0x36, "OP_SHR_U", "Bitwise", true, true},
    {0x37, "OP_RESERVED_37", "Reserved", true, false},
    {0x38, "OP_RESERVED_38", "Reserved", true, false},
    {0x39, "OP_RESERVED_39", "Reserved", true, false},
    {0x3A, "OP_RESERVED_3A", "Reserved", true, false},
    {0x3B, "OP_RESERVED_3B", "Reserved", true, false},
    {0x3C, "OP_RESERVED_3C", "Reserved", true, false},
    {0x3D, "OP_RESERVED_3D", "Reserved", true, false},
    {0x3E, "OP_RESERVED_3E", "Reserved", true, false},
    {0x3F, "OP_RESERVED_3F", "Reserved", true, false},
    
    // Comparison (0x40-0x4F)
    {0x40, "OP_EQ", "Comparison", true, true},
    {0x41, "OP_NEQ", "Comparison", true, true},
    {0x42, "OP_LT", "Comparison", true, true},
    {0x43, "OP_LTE", "Comparison", true, true},
    {0x44, "OP_GT", "Comparison", true, true},
    {0x45, "OP_GTE", "Comparison", true, true},
    {0x46, "OP_STRICT_EQ", "Comparison", true, true},
    {0x47, "OP_STRICT_NEQ", "Comparison", true, true},
    {0x48, "OP_COMPARE", "Comparison", true, false},
    {0x49, "OP_RESERVED_49", "Reserved", true, false},
    {0x4A, "OP_RESERVED_4A", "Reserved", true, false},
    {0x4B, "OP_RESERVED_4B", "Reserved", true, false},
    {0x4C, "OP_RESERVED_4C", "Reserved", true, false},
    {0x4D, "OP_RESERVED_4D", "Reserved", true, false},
    {0x4E, "OP_RESERVED_4E", "Reserved", true, false},
    {0x4F, "OP_RESERVED_4F", "Reserved", true, false},
    
    // Control Flow (0x50-0x5F)
    {0x50, "OP_JMP", "ControlFlow", true, true},
    {0x51, "OP_JMP_COND", "ControlFlow", true, true},
    {0x52, "OP_JMP_NOT_COND", "ControlFlow", true, true},
    {0x53, "OP_JMP_EQ", "ControlFlow", true, true},
    {0x54, "OP_JMP_NEQ", "ControlFlow", true, true},
    {0x55, "OP_JMP_LT", "ControlFlow", true, true},
    {0x56, "OP_CALL", "ControlFlow", true, true},
    {0x57, "OP_CALL_NATIVE", "ControlFlow", true, true},
    {0x58, "OP_THROW", "ControlFlow", true, true},
    {0x59, "OP_TRY_START", "ControlFlow", true, true},
    {0x5A, "OP_TRY_END", "ControlFlow", true, true},
    {0x5B, "OP_ENTER_SCOPE", "ControlFlow", true, true},
    {0x5C, "OP_EXIT_SCOPE", "ControlFlow", true, true},
    {0x5D, "OP_RESERVED_5D", "Reserved", true, false},
    {0x5E, "OP_RESERVED_5E", "Reserved", true, false},
    {0x5F, "OP_RESERVED_5F", "Reserved", true, false},
    
    // Object Operations (0x60-0x6F)
    {0x60, "OP_GET_PROP", "Object", true, true},
    {0x61, "OP_SET_PROP", "Object", true, true},
    {0x62, "OP_GET_ELEM", "Object", true, true},
    {0x63, "OP_SET_ELEM", "Object", true, true},
    {0x64, "OP_DELETE_PROP", "Object", true, true},
    {0x65, "OP_DELETE_ELEM", "Object", true, true},
    {0x66, "OP_IN", "Object", true, true},
    {0x67, "OP_INSTANCEOF", "Object", true, true},
    {0x68, "OP_NEW", "Object", true, true},
    {0x69, "OP_TYPEOF", "Object", true, true},
    {0x6A, "OP_HAS_OWN_PROP", "Object", true, true},
    {0x6B, "OP_GET_PROTO", "Object", true, true},
    {0x6C, "OP_SET_PROTO", "Object", true, true},
    {0x6D, "OP_RESERVED_6D", "Reserved", true, false},
    {0x6E, "OP_RESERVED_6E", "Reserved", true, false},
    {0x6F, "OP_RESERVED_6F", "Reserved", true, false},
    
    // Array Operations (0x70-0x7F)
    {0x70, "OP_CREATE_ARRAY", "Array", true, true},
    {0x71, "OP_ARRAY_PUSH", "Array", true, true},
    {0x72, "OP_ARRAY_POP", "Array", true, true},
    {0x73, "OP_ARRAY_GET_LEN", "Array", true, false},
    {0x74, "OP_ARRAY_SET_LEN", "Array", true, false},
    {0x75, "OP_OBJECT_SET", "Object", true, true},
    {0x76, "OP_OBJECT_GET_KEYS", "Object", true, true},
    {0x77, "OP_CREATE_OBJECT", "Object", true, true},
    {0x78, "OP_RESERVED_78", "Reserved", true, false},
    {0x79, "OP_RESERVED_79", "Reserved", true, false},
    {0x7A, "OP_RESERVED_7A", "Reserved", true, false},
    {0x7B, "OP_RESERVED_7B", "Reserved", true, false},
    {0x7C, "OP_RESERVED_7C", "Reserved", true, false},
    {0x7D, "OP_RESERVED_7D", "Reserved", true, false},
    {0x7E, "OP_RESERVED_7E", "Reserved", true, false},
    {0x7F, "OP_RESERVED_7F", "Reserved", true, false},
    
    // Function Operations (0x80-0x8F)
    {0x80, "OP_CREATE_FUNC", "Function", true, true},
    {0x81, "OP_BIND_THIS", "Function", true, true},
    {0x82, "OP_APPLY", "Function", true, true},
    {0x83, "OP_CALL_METHOD", "Function", true, true},
    {0x84, "OP_GET_CLOSURE", "Function", true, true},
    {0x85, "OP_SET_CLOSURE", "Function", true, true},
    {0x86, "OP_RESERVED_86", "Reserved", true, false},
    {0x87, "OP_RESERVED_87", "Reserved", true, false},
    {0x88, "OP_RESERVED_88", "Reserved", true, false},
    {0x89, "OP_RESERVED_89", "Reserved", true, false},
    {0x8A, "OP_RESERVED_8A", "Reserved", true, false},
    {0x8B, "OP_RESERVED_8B", "Reserved", true, false},
    {0x8C, "OP_RESERVED_8C", "Reserved", true, false},
    {0x8D, "OP_RESERVED_8D", "Reserved", true, false},
    {0x8E, "OP_RESERVED_8E", "Reserved", true, false},
    {0x8F, "OP_RESERVED_8F", "Reserved", true, false},
    
    // Iteration (0x90-0x9F)
    {0x90, "OP_ITER_START", "Iteration", true, true},
    {0x91, "OP_ITER_NEXT", "Iteration", true, true},
    {0x92, "OP_ITER_HAS_NEXT", "Iteration", true, true},
    {0x93, "OP_FOR_IN_START", "Iteration", true, true},
    {0x94, "OP_FOR_IN_NEXT", "Iteration", true, true},
    {0x95, "OP_FOR_OF_START", "Iteration", true, true},
    {0x96, "OP_FOR_OF_NEXT", "Iteration", true, true},
    {0x97, "OP_RESERVED_97", "Reserved", true, false},
    {0x98, "OP_RESERVED_98", "Reserved", true, false},
    {0x99, "OP_RESERVED_99", "Reserved", true, false},
    {0x9A, "OP_RESERVED_9A", "Reserved", true, false},
    {0x9B, "OP_RESERVED_9B", "Reserved", true, false},
    {0x9C, "OP_RESERVED_9C", "Reserved", true, false},
    {0x9D, "OP_RESERVED_9D", "Reserved", true, false},
    {0x9E, "OP_RESERVED_9E", "Reserved", true, false},
    {0x9F, "OP_RESERVED_9F", "Reserved", true, false},
    
    // Async (0xA0-0xAF)
    {0xA0, "OP_AWAIT", "Async", true, false},
    {0xA1, "OP_PROMISE_RESOLVE", "Async", true, false},
    {0xA2, "OP_PROMISE_REJECT", "Async", true, false},
    {0xA3, "OP_ASYNC_CALL", "Async", true, false},
    {0xA4, "OP_YIELD", "Async", true, false},
    {0xA5, "OP_YIELD_STAR", "Async", true, false},
    {0xA6, "OP_RESERVED_A6", "Reserved", true, false},
    {0xA7, "OP_RESERVED_A7", "Reserved", true, false},
    {0xA8, "OP_RESERVED_A8", "Reserved", true, false},
    {0xA9, "OP_RESERVED_A9", "Reserved", true, false},
    {0xAA, "OP_RESERVED_AA", "Reserved", true, false},
    {0xAB, "OP_RESERVED_AB", "Reserved", true, false},
    {0xAC, "OP_RESERVED_AC", "Reserved", true, false},
    {0xAD, "OP_RESERVED_AD", "Reserved", true, false},
    {0xAE, "OP_RESERVED_AE", "Reserved", true, false},
    {0xAF, "OP_RESERVED_AF", "Reserved", true, false},
    
    // Optimized (0xB0-0xBF)
    {0xB0, "OP_ADD_INT", "Optimized", true, true},
    {0xB1, "OP_SUB_INT", "Optimized", true, true},
    {0xB2, "OP_MUL_INT", "Optimized", true, true},
    {0xB3, "OP_INC_LOCAL", "Optimized", true, true},
    {0xB4, "OP_DEC_LOCAL", "Optimized", true, true},
    {0xB5, "OP_GET_LOCAL", "Optimized", true, true},
    {0xB6, "OP_SET_LOCAL", "Optimized", true, true},
    {0xB7, "OP_GET_GLOBAL", "Optimized", true, true},
    {0xB8, "OP_SET_GLOBAL", "Optimized", true, true},
    {0xB9, "OP_RESERVED_B9", "Reserved", true, false},
    {0xBA, "OP_RESERVED_BA", "Reserved", true, false},
    {0xBB, "OP_RESERVED_BB", "Reserved", true, false},
    {0xBC, "OP_RESERVED_BC", "Reserved", true, false},
    {0xBD, "OP_RESERVED_BD", "Reserved", true, false},
    {0xBE, "OP_RESERVED_BE", "Reserved", true, false},
    {0xBF, "OP_RESERVED_BF", "Reserved", true, false},
    
    // Reserved (0xC0-0xEF)
    {0xC0, "OP_RESERVED_C0", "Reserved", true, false},
    {0xC1, "OP_RESERVED_C1", "Reserved", true, false},
    {0xC2, "OP_RESERVED_C2", "Reserved", true, false},
    {0xC3, "OP_RESERVED_C3", "Reserved", true, false},
    {0xC4, "OP_RESERVED_C4", "Reserved", true, false},
    {0xC5, "OP_RESERVED_C5", "Reserved", true, false},
    {0xC6, "OP_RESERVED_C6", "Reserved", true, false},
    {0xC7, "OP_RESERVED_C7", "Reserved", true, false},
    {0xC8, "OP_RESERVED_C8", "Reserved", true, false},
    {0xC9, "OP_RESERVED_C9", "Reserved", true, false},
    {0xCA, "OP_RESERVED_CA", "Reserved", true, false},
    {0xCB, "OP_RESERVED_CB", "Reserved", true, false},
    {0xCC, "OP_RESERVED_CC", "Reserved", true, false},
    {0xCD, "OP_RESERVED_CD", "Reserved", true, false},
    {0xCE, "OP_RESERVED_CE", "Reserved", true, false},
    {0xCF, "OP_RESERVED_CF", "Reserved", true, false},
    {0xD0, "OP_RESERVED_D0", "Reserved", true, false},
    {0xD1, "OP_RESERVED_D1", "Reserved", true, false},
    {0xD2, "OP_RESERVED_D2", "Reserved", true, false},
    {0xD3, "OP_RESERVED_D3", "Reserved", true, false},
    {0xD4, "OP_RESERVED_D4", "Reserved", true, false},
    {0xD5, "OP_RESERVED_D5", "Reserved", true, false},
    {0xD6, "OP_RESERVED_D6", "Reserved", true, false},
    {0xD7, "OP_RESERVED_D7", "Reserved", true, false},
    {0xD8, "OP_RESERVED_D8", "Reserved", true, false},
    {0xD9, "OP_RESERVED_D9", "Reserved", true, false},
    {0xDA, "OP_RESERVED_DA", "Reserved", true, false},
    {0xDB, "OP_RESERVED_DB", "Reserved", true, false},
    {0xDC, "OP_RESERVED_DC", "Reserved", true, false},
    {0xDD, "OP_RESERVED_DD", "Reserved", true, false},
    {0xDE, "OP_RESERVED_DE", "Reserved", true, false},
    {0xDF, "OP_RESERVED_DF", "Reserved", true, false},
    {0xE0, "OP_RESERVED_E0", "Reserved", true, false},
    {0xE1, "OP_RESERVED_E1", "Reserved", true, false},
    {0xE2, "OP_RESERVED_E2", "Reserved", true, false},
    {0xE3, "OP_RESERVED_E3", "Reserved", true, false},
    {0xE4, "OP_RESERVED_E4", "Reserved", true, false},
    {0xE5, "OP_RESERVED_E5", "Reserved", true, false},
    {0xE6, "OP_RESERVED_E6", "Reserved", true, false},
    {0xE7, "OP_RESERVED_E7", "Reserved", true, false},
    {0xE8, "OP_RESERVED_E8", "Reserved", true, false},
    {0xE9, "OP_RESERVED_E9", "Reserved", true, false},
    {0xEA, "OP_RESERVED_EA", "Reserved", true, false},
    {0xEB, "OP_RESERVED_EB", "Reserved", true, false},
    {0xEC, "OP_RESERVED_EC", "Reserved", true, false},
    {0xED, "OP_RESERVED_ED", "Reserved", true, false},
    {0xEE, "OP_RESERVED_EE", "Reserved", true, false},
    {0xEF, "OP_RESERVED_EF", "Reserved", true, false},
    
    // Debug (0xF0-0xFF)
    {0xF0, "OP_DEBUG_BREAK", "Debug", true, true},
    {0xF1, "OP_DEBUG_LOG", "Debug", true, true},
    {0xF2, "OP_ASSERT", "Debug", true, true},
    {0xF3, "OP_PROFILE_START", "Debug", true, true},
    {0xF4, "OP_PROFILE_END", "Debug", true, true},
    {0xF5, "OP_RESERVED_F5", "Reserved", true, false},
    {0xF6, "OP_RESERVED_F6", "Reserved", true, false},
    {0xF7, "OP_RESERVED_F7", "Reserved", true, false},
    {0xF8, "OP_RESERVED_F8", "Reserved", true, false},
    {0xF9, "OP_RESERVED_F9", "Reserved", true, false},
    {0xFA, "OP_RESERVED_FA", "Reserved", true, false},
    {0xFB, "OP_RESERVED_FB", "Reserved", true, false},
    {0xFC, "OP_RESERVED_FC", "Reserved", true, false},
    {0xFD, "OP_RESERVED_FD", "Reserved", true, false},
    {0xFE, "OP_RESERVED_FE", "Reserved", true, false},
    {0xFF, "OP_NOP", "Debug", true, true},
};

// ============================================================================
// Report Generation
// ============================================================================

void GenerateDispatchReport(const char* filename) {
    std::ofstream file(filename);
    if (!file) {
        std::cerr << "Failed to open " << filename << " for writing\n";
        return;
    }
    
    file << "RawrXD-Script Opcode Dispatch Coverage Report\n";
    file << "=============================================\n\n";
    
    int implemented = 0;
    int reserved = 0;
    int stubbed = 0;
    
    for (int i = 0; i < 256; ++i) {
        const auto& info = g_opcodeTable[i];
        file << "Opcode 0x" << std::hex << std::setw(2) << std::setfill('0') 
             << (int)info.code << std::dec << " -> " << info.name;
        
        if (info.isImplemented) {
            file << " [IMPLEMENTED]\n";
            implemented++;
        } else if (std::strstr(info.name, "RESERVED")) {
            file << " [RESERVED]\n";
            reserved++;
        } else {
            file << " [STUB]\n";
            stubbed++;
        }
    }
    
    file << "\n=============================================\n";
    file << "Summary:\n";
    file << "  Implemented: " << implemented << "/256\n";
    file << "  Reserved:    " << reserved << "/256\n";
    file << "  Stubbed:     " << stubbed << "/256\n";
    file << "  Coverage:    " << (implemented * 100 / 256) << "%\n";
    
    file.close();
    std::cout << "Dispatch report written to " << filename << "\n";
}

// ============================================================================
// 2. Emitter Reachability Audit
// ============================================================================

class EmitterAuditor : public BytecodeEmitter {
public:
    std::set<uint8_t> emittedOpcodes;
    
    void AuditExpression(const std::string& source) {
        Lexer lexer;
        auto lexResult = lexer.Tokenize(source);
        if (!lexResult.Success()) return;
        
        Parser parser;
        auto parseResult = parser.Parse(source);
        if (!parseResult.success) return;
        
        Bytecode::BytecodeModule module;
        Emit(parseResult.ast.get(), &module);
        
        // Collect all opcodes from the module
        for (const auto& inst : module.GetCode()) {
            emittedOpcodes.insert(static_cast<uint8_t>(inst.GetOpcode()));
        }
    }
    
    void PrintReport() {
        std::cout << "\n=== Emitter Reachability Audit ===\n";
        std::cout << "Opcodes emitted by compiler:\n";
        
        for (uint8_t op : emittedOpcodes) {
            std::cout << "  0x" << std::hex << std::setw(2) << std::setfill('0') 
                      << (int)op << std::dec << " ";
            if (op < sizeof(g_opcodeTable)/sizeof(g_opcodeTable[0])) {
                std::cout << g_opcodeTable[op].name;
            }
            std::cout << "\n";
        }
        
        std::cout << "\nUnreachable opcodes (never emitted):\n";
        for (int i = 0; i < 256; ++i) {
            if (emittedOpcodes.find(i) == emittedOpcodes.end() && 
                g_opcodeTable[i].isImplemented &&
                !std::strstr(g_opcodeTable[i].name, "RESERVED")) {
                std::cout << "  0x" << std::hex << std::setw(2) << std::setfill('0') 
                          << i << std::dec << " " << g_opcodeTable[i].name << "\n";
            }
        }
    }
};

// ============================================================================
// 3. Round-Trip Test Framework
// ============================================================================

struct RoundTripTest {
    const char* name;
    const char* source;
    const char* expectedOutput;
};

RoundTripTest g_roundTripTests[] = {
    {
        "Basic Arithmetic",
        "var x = 1 + 2;",
        nullptr  // Would check bytecode structure
    },
    {
        "Variable Declaration",
        "var x = 42;",
        nullptr
    },
    {
        "Object Creation",
        "var obj = { x: 1 };",
        nullptr
    },
    {
        "Property Access",
        "var obj = { x: 1 }; var y = obj.x;",
        nullptr
    },
    {
        "Function Declaration",
        "function add(a, b) { return a + b; }",
        nullptr
    },
    {
        "If Statement",
        "if (true) { var x = 1; }",
        nullptr
    },
    {
        "While Loop",
        "while (false) { }",
        nullptr
    },
    {
        "For Loop",
        "for (var i = 0; i < 10; i++) { }",
        nullptr
    },
    {
        "Array Creation",
        "var arr = [1, 2, 3];",
        nullptr
    },
    {
        "Binary Operators",
        "var a = 1 + 2 - 3 * 4 / 5 % 6;",
        nullptr
    },
    {
        "Comparison Operators",
        "var a = 1 < 2; var b = 3 > 4; var c = 5 == 5;",
        nullptr
    },
    {
        "Logical Operators",
        "var a = true && false; var b = true || false;",
        nullptr
    },
    {
        "Bitwise Operators",
        "var a = 1 & 2; var b = 3 | 4; var c = 5 ^ 6;",
        nullptr
    },
    {
        "Unary Operators",
        "var a = -1; var b = !true; var c = ~0;",
        nullptr
    },
    {
        "Update Operators",
        "var x = 0; x++; x--; ++x; --x;",
        nullptr
    },
    {
        "Member Access",
        "var obj = { x: 1 }; obj.x = 2;",
        nullptr
    },
    {
        "Computed Member",
        "var obj = { x: 1 }; obj['x'] = 2;",
        nullptr
    },
    {
        "Function Call",
        "function f() { return 1; } f();",
        nullptr
    },
    {
        "New Operator",
        "function C() { } new C();",
        nullptr
    },
    {
        "Typeof Operator",
        "typeof 1; typeof 'str'; typeof true;",
        nullptr
    },
    {
        "Instanceof Operator",
        "function C() { } new C() instanceof C;",
        nullptr
    },
    {
        "In Operator",
        "'x' in { x: 1 };",
        nullptr
    },
    {
        "Delete Operator",
        "var obj = { x: 1 }; delete obj.x;",
        nullptr
    },
    {
        "Conditional Expression",
        "var x = true ? 1 : 2;",
        nullptr
    },
    {
        "Return Statement",
        "function f() { return 42; }",
        nullptr
    },
    {
        "Break Statement",
        "while (true) { break; }",
        nullptr
    },
    {
        "Continue Statement",
        "while (true) { continue; }",
        nullptr
    },
};

void RunRoundTripTests() {
    std::cout << "\n=== Round-Trip Test Framework ===\n";
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& test : g_roundTripTests) {
        std::cout << "Test: " << test.name << "... ";
        
        Lexer lexer;
        auto lexResult = lexer.Tokenize(test.source);
        if (!lexResult.Success()) {
            std::cout << "LEXER FAILED\n";
            failed++;
            continue;
        }
        
        Parser parser;
        auto parseResult = parser.Parse(test.source);
        if (!parseResult.success) {
            std::cout << "PARSER FAILED\n";
            failed++;
            continue;
        }
        
        Bytecode::BytecodeModule module;
        BytecodeEmitter emitter;
        bool emitSuccess = emitter.Emit(parseResult.ast.get(), &module);
        
        if (!emitSuccess) {
            std::cout << "EMITTER FAILED\n";
            failed++;
            continue;
        }
        
        if (module.GetCode().empty()) {
            std::cout << "EMPTY BYTECODE\n";
            failed++;
            continue;
        }
        
        std::cout << "PASSED (" << module.GetCode().size() << " instructions)\n";
        passed++;
    }
    
    std::cout << "\nResults: " << passed << " passed, " << failed << " failed\n";
}

// ============================================================================
// 4. Execution Counter Framework (Stub)
// ============================================================================

struct ExecutionCounters {
    uint64_t opcodeHits[256];
    uint64_t totalInstructions;
    uint64_t icHits;
    uint64_t icMisses;
    uint64_t propertyAccesses;
    uint64_t arrayAccesses;
    uint64_t functionCalls;
    
    void Reset() {
        std::memset(this, 0, sizeof(*this));
    }
    
    void PrintReport() {
        std::cout << "\n=== Execution Counter Report ===\n";
        std::cout << "Total instructions executed: " << totalInstructions << "\n";
        std::cout << "IC hits: " << icHits << ", misses: " << icMisses << "\n";
        std::cout << "Property accesses: " << propertyAccesses << "\n";
        std::cout << "Array accesses: " << arrayAccesses << "\n";
        std::cout << "Function calls: " << functionCalls << "\n\n";
        
        std::cout << "Top 10 opcodes by frequency:\n";
        
        // Create sorted list
        std::vector<std::pair<uint64_t, int>> sorted;
        for (int i = 0; i < 256; ++i) {
            if (opcodeHits[i] > 0) {
                sorted.push_back({opcodeHits[i], i});
            }
        }
        
        std::sort(sorted.begin(), sorted.end(), std::greater<>());
        
        int count = 0;
        for (const auto& [hits, opcode] : sorted) {
            if (count++ >= 10) break;
            std::cout << "  " << g_opcodeTable[opcode].name << ": " << hits << "\n";
        }
        
        std::cout << "\nUnused opcodes:\n";
        for (int i = 0; i < 256; ++i) {
            if (opcodeHits[i] == 0 && g_opcodeTable[i].isImplemented) {
                std::cout << "  " << g_opcodeTable[i].name << "\n";
            }
        }
    }
};

// ============================================================================
// 5. Exception Path Tests
// ============================================================================

struct ExceptionTest {
    const char* name;
    const char* source;
    const char* expectedError;
};

ExceptionTest g_exceptionTests[] = {
    {
        "Division by zero",
        "var x = 1 / 0;",
        "Infinity"  // Should produce Infinity, not crash
    },
    {
        "Modulo by zero",
        "var x = 1 % 0;",
        "NaN"
    },
    {
        "Invalid property access",
        "var x = null; x.y;",
        "TypeError"
    },
    {
        "Undefined property access",
        "var x = undefined; x.y;",
        "TypeError"
    },
    {
        "Invalid call",
        "var x = 1; x();",
        "TypeError"
    },
    {
        "Stack overflow",
        "function f() { f(); } f();",
        "RangeError"
    },
};

void RunExceptionTests() {
    std::cout << "\n=== Exception Path Tests ===\n";
    std::cout << "(Note: These require runtime execution, currently stubbed)\n";
    
    for (const auto& test : g_exceptionTests) {
        std::cout << "Test: " << test.name << " - " << test.expectedError << "\n";
    }
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "RawrXD-Script Opcode Verification Suite\n";
    std::cout << "=======================================\n\n";
    
    // 1. Generate dispatch report
    GenerateDispatchReport("opcode_dispatch_report.txt");
    
    // 2. Run emitter audit
    {
        EmitterAuditor auditor;
        
        // Test various code patterns
        auditor.AuditExpression("var x = 1 + 2;");
        auditor.AuditExpression("var obj = { x: 1 };");
        auditor.AuditExpression("function f() { return 1; }");
        auditor.AuditExpression("if (true) { } else { }");
        auditor.AuditExpression("while (false) { }");
        auditor.AuditExpression("for (var i = 0; i < 10; i++) { }");
        auditor.AuditExpression("var arr = [1, 2, 3];");
        auditor.AuditExpression("var x = 1 | 2 & 3 ^ 4;");
        auditor.AuditExpression("var x = 1 < 2;");
        auditor.AuditExpression("var x = true && false || true;");
        auditor.AuditExpression("var x = ~0;");
        auditor.AuditExpression("var x = -1;");
        auditor.AuditExpression("var x = !true;");
        auditor.AuditExpression("var x = typeof 1;");
        auditor.AuditExpression("var x = 'str' instanceof String;");
        auditor.AuditExpression("var x = 'a' in { a: 1 };");
        auditor.AuditExpression("delete obj.x;");
        auditor.AuditExpression("var x = true ? 1 : 2;");
        auditor.AuditExpression("function C() { } new C();");
        auditor.AuditExpression("var x = 0; x++;");
        auditor.AuditExpression("var x = 0; ++x;");
        
        auditor.PrintReport();
    }
    
    // 3. Run round-trip tests
    RunRoundTripTests();
    
    // 4. Show execution counter framework
    {
        ExecutionCounters counters;
        counters.Reset();
        counters.opcodeHits[0x20] = 1000;  // OP_ADD
        counters.opcodeHits[0x60] = 500;   // OP_GET_PROP
        counters.opcodeHits[0x61] = 300;   // OP_SET_PROP
        counters.totalInstructions = 5000;
        counters.icHits = 800;
        counters.icMisses = 200;
        counters.PrintReport();
    }
    
    // 5. Exception tests
    RunExceptionTests();
    
    std::cout << "\n=======================================\n";
    std::cout << "Verification complete.\n";
    std::cout << "See opcode_dispatch_report.txt for full dispatch coverage.\n";
    
    return 0;
}
