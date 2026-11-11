// RawrXD-Script Bytecode Disassembler
// Tool for inspecting and debugging emitted bytecode
//
// Usage: rawrxd-disasm <file.rawr>
// Output: Human-readable disassembly

#include "../bytecode/bytecode_contract.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <vector>

using namespace RawrXD::Script::Bytecode;

// Opcode names for disassembly
const char* GetOpcodeName(uint8_t opcode) {
    switch (static_cast<Opcode>(opcode)) {
        // Control Flow
        case Opcode::kNop: return "nop";
        case Opcode::kReturn: return "return";
        case Opcode::kReturnUndefined: return "return_undefined";
        case Opcode::kJump: return "jump";
        case Opcode::kJumpIfTrue: return "jump_if_true";
        case Opcode::kJumpIfFalse: return "jump_if_false";
        case Opcode::kJumpIfEqual: return "jump_if_eq";
        case Opcode::kJumpIfNotEqual: return "jump_if_ne";
        case Opcode::kCall: return "call";
        case Opcode::kCallNative: return "call_native";
        case Opcode::kTailCall: return "tail_call";
        case Opcode::kEnterTry: return "enter_try";
        case Opcode::kLeaveTry: return "leave_try";
        case Opcode::kThrow: return "throw";
        case Opcode::kDebugger: return "debugger";
        case Opcode::kHalt: return "halt";
        
        // Constants
        case Opcode::kLoadConst: return "load_const";
        case Opcode::kLoadUndefined: return "load_undefined";
        case Opcode::kLoadNull: return "load_null";
        case Opcode::kLoadTrue: return "load_true";
        case Opcode::kLoadFalse: return "load_false";
        case Opcode::kLoadZero: return "load_zero";
        case Opcode::kLoadOne: return "load_one";
        case Opcode::kLoadInt: return "load_int";
        case Opcode::kLoadString: return "load_string";
        case Opcode::kLoadGlobal: return "load_global";
        case Opcode::kStoreGlobal: return "store_global";
        case Opcode::kLoadEnv: return "load_env";
        case Opcode::kStoreEnv: return "store_env";
        case Opcode::kReserve: return "reserve";
        case Opcode::kMove: return "move";
        case Opcode::kSwap: return "swap";
        
        // Arithmetic
        case Opcode::kAdd: return "add";
        case Opcode::kSub: return "sub";
        case Opcode::kMul: return "mul";
        case Opcode::kDiv: return "div";
        case Opcode::kMod: return "mod";
        case Opcode::kNeg: return "neg";
        case Opcode::kInc: return "inc";
        case Opcode::kDec: return "dec";
        case Opcode::kPow: return "pow";
        case Opcode::kSqrt: return "sqrt";
        case Opcode::kAbs: return "abs";
        case Opcode::kMin: return "min";
        case Opcode::kMax: return "max";
        case Opcode::kClamp: return "clamp";
        case Opcode::kFloor: return "floor";
        case Opcode::kCeil: return "ceil";
        
        // Bitwise
        case Opcode::kBitAnd: return "bit_and";
        case Opcode::kBitOr: return "bit_or";
        case Opcode::kBitXor: return "bit_xor";
        case Opcode::kBitNot: return "bit_not";
        case Opcode::kShiftLeft: return "shift_left";
        case Opcode::kShiftRight: return "shift_right";
        case Opcode::kShiftRightUnsigned: return "shift_right_u";
        
        // Comparison
        case Opcode::kEq: return "eq";
        case Opcode::kNe: return "ne";
        case Opcode::kLt: return "lt";
        case Opcode::kLe: return "le";
        case Opcode::kGt: return "gt";
        case Opcode::kGe: return "ge";
        case Opcode::kStrictEq: return "strict_eq";
        case Opcode::kStrictNe: return "strict_ne";
        
        // Logical
        case Opcode::kLogicalAnd: return "logical_and";
        case Opcode::kLogicalOr: return "logical_or";
        case Opcode::kLogicalNot: return "logical_not";
        case Opcode::kCoalesce: return "coalesce";
        case Opcode::kTypeOf: return "typeof";
        case Opcode::kVoid: return "void";
        case Opcode::kDelete: return "delete";
        
        // Objects
        case Opcode::kNewObject: return "new_object";
        case Opcode::kGetProp: return "get_prop";
        case Opcode::kSetProp: return "set_prop";
        case Opcode::kDefineProp: return "define_prop";
        case Opcode::kDeleteProp: return "delete_prop";
        case Opcode::kHasProp: return "has_prop";
        
        // Arrays
        case Opcode::kNewArray: return "new_array";
        case Opcode::kArrayPush: return "array_push";
        case Opcode::kArrayPop: return "array_pop";
        case Opcode::kArrayLength: return "array_length";
        
        // Functions
        case Opcode::kNewFunction: return "new_function";
        case Opcode::kBind: return "bind";
        case Opcode::kApply: return "apply";
        case Opcode::kCallMethod: return "call_method";
        
        // Exceptions
        case Opcode::kTryStart: return "try_start";
        case Opcode::kCatch: return "catch";
        case Opcode::kFinally: return "finally";
        case Opcode::kTryEnd: return "try_end";
        
        // Type checks
        case Opcode::kIsNumber: return "is_number";
        case Opcode::kIsString: return "is_string";
        case Opcode::kIsBoolean: return "is_boolean";
        case Opcode::kIsObject: return "is_object";
        case Opcode::kIsFunction: return "is_function";
        case Opcode::kIsArray: return "is_array";
        case Opcode::kIsNull: return "is_null";
        case Opcode::kIsUndefined: return "is_undefined";
        
        // String
        case Opcode::kStringConcat: return "string_concat";
        case Opcode::kStringSlice: return "string_slice";
        case Opcode::kStringIndexOf: return "string_index_of";
        
        // Debug
        case Opcode::kBreakpoint: return "breakpoint";
        case Opcode::kTrace: return "trace";
        case Opcode::kAssert: return "assert";
        case Opcode::kLog: return "log";
        case Opcode::kWarn: return "warn";
        case Opcode::kError: return "error";
        
        default: return "unknown";
    }
}

// Format instruction as string
void FormatInstruction(const Instruction& instr, char* buffer, size_t bufferSize) {
    uint8_t opcode = instr.Opcode();
    uint8_t dst = instr.Dst();
    uint8_t srcA = instr.SrcA();
    uint8_t srcB = instr.SrcB();
    int16_t imm = instr.Imm12Signed();
    
    const char* name = GetOpcodeName(opcode);
    
    // Format based on opcode category
    if (opcode >= 0x10 && opcode <= 0x1F) {
        // Load operations
        if (opcode == static_cast<uint8_t>(Opcode::kLoadInt)) {
            snprintf(buffer, bufferSize, "%s v%d, %d", name, dst, imm);
        } else if (opcode == static_cast<uint8_t>(Opcode::kLoadConst)) {
            snprintf(buffer, bufferSize, "%s v%d, const[%d]", name, dst, srcA);
        } else {
            snprintf(buffer, bufferSize, "%s v%d", name, dst);
        }
    } else if (opcode >= 0x20 && opcode <= 0x2F) {
        // Arithmetic
        if (opcode == static_cast<uint8_t>(Opcode::kNeg) ||
            opcode == static_cast<uint8_t>(Opcode::kInc) ||
            opcode == static_cast<uint8_t>(Opcode::kDec) ||
            opcode == static_cast<uint8_t>(Opcode::kSqrt) ||
            opcode == static_cast<uint8_t>(Opcode::kAbs) ||
            opcode == static_cast<uint8_t>(Opcode::kFloor) ||
            opcode == static_cast<uint8_t>(Opcode::kCeil)) {
            snprintf(buffer, bufferSize, "%s v%d, v%d", name, dst, srcA);
        } else {
            snprintf(buffer, bufferSize, "%s v%d, v%d, v%d", name, dst, srcA, srcB);
        }
    } else if (opcode >= 0x03 && opcode <= 0x07) {
        // Jumps
        snprintf(buffer, bufferSize, "%s %+d", name, imm);
    } else if (opcode == static_cast<uint8_t>(Opcode::kReturn)) {
        snprintf(buffer, bufferSize, "%s v%d", name, srcA);
    } else if (opcode == static_cast<uint8_t>(Opcode::kCall)) {
        snprintf(buffer, bufferSize, "%s v%d, v%d, %d args", name, dst, srcA, srcB);
    } else {
        // Default format
        snprintf(buffer, bufferSize, "%s v%d, v%d, v%d", name, dst, srcA, srcB);
    }
}

// Read file into memory
std::vector<uint8_t> ReadFile(const char* path) {
    FILE* file = fopen(path, "rb");
    if (!file) {
        return {};
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, file);
    fclose(file);
    
    return data;
}

// Disassemble bytecode file
int Disassemble(const char* filename) {
    auto data = ReadFile(filename);
    if (data.empty()) {
        fprintf(stderr, "Error: Cannot read file: %s\n", filename);
        return 1;
    }
    
    if (data.size() < sizeof(BytecodeHeader)) {
        fprintf(stderr, "Error: File too small for header\n");
        return 1;
    }
    
    const BytecodeHeader* header = reinterpret_cast<const BytecodeHeader*>(data.data());
    
    // Verify magic
    if (header->magic != kBytecodeMagic) {
        fprintf(stderr, "Error: Invalid magic number (expected 0x%08X, got 0x%08X)\n",
                kBytecodeMagic, header->magic);
        return 1;
    }
    
    // Print header info
    printf("RawrXD Bytecode Disassembly\n");
    printf("===========================\n\n");
    printf("File: %s\n", filename);
    printf("Version: %d.%d.%d\n", 
           (header->version >> 12) & 0xF,
           (header->version >> 4) & 0xFF,
           header->version & 0xF);
    printf("Flags: 0x%04X\n", header->flags);
    printf("Code: offset=%u, size=%u bytes\n", header->codeOffset, header->codeSize);
    printf("Constants: offset=%u, count=%u\n", header->constPoolOffset, header->constPoolCount);
    printf("Strings: offset=%u, size=%u\n", header->stringTableOffset, header->stringTableSize);
    printf("IC Slots: offset=%u, count=%u\n", header->icTableOffset, header->icSlotCount);
    printf("\n");
    
    // Disassemble code section
    printf("Code Section:\n");
    printf("-------------\n");
    
    const Instruction* code = reinterpret_cast<const Instruction*>(
        data.data() + header->codeOffset);
    size_t instructionCount = header->codeSize / sizeof(Instruction);
    
    char buffer[256];
    for (size_t i = 0; i < instructionCount; i++) {
        FormatInstruction(code[i], buffer, sizeof(buffer));
        printf("%04zu: %08X  %s\n", i, code[i].raw, buffer);
    }
    
    printf("\n");
    printf("Total: %zu instructions\n", instructionCount);
    
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("RawrXD-Script Bytecode Disassembler v1.0\n");
        printf("Usage: %s <file.rawr>\n", argv[0]);
        printf("\nDisassembles RawrXD bytecode files to human-readable format.\n");
        return 1;
    }
    
    return Disassemble(argv[1]);
}
