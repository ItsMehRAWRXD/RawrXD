#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <functional>

// =============================================================================
// JITAssembler - Just-In-Time Assembly Compiler
// Allows the Agent to compile assembly source to machine code at runtime
// =============================================================================

namespace RawrXD {
namespace Sovereign {

// =============================================================================
// Assembly Instruction - Parsed representation
// =============================================================================

enum class InstructionType {
    MOV,        // Data movement
    PUSH,       // Stack push
    POP,        // Stack pop
    CALL,       // Function call
    RET,        // Return
    JMP,        // Unconditional jump
    JCC,        // Conditional jump
    ADD,        // Addition
    SUB,        // Subtraction
    MUL,        // Multiplication
    DIV,        // Division
    AND,        // Bitwise AND
    OR,         // Bitwise OR
    XOR,        // Bitwise XOR
    CMP,        // Compare
    TEST,       // Test
    LEA,        // Load effective address
    NOP,        // No operation
    INT,        // Interrupt
    SYSCALL,    // System call
    VMOV,       // AVX move
    VADD,       // AVX add
    VMUL,       // AVX multiply
    UNKNOWN
};

struct AssemblyInstruction {
    InstructionType type;
    std::string mnemonic;
    std::vector<std::string> operands;
    uint64_t address;        // Resolved address (if known)
    size_t size;             // Size in bytes
    std::vector<uint8_t> encoding;  // Machine code
    
    AssemblyInstruction() 
        : type(InstructionType::UNKNOWN)
        , address(0)
        , size(0)
    {}
};

// =============================================================================
// JIT Compilation Result
// =============================================================================

struct JITResult {
    bool success;
    std::string errorMessage;
    std::vector<uint8_t> machineCode;
    size_t instructionCount;
    uint64_t baseAddress;    // Suggested load address
    
    JITResult() 
        : success(false)
        , instructionCount(0)
        , baseAddress(0)
    {}
};

// =============================================================================
// JIT Assembler
// =============================================================================

class JITAssembler {
public:
    using ErrorCallback = std::function<void(const std::string&)>;
    
    static JITAssembler& Instance();
    
    // Initialize assembler
    bool Initialize();
    
    // Compile assembly source to machine code
    JITResult Compile(const std::string& assemblySource);
    
    // Compile single instruction
    JITResult CompileInstruction(const std::string& instruction);
    
    // Assemble with specific base address (for relocations)
    JITResult CompileAt(const std::string& assemblySource, uint64_t baseAddress);
    
    // Validate assembly without generating code
    bool Validate(const std::string& assemblySource, std::string& errorOut);
    
    // Get instruction info
    bool ParseInstruction(const std::string& line, AssemblyInstruction& out);
    
    // Set error callback
    void SetErrorCallback(ErrorCallback callback);
    
    // Get last error
    std::string GetLastError() const { return lastError_; }
    
    // Architecture info
    bool IsAVX512Supported() const;
    bool IsAVX2Supported() const;
    
private:
    JITAssembler() = default;
    ~JITAssembler() = default;
    
    JITAssembler(const JITAssembler&) = delete;
    JITAssembler& operator=(const JITAssembler&) = delete;
    
    // Internal compilation
    JITResult CompileInternal(const std::string& source, uint64_t baseAddr);
    
    // Instruction encoders
    std::vector<uint8_t> EncodeMOV(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodePUSH(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodePOP(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodeCALL(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodeRET(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodeJMP(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodeADD(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodeNOP(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodeVMOV(const AssemblyInstruction& inst);
    std::vector<uint8_t> EncodeVADD(const AssemblyInstruction& inst);
    
    // Helpers
    InstructionType ParseMnemonic(const std::string& mnemonic);
    std::vector<std::string> Tokenize(const std::string& line);
    bool IsRegister(const std::string& token);
    bool IsImmediate(const std::string& token);
    uint8_t GetRegisterCode(const std::string& reg);
    int64_t ParseImmediate(const std::string& token);
    
    // Member variables
    ErrorCallback errorCallback_;
    std::string lastError_;
    bool initialized_ = false;
    bool hasAVX512_ = false;
    bool hasAVX2_ = false;
};

// =============================================================================
// Convenience Macros
// =============================================================================

#define JIT_COMPILE(asm_code) \
    RawrXD::Sovereign::JITAssembler::Instance().Compile(asm_code)

#define JIT_COMPILE_AT(asm_code, addr) \
    RawrXD::Sovereign::JITAssembler::Instance().CompileAt(asm_code, addr)

} // namespace Sovereign
} // namespace RawrXD
