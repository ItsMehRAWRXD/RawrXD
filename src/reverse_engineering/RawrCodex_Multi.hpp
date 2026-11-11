/**
 * @file RawrCodex_Multi.hpp
 * @brief Multi-Architecture RE Engine C++ Interface
 * @description C++ wrapper for RawrCodex multi-architecture support
 * 
 * @version 1.0.0
 */

#pragma once

#include <cstdint>
#include <cstddef>

// Architecture type constants (must match RawrCodex.asm)
enum class ArchType : uint32_t {
    X86_32      = 0,
    X86_64      = 1,
    ARM_32      = 2,
    ARM_64      = 3,
    THUMB       = 4,
    THUMB2      = 5,
    MIPS_32     = 6,
    MIPS_64     = 7,
    RISCV_32    = 8,
    RISCV_64    = 9
};

// Instruction classes
enum class InstrClass : uint32_t {
    DP_REG      = 0,    // Data processing - register
    DP_IMM      = 1,    // Data processing - immediate
    BRANCH      = 2,    // Branches
    LDST        = 3,    // Load/store
    SIMD        = 4,    // SIMD/FP
    UNKNOWN     = 5
};

// Multi-arch instruction structure
#pragma pack(push, 1)
struct MultiInstruction {
    uint64_t    va;                 // Virtual address
    uint32_t    instrSize;          // Instruction size (2, 4, or variable)
    ArchType    archType;           // Architecture type
    uint8_t     rawBytes[16];       // Raw instruction bytes
    
    // Architecture-specific decoded fields
    uint32_t    opcode;             // Primary opcode
    uint32_t    subOpcode;          // Secondary/sub-opcode
    
    // Register fields
    uint32_t    regRd;              // Destination register
    uint32_t    regRs1;             // Source register 1
    uint32_t    regRs2;             // Source register 2
    uint32_t    regRs3;             // Source register 3
    
    // Immediate values
    uint64_t    immValue;           // Immediate/sign-extended value
    uint32_t    immShift;           // Shift amount
    
    // Instruction class
    InstrClass  instrClass;         // Instruction classification
    
    // Condition codes (ARM/Thumb)
    uint32_t    condition;          // Condition code
    
    // Flags
    uint32_t    isConditional;        // Conditional execution
    uint32_t    isBranch;             // Branch instruction
    uint32_t    isCall;               // Call instruction
    uint32_t    isReturn;             // Return instruction
    uint32_t    isLoad;               // Load instruction
    uint32_t    isStore;              // Store instruction
    uint32_t    isSystem;             // System/privileged instruction
    
    // Branch/call target
    uint64_t    branchTarget;       // Resolved branch target
    
    // Disassembly string
    char        szMnemonic[32];     // Mnemonic
    char        szOperands[128];    // Operand string
};
#pragma pack(pop)

// Emulator state (opaque pointer)
struct EmuState;

// Pattern match callback
using PatternCallback = int (*)(void* ctx, uint64_t fileOffset, uint64_t rva);

extern "C" {

// RawrCodex Context Management
__declspec(dllimport) void* RawrCodex_Create(void);
__declspec(dllimport) void RawrCodex_Destroy(void* ctx);

// Multi-Architecture Disassembler
__declspec(dllimport) int RawrDisasm_Multi_Init(void* ctx, uint32_t archType);
__declspec(dllimport) uint32_t RawrDisasm_Multi_Decode(
    void* ctx,
    uint64_t va,
    const uint8_t* bytes,
    MultiInstruction* outInstr
);

// Architecture-specific decoders
__declspec(dllimport) uint32_t RawrDisasm_ARM_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    MultiInstruction* outInstr
);

__declspec(dllimport) uint32_t RawrDisasm_MIPS_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    MultiInstruction* outInstr
);

__declspec(dllimport) uint32_t RawrDisasm_RISCV_Decode(
    void* ctx,
    uint32_t archType,
    uint64_t va,
    const uint8_t* bytes,
    MultiInstruction* outInstr
);

// Multi-Architecture Emulator
__declspec(dllimport) EmuState* RawrEmu_Multi_Create(uint32_t archType, uint64_t memSize);
__declspec(dllimport) void RawrEmu_Multi_Destroy(EmuState* state);
__declspec(dllimport) int RawrEmu_Multi_Step(EmuState* state);
__declspec(dllimport) uint64_t RawrEmu_Multi_Run(EmuState* state);

// Multi-Architecture Pattern Scanner
__declspec(dllimport) uint64_t RawrPattern_Multi_Scan(
    void* ctx,
    const uint8_t* pattern,
    const uint8_t* mask,
    uint32_t length,
    PatternCallback callback
);

} // extern "C"

namespace RawrXD {
namespace RE {

/**
 * @brief Multi-architecture disassembler wrapper
 */
class MultiDisassembler {
public:
    MultiDisassembler(void* ctx, ArchType arch);
    ~MultiDisassembler() = default;
    
    bool IsValid() const { return m_valid; }
    
    // Disassemble single instruction
    bool Disassemble(uint64_t va, const uint8_t* bytes, MultiInstruction& out);
    
    // Get architecture
    ArchType GetArch() const { return m_arch; }
    
private:
    void* m_ctx;
    ArchType m_arch;
    bool m_valid;
};

/**
 * @brief Multi-architecture emulator wrapper
 */
class MultiEmulator {
public:
    MultiEmulator(ArchType arch, uint64_t memSize = 0x100000);
    ~MultiEmulator();
    
    bool IsValid() const { return m_state != nullptr; }
    
    // Execution control
    bool Step();
    uint64_t Run();
    
    // Memory access
    bool ReadMemory(uint64_t addr, void* data, size_t size);
    bool WriteMemory(uint64_t addr, const void* data, size_t size);
    
    // Register access (architecture-dependent)
    bool SetPC(uint64_t addr);
    uint64_t GetPC() const;
    
    // Stop conditions
    void SetStopAddress(uint64_t addr);
    void SetMaxInstructions(uint64_t count);
    
private:
    EmuState* m_state;
};

/**
 * @brief Multi-architecture pattern scanner
 */
class MultiPatternScanner {
public:
    MultiPatternScanner(void* ctx);
    
    // Scan for pattern
    uint64_t Scan(
        const uint8_t* pattern,
        const uint8_t* mask,
        uint32_t length,
        PatternCallback callback
    );
    
    // Convenience: Scan with string pattern (e.g., "48 89 ?? 50")
    uint64_t ScanString(const char* patternStr, PatternCallback callback);
    
private:
    void* m_ctx;
};

} // namespace RE
} // namespace RawrXD
