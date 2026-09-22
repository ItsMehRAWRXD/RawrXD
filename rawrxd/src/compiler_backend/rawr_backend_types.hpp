#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <variant>
#include <optional>
#include <array>
#include <unordered_map>
#include <memory>
#include <stdexcept>

namespace RawrXD {
namespace Backend {

// ============================================================================
// Register Encoding
// ============================================================================

enum class Register : uint8_t {
    // Low 8-bit
    AL = 0, CL = 1, DL = 2, BL = 3,
    AH = 4, CH = 5, DH = 6, BH = 7,
    // 16-bit
    AX = 0, CX = 1, DX = 2, BX = 3,
    SP = 4, BP = 5, SI = 6, DI = 7,
    // 32-bit
    EAX = 0, ECX = 1, EDX = 2, EBX = 3,
    ESP = 4, EBP = 5, ESI = 6, EDI = 7,
    // 64-bit
    RAX = 0, RCX = 1, RDX = 2, RBX = 3,
    RSP = 4, RBP = 5, RSI = 6, RDI = 7,
    R8 = 8,  R9 = 9,  R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
    // Segment
    NONE = 0xFF
};

inline uint8_t regCode(Register r) {
    return static_cast<uint8_t>(r) & 0x0F;
}

inline bool regRequiresRex(Register r) {
    return static_cast<uint8_t>(r) >= 8;
}

inline bool isRexExtended(Register r) {
    return regRequiresRex(r);
}

// ============================================================================
// Immediate Value
// ============================================================================

struct Immediate {
    uint64_t value = 0;
    uint8_t size = 0; // 1, 2, 4, 8 bytes

    explicit Immediate(uint8_t v)  : value(v), size(1) {}
    explicit Immediate(uint16_t v) : value(v), size(2) {}
    explicit Immediate(uint32_t v) : value(v), size(4) {}
    explicit Immediate(uint64_t v) : value(v), size(8) {}
    explicit Immediate(int8_t v)   : value(static_cast<uint64_t>(static_cast<int64_t>(v))), size(1) {}
    explicit Immediate(int16_t v)  : value(static_cast<uint64_t>(static_cast<int64_t>(v))), size(2) {}
    explicit Immediate(int32_t v)  : value(static_cast<uint64_t>(static_cast<int64_t>(v))), size(4) {}
    explicit Immediate(int64_t v)  : value(static_cast<uint64_t>(v)), size(8) {}

    Immediate() = default;
};

// ============================================================================
// Memory Operand
// ============================================================================

struct MemoryOperand {
    Register base = Register::NONE;
    Register index = Register::NONE;
    uint8_t scale = 1; // 1, 2, 4, 8
    int32_t displacement = 0;
    bool ripRelative = false;

    bool hasBase() const { return base != Register::NONE; }
    bool hasIndex() const { return index != Register::NONE; }
    bool hasDisplacement() const { return displacement != 0; }

    static MemoryOperand ripRel(int32_t disp) {
        MemoryOperand m;
        m.ripRelative = true;
        m.displacement = disp;
        return m;
    }

    static MemoryOperand baseDisp(Register b, int32_t disp) {
        MemoryOperand m;
        m.base = b;
        m.displacement = disp;
        return m;
    }

    static MemoryOperand baseIndexScaleDisp(Register b, Register i, uint8_t s, int32_t disp) {
        MemoryOperand m;
        m.base = b;
        m.index = i;
        m.scale = s;
        m.displacement = disp;
        return m;
    }
};

// ============================================================================
// Label (for branch/call targets)
// ============================================================================

struct Label {
    std::string name;
    uint32_t id = 0;
    bool bound = false;
    size_t boundOffset = 0;
    std::vector<size_t> references; // offsets where this label is referenced (for fixups)

    explicit Label(std::string n, uint32_t i) : name(std::move(n)), id(i), bound(false), boundOffset(0) {}
    Label() = default;
};

// ============================================================================
// Fixup / Relocation
// ============================================================================

enum class FixupKind : uint8_t {
    Rel8,      // 8-bit relative offset
    Rel32,     // 32-bit relative offset
    Rel32_1,   // 32-bit relative, offset by +1
    Rel32_2,   // 32-bit relative, offset by +2
    Rel32_3,   // 32-bit relative, offset by +3
    Rel32_4,   // 32-bit relative, offset by +4
    Rel32_5,   // 32-bit relative, offset by +5
    Abs32,     // Absolute 32-bit
    Abs64,     // Absolute 64-bit
    RipRel32,  // RIP-relative 32-bit
    Section16, // 16-bit section index
    SecRel32,  // 32-bit section-relative
};

struct Fixup {
    FixupKind kind;
    size_t codeOffset = 0; // offset in code buffer where fixup is applied
    size_t targetOffset = 0; // target byte offset (for internal labels)
    uint32_t labelId = 0; // if using label binding
    int64_t addend = 0; // additional offset
};

struct Relocation {
    uint32_t symbolIndex = 0;
    uint16_t type = 0; // IMAGE_REL_AMD64_*
    uint32_t virtualAddress = 0; // offset within section
    int64_t addend = 0;
};

// ============================================================================
// Operand
// ============================================================================

enum class OperandKind : uint8_t {
    None,
    Register,
    Immediate,
    Memory,
    Label
};

struct Operand {
    OperandKind kind = OperandKind::None;
    union {
        Register reg;
    };
    Immediate imm;
    MemoryOperand mem;
    uint32_t labelId = 0;
    int8_t labelRelSize = 0; // 1 or 4 for rel8/rel32

    Operand() : kind(OperandKind::None), reg(Register::NONE) {}

    static Operand fromReg(Register r) {
        Operand o; o.kind = OperandKind::Register; o.reg = r; return o;
    }
    static Operand fromImm(const Immediate& i) {
        Operand o; o.kind = OperandKind::Immediate; o.imm = i; return o;
    }
    static Operand fromMem(const MemoryOperand& m) {
        Operand o; o.kind = OperandKind::Memory; o.mem = m; return o;
    }
    static Operand fromLabel(uint32_t lid, int8_t relSize = 4) {
        Operand o; o.kind = OperandKind::Label; o.labelId = lid; o.labelRelSize = relSize; return o;
    }
};

// ============================================================================
// Instruction Mnemonic
// ============================================================================

enum class Mnemonic : uint8_t {
    MOV, LEA, PUSH, POP,
    ADD, SUB, IMUL, AND, OR, XOR, CMP, TEST,
    SHL, SHR, INC, DEC,
    CALL, JMP, JCC,
    RET, NOP,
    UNKNOWN
};

// ============================================================================
// Condition Code for JCC
// ============================================================================

enum class ConditionCode : uint8_t {
    O = 0,  NO = 1,
    B = 2,  AE = 3,  // below / above or equal (unsigned)
    E = 4,  NE = 5, NZ = 5,  // equal / not equal (NZ alias)
    BE = 6, A = 7,   // below or equal / above (unsigned)
    S = 8,  NS = 9,  // sign / not sign
    P = 10, NP = 11, // parity / not parity
    L = 12, GE = 13, // less / greater or equal (signed)
    LE = 14, G = 15  // less or equal / greater (signed)
};

// ============================================================================
// Instruction IR
// ============================================================================

struct InstructionIR {
    Mnemonic mnemonic = Mnemonic::UNKNOWN;
    std::vector<Operand> operands;
    ConditionCode cc = ConditionCode::O; // for JCC
    bool hasRexW = false; // force REX.W
    uint8_t operandSize = 0; // 1, 2, 4, 8 (auto-detected if 0)

    InstructionIR() = default;
    explicit InstructionIR(Mnemonic m) : mnemonic(m) {}

    InstructionIR& addOperand(const Operand& o) { operands.push_back(o); return *this; }
    InstructionIR& setCc(ConditionCode c) { cc = c; return *this; }
    InstructionIR& setRexW(bool w = true) { hasRexW = w; return *this; }
};

// ============================================================================
// Encoding Result
// ============================================================================

struct EncodedInstruction {
    std::vector<uint8_t> bytes;
    std::vector<Fixup> fixups;
    size_t length() const { return bytes.size(); }
};

class EncodingError : public std::runtime_error {
public:
    explicit EncodingError(const std::string& msg) : std::runtime_error(msg) {}
};

} // namespace Backend
} // namespace RawrXD
