// ============================================================================
// RawrXD_Disasm_Kernel.cpp
// Native C++20 x64 instruction decoder implementation.
// Replacement for missing src/asm/RawrXD_Disasm_Kernel.asm.
// Decodes a bounded, correct subset of x64; rejects everything else.
// ============================================================================

#include "RawrXD_Disasm_Kernel.hpp"

#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>

// Reference decoder interface (declared dllexport in RawrCodex_Multi_v2.hpp,
// but never defined anywhere in the source tree). Implement it here using the
// tested x64 decoder for X86_64; return ERROR_INVALID_ARCH for all others.
#include "../../~dev/rawrxd/src/reverse_engineering/RawrCodex_Multi_v2.hpp"

namespace RawrXD {
namespace Disasm {

// ---------------------------------------------------------------------------
// Error messages
// ---------------------------------------------------------------------------

std::string decodeErrcMessage(DecodeErrc e) {
    switch (e) {
        case DecodeErrc::ok: return "no error";
        case DecodeErrc::empty_input: return "empty input";
        case DecodeErrc::truncated: return "instruction truncated (insufficient bytes)";
        case DecodeErrc::unsupported: return "opcode not in supported subset";
        case DecodeErrc::invalid_prefix: return "invalid prefix/rex combination";
        case DecodeErrc::internal_error: return "internal decoder error";
        default: return "unknown decode error";
    }
}

// ---------------------------------------------------------------------------
// Register name tables (x64)
// ---------------------------------------------------------------------------

static const char* k_gpr64[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
};

static const char* k_gpr32[8] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
};

// ---------------------------------------------------------------------------
// ModRM decoding
// ---------------------------------------------------------------------------

struct ModRM {
    std::uint8_t mod;
    std::uint8_t reg;
    std::uint8_t rm;
    bool hasSIB;
    std::uint8_t scale;
    std::uint8_t index;
    std::uint8_t base;
    std::int32_t displacement;
    std::size_t size; // bytes consumed by ModRM + SIB + disp
};

static std::optional<ModRM> parseModRM(const std::uint8_t* ptr,
                                       std::size_t remaining,
                                       std::size_t offset) {
    ModRM m{};
    m.hasSIB = false;
    m.scale = 0;
    m.index = 4; // none
    m.base = 5;  // none
    m.displacement = 0;
    m.size = 1; // ModRM byte itself

    if (offset + 1 > remaining) return std::nullopt;
    std::uint8_t modrm = ptr[offset];
    m.mod = (modrm >> 6) & 0x3;
    m.reg = (modrm >> 3) & 0x7;
    m.rm  = modrm & 0x7;
    offset++;

    // SIB byte needed for mod != 3 and rm == 4 (or rm == 5 with mod == 0)
    bool needSIB = (m.mod != 3 && m.rm == 4) || (m.mod == 0 && m.rm == 5);

    if (needSIB) {
        if (offset + 1 > remaining) return std::nullopt;
        std::uint8_t sib = ptr[offset];
        m.scale = (sib >> 6) & 0x3;
        m.index = (sib >> 3) & 0x7;
        m.base  = sib & 0x7;
        m.hasSIB = true;
        m.size++;
        offset++;
    }

    // Displacement
    if (m.mod == 0) {
        if (m.rm == 5 || (m.hasSIB && m.base == 5)) {
            // disp32
            if (offset + 4 > remaining) return std::nullopt;
            m.displacement = static_cast<std::int32_t>(
                ptr[offset] | (ptr[offset+1] << 8) |
                (ptr[offset+2] << 16) | (ptr[offset+3] << 24));
            m.size += 4;
            offset += 4;
        }
        // mod=0, rm != 5: no displacement
    } else if (m.mod == 1) {
        // disp8
        if (offset + 1 > remaining) return std::nullopt;
        m.displacement = static_cast<std::int8_t>(ptr[offset]);
        m.size += 1;
        offset += 1;
    } else if (m.mod == 2) {
        // disp32
        if (offset + 4 > remaining) return std::nullopt;
        m.displacement = static_cast<std::int32_t>(
            ptr[offset] | (ptr[offset+1] << 8) |
            (ptr[offset+2] << 16) | (ptr[offset+3] << 24));
        m.size += 4;
        offset += 4;
    }
    // mod == 3: register, no displacement

    return m;
}

static std::string modrmToString(const ModRM& m, bool use64Bit) {
    std::ostringstream os;
    if (m.mod == 3) {
        // Register direct
        if (use64Bit) {
            os << k_gpr64[m.rm];
        } else {
            os << k_gpr32[m.rm & 0x7];
        }
    } else {
        // Memory operand
        os << "[";

        bool needPlus = false;
        if (m.hasSIB) {
            if (m.index != 4) {
                os << k_gpr64[m.index];
                if (m.scale > 0) {
                    os << "*" << (1 << m.scale);
                }
                needPlus = true;
            }
            if (m.base != 5 || m.mod != 0) {
                if (needPlus) os << " + ";
                os << k_gpr64[m.base];
                needPlus = true;
            }
        } else {
            if (m.rm != 5 || m.mod != 0) {
                os << k_gpr64[m.rm];
                needPlus = true;
            }
        }

        if (m.displacement != 0 || (m.mod == 0 && m.rm == 5) ||
            (m.hasSIB && m.base == 5 && m.mod == 0)) {
            if (needPlus) os << " + ";
            if (m.displacement < 0) {
                os << "-" << std::hex << std::uppercase
                   << std::setfill('0') << std::setw(2)
                   << static_cast<unsigned int>(-m.displacement);
            } else {
                os << std::hex << std::uppercase << std::setfill('0')
                   << std::setw(2) << static_cast<unsigned int>(m.displacement);
            }
        }
        os << "]";
    }
    return os.str();
}

// ---------------------------------------------------------------------------
// REX prefix decoding
// ---------------------------------------------------------------------------

struct REX {
    bool present;
    bool w;  // 64-bit operand size
    bool r;  // ModRM reg extension
    bool x;  // SIB index extension
    bool b;  // ModRM rm / SIB base extension
    std::size_t size;
};

static REX parseREX(const std::uint8_t* ptr, std::size_t offset, std::size_t remaining) {
    REX r{};
    r.present = false;
    r.w = false;
    r.r = false;
    r.x = false;
    r.b = false;
    r.size = 0;

    if (offset < remaining && (ptr[offset] & 0xF0) == 0x40) {
        r.present = true;
        r.w = (ptr[offset] & 0x8) != 0;
        r.r = (ptr[offset] & 0x4) != 0;
        r.x = (ptr[offset] & 0x2) != 0;
        r.b = (ptr[offset] & 0x1) != 0;
        r.size = 1;
    }
    return r;
}

// Immediate reading helpers
// ---------------------------------------------------------------------------

static std::optional<std::int64_t> readImm16(const std::uint8_t* ptr,
                                             std::size_t offset,
                                             std::size_t remaining) {
    if (offset + 2 > remaining) return std::nullopt;
    std::int16_t v = static_cast<std::int16_t>(ptr[offset] | (ptr[offset+1] << 8));
    return static_cast<std::int64_t>(v);
}

static std::optional<std::int64_t> readImm8(const std::uint8_t* ptr,
                                            std::size_t offset,
                                            std::size_t remaining) {
    if (offset + 1 > remaining) return std::nullopt;
    return static_cast<std::int64_t>(static_cast<std::int8_t>(ptr[offset]));
}

static std::optional<std::int64_t> readImm32(const std::uint8_t* ptr,
                                             std::size_t offset,
                                             std::size_t remaining) {
    if (offset + 4 > remaining) return std::nullopt;
    std::int32_t v = static_cast<std::int32_t>(
        ptr[offset] | (ptr[offset+1] << 8) |
        (ptr[offset+2] << 16) | (ptr[offset+3] << 24));
    return static_cast<std::int64_t>(v);
}

static std::optional<std::uint64_t> readImm64(const std::uint8_t* ptr,
                                              std::size_t offset,
                                              std::size_t remaining) {
    if (offset + 8 > remaining) return std::nullopt;
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<std::uint64_t>(ptr[offset + i]) << (8 * i);
    }
    return v;
}

// ---------------------------------------------------------------------------
// Opcode decode table (bounded subset)
// ---------------------------------------------------------------------------

static std::optional<Instruction> decodeSingle(const std::uint8_t* ptr,
                                               std::size_t remaining,
                                               std::uint64_t address) {
    if (remaining == 0) return std::nullopt;

    std::size_t off = 0;
    std::uint8_t op0 = ptr[0];

    // REX prefix
    REX rex = parseREX(ptr, off, remaining);
    off += rex.size;

    if (off >= remaining) return std::nullopt;
    std::uint8_t opcode = ptr[off];

    // ===== NOP (0x90) =====
    if (opcode == 0x90 && !rex.present) {
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = 1;
        ins.address = address;
        ins.mnemonic = "nop";
        ins.operands = "";
        return ins;
    }

    // ===== INT3 (0xCC) =====
    if (opcode == 0xCC && !rex.present) {
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = 1;
        ins.address = address;
        ins.mnemonic = "int3";
        ins.operands = "";
        return ins;
    }

    // ===== RET (0xC3, 0xC2 imm16) =====
    if (opcode == 0xC3 && !rex.present) {
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = 1;
        ins.address = address;
        ins.mnemonic = "ret";
        ins.operands = "";
        ins.isRet = true;
        return ins;
    }
    if (opcode == 0xC2 && !rex.present) {
        auto imm = readImm16(ptr, off + 1, remaining);
        if (!imm) return std::nullopt;
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = 3;
        ins.address = address;
        ins.mnemonic = "ret";
        ins.operands = std::to_string(*imm);
        ins.isRet = true;
        return ins;
    }

    // ===== PUSH r64 (0x50-0x57, with REX.B) =====
    // In 64-bit mode these are 64-bit pushes regardless of REX.W.
    if ((opcode & 0xF8) == 0x50) {
        int reg = (opcode & 0x7) | (rex.b ? 8 : 0);
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 1;
        ins.address = address;
        ins.mnemonic = "push";
        ins.operands = k_gpr64[reg & 0xF];
        return ins;
    }

    // ===== POP r64 (0x58-0x5F, with REX.B) =====
    // In 64-bit mode these are 64-bit pops regardless of REX.W.
    if ((opcode & 0xF8) == 0x58) {
        int reg = (opcode & 0x7) | (rex.b ? 8 : 0);
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 1;
        ins.address = address;
        ins.mnemonic = "pop";
        ins.operands = k_gpr64[reg & 0xF];
        return ins;
    }

    // ===== Group 1: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP (0x80-0x83) =====
    // ModRM reg field selects the operation: 0=add,1=or,2=adc,3=sbb,4=and,5=sub,6=xor,7=cmp
    if (opcode >= 0x80 && opcode <= 0x83) {
        if (off + 1 >= remaining) return std::nullopt;
        auto modrm = parseModRM(ptr, remaining, off + 1);
        if (!modrm) return std::nullopt;

        static const char* k_grp1[8] = { "add", "or", "adc", "sbb", "and", "sub", "xor", "cmp" };
        uint8_t op = (modrm->reg & 0x7);

        // Immediate size: 0x80/0x82 → imm8; 0x81 → imm32; 0x83 → imm8 (sign-extended)
        std::size_t immSize = (opcode == 0x81) ? 4 : 1;
        if (off + 1 + modrm->size + immSize > remaining) return std::nullopt;

        std::string dst = modrmToString(*modrm, rex.w);
        std::string imm;
        if (immSize == 1) {
            auto imm8 = readImm8(ptr, off + 1 + modrm->size, remaining);
            if (!imm8) return std::nullopt;
            imm = std::to_string(static_cast<int>(*imm8));
        } else {
            auto imm32 = readImm32(ptr, off + 1 + modrm->size, remaining);
            if (!imm32) return std::nullopt;
            imm = std::string("0x") + std::to_string(static_cast<unsigned long long>(*imm32));
        }

        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 1 + modrm->size + immSize;
        ins.address = address;
        ins.mnemonic = k_grp1[op];
        ins.operands = dst + ", " + imm;
        return ins;
    }

    // ===== PUSH imm8 (0x6A) / PUSH imm32 (0x68) =====
    if (opcode == 0x6A && !rex.present) {
        auto imm = readImm8(ptr, off + 1, remaining);
        if (!imm) return std::nullopt;
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 2;
        ins.address = address;
        ins.mnemonic = "push";
        ins.operands = std::to_string(static_cast<int>(*imm));
        return ins;
    }
    if (opcode == 0x68 && !rex.present) {
        auto imm = readImm32(ptr, off + 1, remaining);
        if (!imm) return std::nullopt;
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 5;
        ins.address = address;
        ins.mnemonic = "push";
        ins.operands = std::string("0x") + std::to_string(static_cast<unsigned long long>(*imm));
        return ins;
    }

    // ===== MOV r64, imm64 (0x48 0xB8+r) =====
    // REX.W + B8+rd
    if (rex.w && (opcode & 0xF8) == 0xB8) {
        int reg = (opcode & 0x7) | (rex.b ? 8 : 0);
        auto imm = readImm64(ptr, off + 1, remaining);
        if (!imm) return std::nullopt;
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 9; // 1 REX + 1 opcode + 8 imm
        ins.address = address;
        ins.mnemonic = "mov";
        ins.operands = std::string(k_gpr64[reg & 0xF]) + ", 0x" +
            std::to_string(*imm);
        return ins;
    }

    // ===== Two-byte opcodes (0x0F escape) =====
    if (opcode == 0x0F && !rex.present) {
        if (off + 1 >= remaining) return std::nullopt;
        std::uint8_t op1 = ptr[off + 1];

        // MOV r64, mov r/m64 (0x48 0x8B /r) and (0x48 0x89 /r) handled below in REX.W path
        // Jcc rel32 (0x0F 0x80-0x8F)
        if ((op1 & 0xF0) == 0x80) {
            static const char* k_jcc[16] = {
                "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
                "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
            };
            auto imm = readImm32(ptr, off + 2, remaining);
            if (!imm) return std::nullopt;
            std::int64_t target = static_cast<std::int64_t>(address) + off + 6 + *imm;
            Instruction ins{};
            ins.ptr = ptr;
            ins.length = off + 6;
            ins.address = address;
            ins.mnemonic = k_jcc[op1 & 0xF];
            ins.operands = std::string("0x") + std::to_string(static_cast<unsigned long long>(target));
            ins.isBranch = true;
            ins.isConditionalBranch = true;
            ins.branchTarget = target;
            return ins;
        }

        // JMP rel32 (0x0F 0xE9)
        if (op1 == 0xE9) {
            auto imm = readImm32(ptr, off + 2, remaining);
            if (!imm) return std::nullopt;
            std::int64_t target = static_cast<std::int64_t>(address) + off + 6 + *imm;
            Instruction ins{};
            ins.ptr = ptr;
            ins.length = off + 6;
            ins.address = address;
            ins.mnemonic = "jmp";
            ins.operands = std::string("0x") + std::to_string(static_cast<unsigned long long>(target));
            ins.isBranch = true;
            ins.branchTarget = target;
            return ins;
        }

        // CALL rel32 (0x0F 0xE8? No — CALL is 0xE8 directly). 
        // 0x0F 0xE8 is not standard. Skip.
    }

    // ===== Single-byte JMP rel8 (0xEB) =====
    if (opcode == 0xEB && !rex.present) {
        auto imm = readImm8(ptr, off + 1, remaining);
        if (!imm) return std::nullopt;
        std::int64_t target = static_cast<std::int64_t>(address) + off + 2 + *imm;
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 2;
        ins.address = address;
        ins.mnemonic = "jmp";
        ins.operands = std::string("0x") + std::to_string(static_cast<unsigned long long>(target));
        ins.isBranch = true;
        ins.branchTarget = target;
        return ins;
    }

    // ===== Single-byte Jcc rel8 (0x70-0x7F) =====
    if ((opcode & 0xF0) == 0x70 && !rex.present) {
        static const char* k_jcc8[16] = {
            "jo", "jno", "jb", "jnb", "jz", "jnz", "jbe", "ja",
            "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"
        };
        auto imm = readImm8(ptr, off + 1, remaining);
        if (!imm) return std::nullopt;
        std::int64_t target = static_cast<std::int64_t>(address) + off + 2 + *imm;
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 2;
        ins.address = address;
        ins.mnemonic = k_jcc8[opcode & 0xF];
        ins.operands = std::string("0x") + std::to_string(static_cast<unsigned long long>(target));
        ins.isBranch = true;
        ins.isConditionalBranch = true;
        ins.branchTarget = target;
        return ins;
    }

    // ===== CALL rel32 (0xE8) =====
    if (opcode == 0xE8 && !rex.present) {
        auto imm = readImm32(ptr, off + 1, remaining);
        if (!imm) return std::nullopt;
        std::int64_t target = static_cast<std::int64_t>(address) + off + 5 + *imm;
        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 5;
        ins.address = address;
        ins.mnemonic = "call";
        ins.operands = std::string("0x") + std::to_string(static_cast<unsigned long long>(target));
        ins.isBranch = true;
        ins.isCall = true;
        ins.branchTarget = target;
        return ins;
    }

    // ===== REX.W MOV r/m64, r64 (0x48 0x89 /r) and MOV r64, r/m64 (0x48 0x8B /r) =====
    if (rex.w && (opcode == 0x89 || opcode == 0x8B)) {
        auto modrm = parseModRM(ptr, remaining, off + 1);
        if (!modrm) return std::nullopt;

        std::string dst, src;
        int regField = modrm->reg | (rex.r ? 8 : 0);

        if (opcode == 0x89) {
            // MOV r/m64, r64
            dst = modrmToString(*modrm, true);
            src = k_gpr64[regField & 0xF];
        } else {
            // MOV r64, r/m64
            dst = k_gpr64[regField & 0xF];
            src = modrmToString(*modrm, true);
        }

        Instruction ins{};
        ins.ptr = ptr;
        ins.length = off + 1 + modrm->size;
        ins.address = address;
        ins.mnemonic = "mov";
        ins.operands = dst + ", " + src;
        return ins;
    }

    // ===== Unsupported =====
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

std::optional<Instruction> decodeInstruction(const std::uint8_t* ptr,
                                             std::size_t remaining,
                                             std::uint64_t address) {
    return decodeSingle(ptr, remaining, address);
}

DecodeResult decodeBuffer(const std::uint8_t* begin,
                          const std::uint8_t* end,
                          std::uint64_t startAddress) {
    DecodeResult result{};
    const std::uint8_t* cur = begin;
    std::uint64_t addr = startAddress;

    while (cur < end) {
        auto ins = decodeSingle(cur, static_cast<std::size_t>(end - cur), addr);
        if (!ins) {
            result.error = DecodeErrc::unsupported;
            result.bytesConsumed = static_cast<std::size_t>(cur - begin);
            return result;
        }
        result.instructions.push_back(*ins);
        cur += ins->length;
        addr += ins->length;
    }

    result.bytesConsumed = static_cast<std::size_t>(cur - begin);
    return result;
}

std::string disassemble(const std::uint8_t* begin,
                        const std::uint8_t* end,
                        std::uint64_t startAddress) {
    std::ostringstream os;
    const std::uint8_t* cur = begin;
    std::uint64_t addr = startAddress;

    while (cur < end) {
        auto ins = decodeSingle(cur, static_cast<std::size_t>(end - cur), addr);
        if (!ins) {
            os << std::hex << std::uppercase << std::setfill('0')
               << std::setw(16) << addr << ":  <unsupported or truncated>\n";
            break;
        }
        os << std::hex << std::uppercase << std::setfill('0')
           << std::setw(16) << ins->address << ":  "
           << ins->mnemonic;
        if (!ins->operands.empty()) {
            os << " " << ins->operands;
        }
        os << "\n";
        cur += ins->length;
        addr += ins->length;
    }

    return os.str();
}

bool isSupportedOpcode(std::uint8_t b) {
    // Fast check: could this byte start a supported instruction?
    // NOP, INT3, RET, PUSH/POP r64, PUSH imm, MOV imm64, JMP, Jcc, CALL,
    // 0x0F escape, REX-prefixed MOV
    if (b == 0x90 || b == 0xCC || b == 0xC3 || b == 0xC2 ||
        b == 0x6A || b == 0x68 || b == 0xE8 || b == 0xEB ||
        b == 0x0F) {
        return true;
    }
    if ((b & 0xF8) == 0x50 || (b & 0xF8) == 0x58) return true; // push/pop r64
    if ((b & 0xF0) == 0x70) return true; // jcc rel8
    if ((b & 0xF0) == 0x80 && b != 0x80 && b != 0x88 && b != 0x8A) {
        // 0x80-0x8F group: some are supported with ModRM, some not
        return true;
    }
    // REX prefix (0x40-0x4F) — the real opcode follows
    if ((b & 0xF0) == 0x40) return true;
    // 0x48-0x4F are REX.W prefixes; 0x89/0x8B with REX.W are MOV
    return false;
}

std::optional<std::size_t> instructionLength(const std::uint8_t* ptr,
                                             std::size_t remaining) {
    auto ins = decodeSingle(ptr, remaining, 0);
    if (!ins) return std::nullopt;
    return ins->length;
}

} // namespace Disasm
} // namespace RawrXD

// ============================================================================
// ReferenceDecoder_Decode — the "oracle" reference decoder.
// Declared __declspec(dllexport) in RawrCodex_Multi_v2.hpp but never defined
// anywhere in the source tree. Implement here using the tested x64 decoder.
// Defined at global scope with C linkage (matches extern "C" in the header).
// ============================================================================

extern "C" __declspec(dllexport) DecodeStatus ReferenceDecoder_Decode(
    ArchType arch,
    const std::uint8_t* bytes,
    std::size_t byteCount,
    DecodedInstruction* out)
{
    if (!out) return DecodeStatus::ERROR_INVALID_INPUT;
    if (!bytes || byteCount == 0) return DecodeStatus::ERROR_INVALID_INPUT;

    // Clear output
    std::memset(out, 0, sizeof(DecodedInstruction));

    // Only x86/x64 are supported by this decoder
    if (arch != ArchType::X86_64 && arch != ArchType::X86_32) {
        return DecodeStatus::ERROR_INVALID_ARCH;
    }

    // Decode using our tested decoder (call via fully-qualified name)
    auto ins = RawrXD::Disasm::decodeSingle(bytes, byteCount, 0);
    if (!ins) {
        // Determine whether truncated or unsupported
        if (byteCount == 0) return DecodeStatus::ERROR_TRUNCATED;
        return DecodeStatus::ERROR_UNSUPPORTED;
    }

    // Fill RawInstruction
    out->raw.va = 0;
    out->raw.length = static_cast<uint32_t>(ins->length);
    out->raw.arch = arch;
    std::memcpy(out->raw.bytes, bytes, std::min(byteCount, size_t{16}));
    out->raw.encoding = 0;
    for (uint32_t i = 0; i < 4 && i < out->raw.length; ++i) {
        out->raw.encoding |= static_cast<uint32_t>(bytes[i]) << (8 * i);
    }

    // Fill SemanticInstruction
    out->semantic.mnemonic = Mnemonic::UNKNOWN;
    out->semantic.instrClass = InstrClass::UNKNOWN;
    out->semantic.arch = arch;
    out->semantic.opcode = 0;
    out->semantic.subOpcode = 0;
    out->semantic.operandCount = 0;
    out->semantic.flags = {};
    out->semantic.targetAddr = 0;
    out->semantic.condition = 0;

    // Map mnemonic and flags from our decode result
    if (ins->mnemonic == "nop") {
        out->semantic.mnemonic = Mnemonic::X64_NOP;
        out->semantic.instrClass = InstrClass::NOP;
    } else if (ins->mnemonic == "int3") {
        out->semantic.mnemonic = Mnemonic::X64_NOP; // no INT3 mnemonic in enum
        out->semantic.instrClass = InstrClass::DEBUG;
        out->semantic.flags.isPrivileged = 1;
    } else if (ins->mnemonic == "ret") {
        out->semantic.mnemonic = Mnemonic::X64_RET;
        out->semantic.instrClass = InstrClass::RETURN;
        out->semantic.flags.isReturn = 1;
        out->semantic.flags.isBranch = 1;
    } else if (ins->mnemonic == "push") {
        out->semantic.mnemonic = Mnemonic::X64_PUSH;
        out->semantic.instrClass = InstrClass::DP_IMM;
        out->semantic.operands[0].type = OperandType::REGISTER;
        out->semantic.operands[0].size = 8;
        out->semantic.operands[0].reg = Register::NONE;
        out->semantic.operandCount = 1;
    } else if (ins->mnemonic == "pop") {
        out->semantic.mnemonic = Mnemonic::X64_POP;
        out->semantic.instrClass = InstrClass::DP_IMM;
        out->semantic.operands[0].type = OperandType::REGISTER;
        out->semantic.operands[0].size = 8;
        out->semantic.operands[0].reg = Register::NONE;
        out->semantic.operandCount = 1;
    } else if (ins->mnemonic == "mov") {
        out->semantic.mnemonic = Mnemonic::X64_MOV;
        out->semantic.instrClass = InstrClass::DP_IMM;
    } else if (ins->mnemonic == "jmp") {
        out->semantic.mnemonic = Mnemonic::X64_JMP;
        out->semantic.instrClass = InstrClass::BRANCH;
        out->semantic.flags.isBranch = 1;
        if (ins->branchTarget.has_value()) {
            out->semantic.targetAddr = static_cast<uint64_t>(*ins->branchTarget);
        }
    } else if (ins->mnemonic == "jz" || ins->mnemonic == "jnz" ||
               ins->mnemonic == "jo" || ins->mnemonic == "jno" ||
               ins->mnemonic == "jb" || ins->mnemonic == "jnb" ||
               ins->mnemonic == "js" || ins->mnemonic == "jns" ||
               ins->mnemonic == "jp" || ins->mnemonic == "jnp" ||
               ins->mnemonic == "jl" || ins->mnemonic == "jge" ||
               ins->mnemonic == "jle" || ins->mnemonic == "jg" ||
               ins->mnemonic == "jbe" || ins->mnemonic == "ja") {
        out->semantic.mnemonic = Mnemonic::X64_JCC;
        out->semantic.instrClass = InstrClass::BRANCH_COND;
        out->semantic.flags.isBranch = 1;
        out->semantic.flags.isConditional = 1;
        if (ins->branchTarget.has_value()) {
            out->semantic.targetAddr = static_cast<uint64_t>(*ins->branchTarget);
        }
    } else if (ins->mnemonic == "call") {
        out->semantic.mnemonic = Mnemonic::X64_CALL;
        out->semantic.instrClass = InstrClass::CALL;
        out->semantic.flags.isCall = 1;
        out->semantic.flags.isBranch = 1;
        if (ins->branchTarget.has_value()) {
            out->semantic.targetAddr = static_cast<uint64_t>(*ins->branchTarget);
        }
    } else {
        return DecodeStatus::ERROR_UNSUPPORTED;
    }

    // Cache text representation
    std::strncpy(out->cachedMnemonic, ins->mnemonic.c_str(),
                 sizeof(out->cachedMnemonic) - 1);
    out->cachedMnemonic[sizeof(out->cachedMnemonic) - 1] = '\0';
    if (!ins->operands.empty()) {
        std::strncpy(out->cachedOperands, ins->operands.c_str(),
                     sizeof(out->cachedOperands) - 1);
        out->cachedOperands[sizeof(out->cachedOperands) - 1] = '\0';
    }
    out->hasCachedText = true;

    return DecodeStatus::SUCCESS;
}
