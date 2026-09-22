#include "InstructionEncoderX64.hpp"
#include <cstring>
#include <cstdint>
#include <climits>

namespace {
inline void emitLE(std::vector<uint8_t>& out, uint64_t value, uint8_t bytes) {
    for (uint8_t i = 0; i < bytes; ++i) {
        out.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
    }
}

inline bool fitsSigned8(uint64_t value) {
    const int64_t v = static_cast<int64_t>(value);
    return v >= INT8_MIN && v <= INT8_MAX;
}

inline bool fitsSigned32(uint64_t value) {
    const int64_t v = static_cast<int64_t>(value);
    return v >= INT32_MIN && v <= INT32_MAX;
}
}

namespace RawrXD {
namespace Backend {

InstructionEncoderX64::InstructionEncoderX64() = default;

uint32_t InstructionEncoderX64::createLabel(const std::string& name) {
    uint32_t id = m_nextLabelId++;
    m_labels.emplace(id, Label(name, id));
    return id;
}

void InstructionEncoderX64::bindLabel(uint32_t labelId, size_t offset) {
    auto it = m_labels.find(labelId);
    if (it == m_labels.end()) throw EncodingError("bindLabel: unknown label id");
    it->second.bound = true;
    it->second.boundOffset = offset;
}

bool InstructionEncoderX64::isLabelBound(uint32_t labelId) const {
    auto it = m_labels.find(labelId);
    if (it == m_labels.end()) return false;
    return it->second.bound;
}

size_t InstructionEncoderX64::getLabelOffset(uint32_t labelId) const {
    auto it = m_labels.find(labelId);
    if (it == m_labels.end()) throw EncodingError("getLabelOffset: unknown label id");
    if (!it->second.bound) throw EncodingError("getLabelOffset: label not bound");
    return it->second.boundOffset;
}

void InstructionEncoderX64::reset() {
    m_currentOffset = 0;
    m_nextLabelId = 1;
    m_labels.clear();
}

void InstructionEncoderX64::emitRex(std::vector<uint8_t>& out, bool w, bool r, bool x, bool b) {
    uint8_t rex = 0x40;
    if (w) rex |= 0x08;
    if (r) rex |= 0x04;
    if (x) rex |= 0x02;
    if (b) rex |= 0x01;
    out.push_back(rex);
}

void InstructionEncoderX64::emitModRM(std::vector<uint8_t>& out, uint8_t mod, uint8_t reg, uint8_t rm) {
    out.push_back((mod << 6) | ((reg & 0x07) << 3) | (rm & 0x07));
}

void InstructionEncoderX64::emitSIB(std::vector<uint8_t>& out, uint8_t scale, uint8_t index, uint8_t base) {
    uint8_t scaleBits = 0;
    switch (scale) {
        case 0:
        case 1: scaleBits = 0; break;
        case 2: scaleBits = 1; break;
        case 4: scaleBits = 2; break;
        case 8: scaleBits = 3; break;
        default: throw EncodingError("SIB scale must be 1, 2, 4, or 8");
    }
    out.push_back((scaleBits << 6) | ((index & 0x07) << 3) | (base & 0x07));
}

void InstructionEncoderX64::emitImm(std::vector<uint8_t>& out, const Immediate& imm) {
    for (uint8_t i = 0; i < imm.size; ++i) {
        out.push_back(static_cast<uint8_t>((imm.value >> (i * 8)) & 0xFF));
    }
}

void InstructionEncoderX64::emitDisp8(std::vector<uint8_t>& out, int8_t disp) {
    out.push_back(static_cast<uint8_t>(disp));
}

void InstructionEncoderX64::emitDisp32(std::vector<uint8_t>& out, int32_t disp) {
    for (uint8_t i = 0; i < 4; ++i) {
        out.push_back(static_cast<uint8_t>((disp >> (i * 8)) & 0xFF));
    }
}

uint8_t InstructionEncoderX64::determineOperandSize(const InstructionIR& inst) const {
    if (inst.operandSize != 0) return inst.operandSize;
    // Infer from operands
    for (const auto& op : inst.operands) {
        if (op.kind == OperandKind::Register) {
            uint8_t code = static_cast<uint8_t>(op.reg);
            if (code >= 8) return 8; // R8-R15 are 64-bit
            // Legacy GPRs (0-7): default to 32-bit unless REX.W is forced
            return inst.hasRexW ? 8 : 4;
        }
        if (op.kind == OperandKind::Immediate) return op.imm.size;
    }
    return 4; // default 32-bit
}

bool InstructionEncoderX64::needsRexW(const InstructionIR& inst, uint8_t opSize) const {
    if (inst.hasRexW) return true;
    // Many instructions default to 32-bit; force REX.W for 64-bit
    if (opSize == 8) {
        switch (inst.mnemonic) {
            case Mnemonic::MOV:
            case Mnemonic::ADD:
            case Mnemonic::SUB:
            case Mnemonic::AND:
            case Mnemonic::OR:
            case Mnemonic::XOR:
            case Mnemonic::CMP:
            case Mnemonic::TEST:
            case Mnemonic::SHL:
            case Mnemonic::SHR:
            case Mnemonic::IMUL:
            case Mnemonic::INC:
            case Mnemonic::DEC:
            case Mnemonic::PUSH:
            case Mnemonic::POP:
            case Mnemonic::CALL:
            case Mnemonic::JMP:
            case Mnemonic::LEA:
                return true;
            default:
                return false;
        }
    }
    return false;
}

bool InstructionEncoderX64::isRexExtendedReg(Register r) const {
    return regRequiresRex(r);
}

bool InstructionEncoderX64::isRexExtendedMem(const MemoryOperand& mem) const {
    return regRequiresRex(mem.base) || regRequiresRex(mem.index);
}

void InstructionEncoderX64::encodeModRMSIB(std::vector<uint8_t>& out,
    uint8_t regField, const MemoryOperand& mem, std::vector<Fixup>& fixups) {
    if (mem.ripRelative) {
        // 64-bit RIP-relative addressing: mod=00, r/m=101, disp32.
        emitModRM(out, 0, regField, 5);
        emitDisp32(out, mem.displacement);
        fixups.push_back(Fixup{ FixupKind::RipRel32, out.size() - 4, 0, 0, mem.displacement });
        return;
    }

    const bool hasBase = mem.hasBase();
    const bool hasIndex = mem.hasIndex();
    const uint8_t baseCode = hasBase ? regCode(mem.base) : 0;
    const uint8_t indexCode = hasIndex ? regCode(mem.index) : 4;

    // In 64-bit address-size mode, mod=00 r/m=101 is RIP-relative, not
    // absolute. Encode disp32-only addressing through a SIB with no base.
    if (!hasBase && !hasIndex) {
        emitModRM(out, 0, regField, 4);
        emitSIB(out, 1, 4, 5); // scale=1, no index, no base
        emitDisp32(out, mem.displacement);
        return;
    }

    const bool needsSib = hasIndex || (hasBase && baseCode == 4);
    bool disp8 = false;
    bool disp32 = false;

    // RBP/R13 with mod=00 means "no base"/special form, so force disp8=0.
    if (hasBase && baseCode == 5 && mem.displacement == 0) {
        disp8 = true;
    } else if (mem.displacement != 0) {
        if (mem.displacement >= -128 && mem.displacement <= 127) disp8 = true;
        else disp32 = true;
    }

    // A SIB without a base always requires a disp32.
    if (!hasBase) {
        disp8 = false;
        disp32 = true;
    }

    const uint8_t mod = disp8 ? 1 : (disp32 ? 2 : 0);

    if (needsSib || !hasBase) {
        const uint8_t sibBase = hasBase ? baseCode : 5;
        const uint8_t sibIndex = hasIndex ? indexCode : 4;
        emitModRM(out, hasBase ? mod : 0, regField, 4);
        // emitSIB expects the actual scale (1,2,4,8), not encoded scale bits.
        emitSIB(out, mem.scale == 0 ? 1 : mem.scale, sibIndex, sibBase);
    } else {
        emitModRM(out, mod, regField, baseCode);
    }

    if (disp8) emitDisp8(out, static_cast<int8_t>(mem.displacement));
    else if (disp32 || !hasBase) emitDisp32(out, mem.displacement);
}

void InstructionEncoderX64::encodeModRMSIB(std::vector<uint8_t>& out,
    uint8_t regField, Register reg, std::vector<Fixup>&) {
    emitModRM(out, 3, regField, regCode(reg));
}

EncodedInstruction InstructionEncoderX64::encode(const InstructionIR& inst) {
    switch (inst.mnemonic) {
        case Mnemonic::MOV: return encodeMOV(inst);
        case Mnemonic::LEA: return encodeLEA(inst);
        case Mnemonic::PUSH: return encodePUSH(inst);
        case Mnemonic::POP: return encodePOP(inst);
        case Mnemonic::ADD: return encodeALU(inst, 0x00); // ADD r/m, r = 0x00; ADD r, r/m = 0x02
        case Mnemonic::SUB: return encodeALU(inst, 0x28);
        case Mnemonic::AND: return encodeALU(inst, 0x20);
        case Mnemonic::OR:  return encodeALU(inst, 0x08);
        case Mnemonic::XOR: return encodeALU(inst, 0x30);
        case Mnemonic::CMP: return encodeCMP(inst);
        case Mnemonic::TEST: return encodeTEST(inst);
        case Mnemonic::SHL: return encodeShift(inst, 4);
        case Mnemonic::SHR: return encodeShift(inst, 5);
        case Mnemonic::IMUL: return encodeIMUL(inst);
        case Mnemonic::INC: return encodeINC_DEC(inst, true);
        case Mnemonic::DEC: return encodeINC_DEC(inst, false);
        case Mnemonic::CALL: return encodeCALL(inst);
        case Mnemonic::JMP: return encodeJMP(inst);
        case Mnemonic::JCC: return encodeJCC(inst);
        case Mnemonic::RET: return encodeRET(inst);
        case Mnemonic::NOP: return encodeNOP(inst);
        default:
            throw EncodingError("Unsupported mnemonic");
    }
}

EncodedInstruction InstructionEncoderX64::encodeMOV(const InstructionIR& inst) {
    if (inst.operands.size() != 2) throw EncodingError("MOV requires 2 operands");
    const auto& dst = inst.operands[0];
    const auto& src = inst.operands[1];
    uint8_t opSize = determineOperandSize(inst);
    bool rexW = needsRexW(inst, opSize);
    EncodedInstruction result;

    if (dst.kind == OperandKind::Register && src.kind == OperandKind::Register) {
        // MOV r, r/m or r/m, r
        // For reg,reg: opcode 0x89 (r/m <- r) or 0x8B (r <- r/m). Use 0x89 with mod=3.
        bool rExt = isRexExtendedReg(src.reg);
        bool bExt = isRexExtendedReg(dst.reg);
        if (rexW || rExt || bExt) emitRex(result.bytes, rexW, rExt, false, bExt);
        result.bytes.push_back(opSize == 1 ? 0x88 : 0x89);
        encodeModRMSIB(result.bytes, regCode(src.reg), dst.reg, result.fixups);
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Immediate) {
        // MOV r, imm. B8+rd uses the operand's natural immediate width.
        bool bExt = isRexExtendedReg(dst.reg);
        if (rexW || bExt) emitRex(result.bytes, rexW, false, false, bExt);
        if (opSize == 1) {
            result.bytes.push_back(0xB0 + (regCode(dst.reg) & 0x07));
            emitLE(result.bytes, src.imm.value, 1);
        } else if (opSize == 4) {
            result.bytes.push_back(0xB8 + (regCode(dst.reg) & 0x07));
            emitLE(result.bytes, src.imm.value, 4);
        } else if (opSize == 8) {
            result.bytes.push_back(0xB8 + (regCode(dst.reg) & 0x07));
            emitLE(result.bytes, src.imm.value, 8);
        } else {
            throw EncodingError("MOV immediate supports 8-, 32-, or 64-bit operands");
        }
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Memory) {
        // MOV r, [mem]
        bool rExt = isRexExtendedReg(dst.reg);
        bool xExt = src.mem.hasIndex() && isRexExtendedReg(src.mem.index);
        bool bExt = src.mem.hasBase() && isRexExtendedReg(src.mem.base);
        if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
        result.bytes.push_back(opSize == 1 ? 0x8A : 0x8B);
        encodeModRMSIB(result.bytes, regCode(dst.reg), src.mem, result.fixups);
    } else if (dst.kind == OperandKind::Memory && src.kind == OperandKind::Register) {
        // MOV [mem], r
        bool rExt = isRexExtendedReg(src.reg);
        bool xExt = dst.mem.hasIndex() && isRexExtendedReg(dst.mem.index);
        bool bExt = dst.mem.hasBase() && isRexExtendedReg(dst.mem.base);
        if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
        result.bytes.push_back(opSize == 1 ? 0x88 : 0x89);
        encodeModRMSIB(result.bytes, regCode(src.reg), dst.mem, result.fixups);
    } else if (dst.kind == OperandKind::Memory && src.kind == OperandKind::Immediate) {
        // MOV [mem], imm
        bool xExt = dst.mem.hasIndex() && isRexExtendedReg(dst.mem.index);
        bool bExt = dst.mem.hasBase() && isRexExtendedReg(dst.mem.base);
        if (rexW || xExt || bExt) emitRex(result.bytes, rexW, false, xExt, bExt);
        if (opSize == 1) {
            result.bytes.push_back(0xC6);
            encodeModRMSIB(result.bytes, 0, dst.mem, result.fixups);
            emitLE(result.bytes, src.imm.value, 1);
        } else if (opSize == 4) {
            result.bytes.push_back(0xC7);
            encodeModRMSIB(result.bytes, 0, dst.mem, result.fixups);
            emitLE(result.bytes, src.imm.value, 4);
        } else if (opSize == 8) {
            if (!fitsSigned32(src.imm.value)) {
                throw EncodingError("MOV r/m64, imm requires sign-extendable imm32");
            }
            result.bytes.push_back(0xC7);
            encodeModRMSIB(result.bytes, 0, dst.mem, result.fixups);
            emitLE(result.bytes, src.imm.value, 4);
        } else {
            throw EncodingError("MOV memory immediate supports 8-, 32-, or 64-bit operands");
        }
    } else {
        throw EncodingError("Unsupported MOV operand combination");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeLEA(const InstructionIR& inst) {
    if (inst.operands.size() != 2) throw EncodingError("LEA requires 2 operands");
    const auto& dst = inst.operands[0];
    const auto& src = inst.operands[1];
    if (dst.kind != OperandKind::Register || src.kind != OperandKind::Memory) {
        throw EncodingError("LEA requires reg, mem");
    }
    EncodedInstruction result;
    const uint8_t opSize = determineOperandSize(inst);
    if (opSize != 4 && opSize != 8) {
        throw EncodingError("LEA currently supports 32- or 64-bit destinations");
    }
    const bool rexW = (opSize == 8);
    bool rExt = isRexExtendedReg(dst.reg);
    bool xExt = src.mem.hasIndex() && isRexExtendedReg(src.mem.index);
    bool bExt = src.mem.hasBase() && isRexExtendedReg(src.mem.base);
    if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
    result.bytes.push_back(0x8D);
    encodeModRMSIB(result.bytes, regCode(dst.reg), src.mem, result.fixups);
    return result;
}

EncodedInstruction InstructionEncoderX64::encodePUSH(const InstructionIR& inst) {
    if (inst.operands.size() != 1) throw EncodingError("PUSH requires 1 operand");
    const auto& op = inst.operands[0];
    EncodedInstruction result;
    if (op.kind == OperandKind::Register) {
        bool bExt = isRexExtendedReg(op.reg);
        if (bExt) emitRex(result.bytes, false, false, false, bExt);
        result.bytes.push_back(0x50 + (regCode(op.reg) & 0x07));
    } else if (op.kind == OperandKind::Immediate) {
        if (fitsSigned8(op.imm.value)) {
            result.bytes.push_back(0x6A);
            emitLE(result.bytes, op.imm.value, 1);
        } else if (fitsSigned32(op.imm.value)) {
            result.bytes.push_back(0x68);
            emitLE(result.bytes, op.imm.value, 4);
        } else {
            throw EncodingError("PUSH immediate must fit signed imm32");
        }
    } else {
        throw EncodingError("Unsupported PUSH operand");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodePOP(const InstructionIR& inst) {
    if (inst.operands.size() != 1) throw EncodingError("POP requires 1 operand");
    const auto& op = inst.operands[0];
    if (op.kind != OperandKind::Register) throw EncodingError("POP requires register");
    EncodedInstruction result;
    bool bExt = isRexExtendedReg(op.reg);
    if (bExt) emitRex(result.bytes, false, false, false, bExt);
    result.bytes.push_back(0x58 + (regCode(op.reg) & 0x07));
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeALU(const InstructionIR& inst, uint8_t opcode) {
    if (inst.operands.size() != 2) throw EncodingError("ALU requires 2 operands");
    const auto& dst = inst.operands[0];
    const auto& src = inst.operands[1];
    uint8_t opSize = determineOperandSize(inst);
    bool rexW = needsRexW(inst, opSize);
    EncodedInstruction result;

    if (dst.kind == OperandKind::Register && src.kind == OperandKind::Register) {
        // ADD/SUB/AND/OR/XOR r, r/m
        bool rExt = isRexExtendedReg(dst.reg);
        bool bExt = isRexExtendedReg(src.reg);
        if (rexW || rExt || bExt) emitRex(result.bytes, rexW, rExt, false, bExt);
        result.bytes.push_back((opSize == 1 ? opcode : opcode + 1) + 0x02); // r, r/m form
        encodeModRMSIB(result.bytes, regCode(dst.reg), src.reg, result.fixups);
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Immediate) {
        // ADD/SUB/AND/OR/XOR r, imm
        bool bExt = isRexExtendedReg(dst.reg);
        if (rexW || bExt) emitRex(result.bytes, rexW, false, false, bExt);
        if (opSize == 1) {
            result.bytes.push_back(0x80);
            encodeModRMSIB(result.bytes, opcode / 8, dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 1);
        } else if (opSize == 4 || opSize == 8) {
            if (fitsSigned8(src.imm.value)) {
                result.bytes.push_back(0x83);
                encodeModRMSIB(result.bytes, opcode / 8, dst.reg, result.fixups);
                emitLE(result.bytes, src.imm.value, 1);
                return result;
            }
            if (opSize == 8 && !fitsSigned32(src.imm.value)) {
                throw EncodingError("ALU r64, imm requires sign-extendable imm32");
            }
            result.bytes.push_back(0x81);
            encodeModRMSIB(result.bytes, opcode / 8, dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 4);
        } else {
            throw EncodingError("ALU immediate supports 8-, 32-, or 64-bit operands");
        }
    } else if (dst.kind == OperandKind::Memory && src.kind == OperandKind::Register) {
        // ALU [mem], r
        bool rExt = isRexExtendedReg(src.reg);
        bool xExt = dst.mem.hasIndex() && isRexExtendedReg(dst.mem.index);
        bool bExt = dst.mem.hasBase() && isRexExtendedReg(dst.mem.base);
        if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
        result.bytes.push_back(opcode); // r/m, r form
        encodeModRMSIB(result.bytes, regCode(src.reg), dst.mem, result.fixups);
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Memory) {
        // ALU r, [mem]
        bool rExt = isRexExtendedReg(dst.reg);
        bool xExt = src.mem.hasIndex() && isRexExtendedReg(src.mem.index);
        bool bExt = src.mem.hasBase() && isRexExtendedReg(src.mem.base);
        if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
        result.bytes.push_back(opcode + 0x02); // r, r/m form
        encodeModRMSIB(result.bytes, regCode(dst.reg), src.mem, result.fixups);
    } else if (dst.kind == OperandKind::Memory && src.kind == OperandKind::Immediate) {
        bool xExt = dst.mem.hasIndex() && isRexExtendedReg(dst.mem.index);
        bool bExt = dst.mem.hasBase() && isRexExtendedReg(dst.mem.base);
        if (rexW || xExt || bExt) emitRex(result.bytes, rexW, false, xExt, bExt);
        if (opSize == 1) {
            result.bytes.push_back(0x80);
            encodeModRMSIB(result.bytes, opcode / 8, dst.mem, result.fixups);
            emitLE(result.bytes, src.imm.value, 1);
        } else if (opSize == 4 || opSize == 8) {
            if (fitsSigned8(src.imm.value)) {
                result.bytes.push_back(0x83);
                encodeModRMSIB(result.bytes, opcode / 8, dst.mem, result.fixups);
                emitLE(result.bytes, src.imm.value, 1);
            } else {
                if (opSize == 8 && !fitsSigned32(src.imm.value)) {
                    throw EncodingError("ALU r/m64, imm requires sign-extendable imm32");
                }
                result.bytes.push_back(0x81);
                encodeModRMSIB(result.bytes, opcode / 8, dst.mem, result.fixups);
                emitLE(result.bytes, src.imm.value, 4);
            }
        } else {
            throw EncodingError("ALU memory immediate supports 8-, 32-, or 64-bit operands");
        }
    } else {
        throw EncodingError("Unsupported ALU operand combination");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeIMUL(const InstructionIR& inst) {
    if (inst.operands.size() != 2) throw EncodingError("IMUL requires 2 operands");
    const auto& dst = inst.operands[0];
    const auto& src = inst.operands[1];
    uint8_t opSize = determineOperandSize(inst);
    bool rexW = needsRexW(inst, opSize);
    EncodedInstruction result;
    if (dst.kind == OperandKind::Register && src.kind == OperandKind::Register) {
        bool rExt = isRexExtendedReg(dst.reg);
        bool bExt = isRexExtendedReg(src.reg);
        if (rexW || rExt || bExt) emitRex(result.bytes, rexW, rExt, false, bExt);
        result.bytes.push_back(0x0F);
        result.bytes.push_back(0xAF);
        encodeModRMSIB(result.bytes, regCode(dst.reg), src.reg, result.fixups);
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Immediate) {
        if (opSize != 4 && opSize != 8) {
            throw EncodingError("IMUL immediate supports 32- or 64-bit operands");
        }
        bool ext = isRexExtendedReg(dst.reg);
        if (rexW || ext) emitRex(result.bytes, rexW, ext, false, ext);
        if (fitsSigned8(src.imm.value)) {
            result.bytes.push_back(0x6B);
            encodeModRMSIB(result.bytes, regCode(dst.reg), dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 1);
        } else {
            if (opSize == 8 && !fitsSigned32(src.imm.value)) {
                throw EncodingError("IMUL r64, imm requires sign-extendable imm32");
            }
            result.bytes.push_back(0x69);
            encodeModRMSIB(result.bytes, regCode(dst.reg), dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 4);
        }
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Memory) {
        bool rExt = isRexExtendedReg(dst.reg);
        bool xExt = src.mem.hasIndex() && isRexExtendedReg(src.mem.index);
        bool bExt = src.mem.hasBase() && isRexExtendedReg(src.mem.base);
        if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
        result.bytes.push_back(0x0F);
        result.bytes.push_back(0xAF);
        encodeModRMSIB(result.bytes, regCode(dst.reg), src.mem, result.fixups);
    } else {
        throw EncodingError("Unsupported IMUL operand combination");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeCMP(const InstructionIR& inst) {
    if (inst.operands.size() != 2) throw EncodingError("CMP requires 2 operands");
    const auto& dst = inst.operands[0];
    const auto& src = inst.operands[1];
    uint8_t opSize = determineOperandSize(inst);
    bool rexW = needsRexW(inst, opSize);
    EncodedInstruction result;
    if (dst.kind == OperandKind::Register && src.kind == OperandKind::Register) {
        bool rExt = isRexExtendedReg(dst.reg);
        bool bExt = isRexExtendedReg(src.reg);
        if (rexW || rExt || bExt) emitRex(result.bytes, rexW, rExt, false, bExt);
        result.bytes.push_back(0x3B);
        encodeModRMSIB(result.bytes, regCode(dst.reg), src.reg, result.fixups);
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Immediate) {
        bool bExt = isRexExtendedReg(dst.reg);
        if (rexW || bExt) emitRex(result.bytes, rexW, false, false, bExt);
        if (opSize == 1) {
            result.bytes.push_back(0x80);
            encodeModRMSIB(result.bytes, 7, dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 1);
        } else if (opSize == 4 || opSize == 8) {
            if (fitsSigned8(src.imm.value)) {
                result.bytes.push_back(0x83);
                encodeModRMSIB(result.bytes, 7, dst.reg, result.fixups);
                emitLE(result.bytes, src.imm.value, 1);
                return result;
            }
            if (opSize == 8 && !fitsSigned32(src.imm.value)) {
                throw EncodingError("CMP r64, imm requires sign-extendable imm32");
            }
            result.bytes.push_back(0x81);
            encodeModRMSIB(result.bytes, 7, dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 4);
        } else {
            throw EncodingError("CMP immediate supports 8-, 32-, or 64-bit operands");
        }
    } else if (dst.kind == OperandKind::Memory && src.kind == OperandKind::Register) {
        bool rExt = isRexExtendedReg(src.reg);
        bool xExt = dst.mem.hasIndex() && isRexExtendedReg(dst.mem.index);
        bool bExt = dst.mem.hasBase() && isRexExtendedReg(dst.mem.base);
        if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
        result.bytes.push_back(0x39);
        encodeModRMSIB(result.bytes, regCode(src.reg), dst.mem, result.fixups);
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Memory) {
        bool rExt = isRexExtendedReg(dst.reg);
        bool xExt = src.mem.hasIndex() && isRexExtendedReg(src.mem.index);
        bool bExt = src.mem.hasBase() && isRexExtendedReg(src.mem.base);
        if (rexW || rExt || xExt || bExt) emitRex(result.bytes, rexW, rExt, xExt, bExt);
        result.bytes.push_back(0x3B);
        encodeModRMSIB(result.bytes, regCode(dst.reg), src.mem, result.fixups);
    } else {
        throw EncodingError("Unsupported CMP operand combination");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeTEST(const InstructionIR& inst) {
    if (inst.operands.size() != 2) throw EncodingError("TEST requires 2 operands");
    const auto& dst = inst.operands[0];
    const auto& src = inst.operands[1];
    uint8_t opSize = determineOperandSize(inst);
    bool rexW = needsRexW(inst, opSize);
    EncodedInstruction result;
    if (dst.kind == OperandKind::Register && src.kind == OperandKind::Register) {
        bool rExt = isRexExtendedReg(src.reg);
        bool bExt = isRexExtendedReg(dst.reg);
        if (rexW || rExt || bExt) emitRex(result.bytes, rexW, rExt, false, bExt);
        result.bytes.push_back(opSize == 1 ? 0x84 : 0x85);
        encodeModRMSIB(result.bytes, regCode(src.reg), dst.reg, result.fixups);
    } else if (dst.kind == OperandKind::Register && src.kind == OperandKind::Immediate) {
        bool bExt = isRexExtendedReg(dst.reg);
        if (rexW || bExt) emitRex(result.bytes, rexW, false, false, bExt);
        if (opSize == 1) {
            result.bytes.push_back(0xF6);
            encodeModRMSIB(result.bytes, 0, dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 1);
        } else if (opSize == 4 || opSize == 8) {
            if (opSize == 8 && !fitsSigned32(src.imm.value)) {
                throw EncodingError("TEST r64, imm requires sign-extendable imm32");
            }
            result.bytes.push_back(0xF7);
            encodeModRMSIB(result.bytes, 0, dst.reg, result.fixups);
            emitLE(result.bytes, src.imm.value, 4);
        } else {
            throw EncodingError("TEST immediate supports 8-, 32-, or 64-bit operands");
        }
    } else {
        throw EncodingError("Unsupported TEST operand combination");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeShift(const InstructionIR& inst, uint8_t shiftOpcode) {
    if (inst.operands.size() != 2) throw EncodingError("Shift requires 2 operands");
    const auto& dst = inst.operands[0];
    const auto& src = inst.operands[1];
    uint8_t opSize = determineOperandSize(inst);
    bool rexW = needsRexW(inst, opSize);
    EncodedInstruction result;
    if (dst.kind != OperandKind::Register && dst.kind != OperandKind::Memory) {
        throw EncodingError("Shift destination must be register or memory");
    }
    bool xExt = (dst.kind == OperandKind::Memory) && dst.mem.hasIndex() && isRexExtendedReg(dst.mem.index);
    bool bExt = (dst.kind == OperandKind::Register)
        ? isRexExtendedReg(dst.reg)
        : (dst.mem.hasBase() && isRexExtendedReg(dst.mem.base));
    if (rexW || xExt || bExt) emitRex(result.bytes, rexW, false, xExt, bExt);
    if (src.kind == OperandKind::Immediate) {
        if (src.imm.value == 1) {
            // shift by 1
            result.bytes.push_back(opSize == 1 ? 0xD0 : 0xD1);
            if (dst.kind == OperandKind::Register) encodeModRMSIB(result.bytes, shiftOpcode, dst.reg, result.fixups);
            else encodeModRMSIB(result.bytes, shiftOpcode, dst.mem, result.fixups);
        } else {
            result.bytes.push_back(opSize == 1 ? 0xC0 : 0xC1);
            if (dst.kind == OperandKind::Register) encodeModRMSIB(result.bytes, shiftOpcode, dst.reg, result.fixups);
            else encodeModRMSIB(result.bytes, shiftOpcode, dst.mem, result.fixups);
            result.bytes.push_back(static_cast<uint8_t>(src.imm.value & 0xFF));
        }
    } else if (src.kind == OperandKind::Register && src.reg == Register::CL) {
        result.bytes.push_back(opSize == 1 ? 0xD2 : 0xD3);
        if (dst.kind == OperandKind::Register) encodeModRMSIB(result.bytes, shiftOpcode, dst.reg, result.fixups);
        else encodeModRMSIB(result.bytes, shiftOpcode, dst.mem, result.fixups);
    } else {
        throw EncodingError("Unsupported shift count operand");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeINC_DEC(const InstructionIR& inst, bool isInc) {
    if (inst.operands.size() != 1) throw EncodingError("INC/DEC requires 1 operand");
    const auto& op = inst.operands[0];
    const uint8_t opSize = determineOperandSize(inst);
    const bool rexW = needsRexW(inst, opSize);
    EncodedInstruction result;

    // In 64-bit mode 0x40..0x4F are REX prefixes, not INC/DEC register
    // opcodes. Always use the FE/FF group encodings.
    if (op.kind == OperandKind::Register) {
        const bool bExt = isRexExtendedReg(op.reg);
        if (rexW || bExt) emitRex(result.bytes, rexW, false, false, bExt);
        result.bytes.push_back(opSize == 1 ? 0xFE : 0xFF);
        encodeModRMSIB(result.bytes, isInc ? 0 : 1, op.reg, result.fixups);
    } else if (op.kind == OperandKind::Memory) {
        const bool xExt = op.mem.hasIndex() && isRexExtendedReg(op.mem.index);
        const bool bExt = op.mem.hasBase() && isRexExtendedReg(op.mem.base);
        if (rexW || xExt || bExt) emitRex(result.bytes, rexW, false, xExt, bExt);
        result.bytes.push_back(opSize == 1 ? 0xFE : 0xFF);
        encodeModRMSIB(result.bytes, isInc ? 0 : 1, op.mem, result.fixups);
    } else {
        throw EncodingError("Unsupported INC/DEC operand");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeCALL(const InstructionIR& inst) {
    if (inst.operands.size() != 1) throw EncodingError("CALL requires 1 operand");
    const auto& op = inst.operands[0];
    EncodedInstruction result;
    if (op.kind == OperandKind::Label) {
        if (op.labelRelSize == 1) {
            throw EncodingError("CALL does not support rel8");
        } else {
            result.bytes.push_back(0xE8);
            size_t fixupOff = result.bytes.size();
            result.bytes.push_back(0); result.bytes.push_back(0); result.bytes.push_back(0); result.bytes.push_back(0);
            result.fixups.push_back(Fixup{ FixupKind::Rel32, fixupOff, 0, op.labelId, 0 });
        }
    } else if (op.kind == OperandKind::Register) {
        bool bExt = isRexExtendedReg(op.reg);
        if (bExt) emitRex(result.bytes, false, false, false, bExt);
        result.bytes.push_back(0xFF);
        encodeModRMSIB(result.bytes, 2, op.reg, result.fixups);
    } else if (op.kind == OperandKind::Memory) {
        bool xExt = op.mem.hasIndex() && isRexExtendedReg(op.mem.index);
        bool bExt = op.mem.hasBase() && isRexExtendedReg(op.mem.base);
        if (xExt || bExt) emitRex(result.bytes, false, false, xExt, bExt);
        result.bytes.push_back(0xFF);
        encodeModRMSIB(result.bytes, 2, op.mem, result.fixups);
    } else {
        throw EncodingError("Unsupported CALL operand");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeJMP(const InstructionIR& inst) {
    if (inst.operands.size() != 1) throw EncodingError("JMP requires 1 operand");
    const auto& op = inst.operands[0];
    EncodedInstruction result;
    if (op.kind == OperandKind::Label) {
        if (op.labelRelSize == 1) {
            result.bytes.push_back(0xEB);
            size_t fixupOff = result.bytes.size();
            result.bytes.push_back(0);
            result.fixups.push_back(Fixup{ FixupKind::Rel8, fixupOff, 0, op.labelId, 0 });
        } else {
            result.bytes.push_back(0xE9);
            size_t fixupOff = result.bytes.size();
            result.bytes.push_back(0); result.bytes.push_back(0); result.bytes.push_back(0); result.bytes.push_back(0);
            result.fixups.push_back(Fixup{ FixupKind::Rel32, fixupOff, 0, op.labelId, 0 });
        }
    } else if (op.kind == OperandKind::Register) {
        bool bExt = isRexExtendedReg(op.reg);
        if (bExt) emitRex(result.bytes, false, false, false, bExt);
        result.bytes.push_back(0xFF);
        encodeModRMSIB(result.bytes, 4, op.reg, result.fixups);
    } else if (op.kind == OperandKind::Memory) {
        bool xExt = op.mem.hasIndex() && isRexExtendedReg(op.mem.index);
        bool bExt = op.mem.hasBase() && isRexExtendedReg(op.mem.base);
        if (xExt || bExt) emitRex(result.bytes, false, false, xExt, bExt);
        result.bytes.push_back(0xFF);
        encodeModRMSIB(result.bytes, 4, op.mem, result.fixups);
    } else {
        throw EncodingError("Unsupported JMP operand");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeJCC(const InstructionIR& inst) {
    if (inst.operands.size() != 1) throw EncodingError("JCC requires 1 operand");
    const auto& op = inst.operands[0];
    if (op.kind != OperandKind::Label) throw EncodingError("JCC requires label operand");
    EncodedInstruction result;
    uint8_t cc = static_cast<uint8_t>(inst.cc);
    if (cc > 0x0F) throw EncodingError("JCC condition code out of range");
    if (op.labelRelSize == 1) {
        result.bytes.push_back(0x70 + cc);
        size_t fixupOff = result.bytes.size();
        result.bytes.push_back(0);
        result.fixups.push_back(Fixup{ FixupKind::Rel8, fixupOff, 0, op.labelId, 0 });
    } else {
        result.bytes.push_back(0x0F);
        result.bytes.push_back(0x80 + cc);
        size_t fixupOff = result.bytes.size();
        result.bytes.push_back(0); result.bytes.push_back(0); result.bytes.push_back(0); result.bytes.push_back(0);
        result.fixups.push_back(Fixup{ FixupKind::Rel32, fixupOff, 0, op.labelId, 0 });
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeRET(const InstructionIR& inst) {
    EncodedInstruction result;
    if (inst.operands.empty()) {
        result.bytes.push_back(0xC3);
    } else if (inst.operands.size() == 1 && inst.operands[0].kind == OperandKind::Immediate) {
        if (inst.operands[0].imm.size != 2) {
            throw EncodingError("RET immediate must be imm16");
        }
        result.bytes.push_back(0xC2);
        emitLE(result.bytes, inst.operands[0].imm.value, 2);
    } else {
        throw EncodingError("Unsupported RET operand combination");
    }
    return result;
}

EncodedInstruction InstructionEncoderX64::encodeNOP(const InstructionIR& inst) {
    EncodedInstruction result;
    if (inst.operands.empty()) {
        result.bytes.push_back(0x90);
    } else {
        throw EncodingError("NOP takes no operands");
    }
    return result;
}

} // namespace Backend
} // namespace RawrXD
