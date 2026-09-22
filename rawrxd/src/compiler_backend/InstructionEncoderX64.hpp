#pragma once

#include "rawr_backend_types.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <stdexcept>

namespace RawrXD {
namespace Backend {

// ============================================================================
// x64 Instruction Encoder
// ============================================================================

class InstructionEncoderX64 {
public:
    InstructionEncoderX64();

    // Encode a single instruction. Returns bytes + fixups.
    EncodedInstruction encode(const InstructionIR& inst);

    // Label management
    uint32_t createLabel(const std::string& name);
    void bindLabel(uint32_t labelId, size_t offset);
    bool isLabelBound(uint32_t labelId) const;
    size_t getLabelOffset(uint32_t labelId) const;

    // Reset state for new function/section
    void reset();

    // Current code offset (for fixup resolution)
    size_t currentOffset() const { return m_currentOffset; }
    void advanceOffset(size_t len) { m_currentOffset += len; }

private:
    size_t m_currentOffset = 0;
    uint32_t m_nextLabelId = 1;
    std::unordered_map<uint32_t, Label> m_labels;

    // Core encoding helpers
    void emitRex(std::vector<uint8_t>& out, bool w, bool r, bool x, bool b);
    void emitModRM(std::vector<uint8_t>& out, uint8_t mod, uint8_t reg, uint8_t rm);
    void emitSIB(std::vector<uint8_t>& out, uint8_t scale, uint8_t index, uint8_t base);
    void emitImm(std::vector<uint8_t>& out, const Immediate& imm);
    void emitDisp8(std::vector<uint8_t>& out, int8_t disp);
    void emitDisp32(std::vector<uint8_t>& out, int32_t disp);

    // Operand analysis
    uint8_t determineOperandSize(const InstructionIR& inst) const;
    bool needsRexW(const InstructionIR& inst, uint8_t opSize) const;
    bool isRexExtendedReg(Register r) const;
    bool isRexExtendedMem(const MemoryOperand& mem) const;

    // Addressing mode encoding
    void encodeModRMSIB(std::vector<uint8_t>& out,
                        uint8_t regField,
                        const MemoryOperand& mem,
                        std::vector<Fixup>& fixups);
    void encodeModRMSIB(std::vector<uint8_t>& out,
                        uint8_t regField,
                        Register reg,
                        std::vector<Fixup>& fixups);

    // Per-instruction encoders
    EncodedInstruction encodeMOV(const InstructionIR& inst);
    EncodedInstruction encodeLEA(const InstructionIR& inst);
    EncodedInstruction encodePUSH(const InstructionIR& inst);
    EncodedInstruction encodePOP(const InstructionIR& inst);
    EncodedInstruction encodeALU(const InstructionIR& inst, uint8_t opcode);
    EncodedInstruction encodeALUImm(const InstructionIR& inst, uint8_t immOpcode8, uint8_t immOpcode);
    EncodedInstruction encodeIMUL(const InstructionIR& inst);
    EncodedInstruction encodeCMP(const InstructionIR& inst);
    EncodedInstruction encodeTEST(const InstructionIR& inst);
    EncodedInstruction encodeShift(const InstructionIR& inst, uint8_t shiftOpcode);
    EncodedInstruction encodeINC_DEC(const InstructionIR& inst, bool isInc);
    EncodedInstruction encodeCALL(const InstructionIR& inst);
    EncodedInstruction encodeJMP(const InstructionIR& inst);
    EncodedInstruction encodeJCC(const InstructionIR& inst);
    EncodedInstruction encodeRET(const InstructionIR& inst);
    EncodedInstruction encodeNOP(const InstructionIR& inst);
};

} // namespace Backend
} // namespace RawrXD
