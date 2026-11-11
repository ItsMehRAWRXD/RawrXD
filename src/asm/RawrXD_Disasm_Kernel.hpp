#pragma once

// ============================================================================
// RawrXD_Disasm_Kernel.hpp
// Native C++20 x64 instruction decoder — replacement for the missing
// src/asm/RawrXD_Disasm_Kernel.asm (referenced by the rawrxd CLI target).
//
// Design constraints:
//   - Zero external dependencies (native C++20 + Win32 only).
//   - Decodes REAL instruction bytes; never fabricates disassembly.
//   - Unsupported or truncated encodings return an explicit failure status.
//   - Bounded, correct subset of x64 (not a complete disassembler).
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <optional>
#include <system_error>

namespace RawrXD {
namespace Disasm {

// Status returned by the decoder. A successful decode always fills the
// Instruction struct; failure returns std::nullopt with an error code.
enum class DecodeErrc {
    ok = 0,
    empty_input,
    truncated,        // Not enough bytes to complete the instruction
    unsupported,      // Opcode not in the supported subset
    invalid_prefix,   // Malformed prefix/rex combination
    internal_error,
};

std::string decodeErrcMessage(DecodeErrc e);

// A single decoded instruction.
struct Instruction {
    const std::uint8_t* ptr;       // Pointer into the input buffer (non-owning)
    std::size_t        length;     // Instruction length in bytes
    std::uint64_t      address;    // Virtual address of the instruction
    std::string        mnemonic;   // Human-readable mnemonic
    std::string        operands;   // Human-readable operand string
    bool               isBranch    = false;
    bool               isConditionalBranch = false;
    bool               isCall      = false;
    bool               isRet       = false;
    std::optional<std::int64_t> branchTarget; // Resolved target (absolute) for branches/calls
};

// Decode a single instruction starting at `ptr` with `remaining` bytes
// available. `address` is the virtual address of the first byte.
//
// Returns std::nullopt on failure; the error code indicates why.
std::optional<Instruction> decodeInstruction(const std::uint8_t* ptr,
                                             std::size_t remaining,
                                             std::uint64_t address);

// Decode all instructions in [begin, end) until failure or end of buffer.
// Stops at the first undecodable instruction and returns what was decoded
// plus the error.
struct DecodeResult {
    std::vector<Instruction> instructions;
    std::optional<DecodeErrc> error;
    std::size_t bytesConsumed;
};

DecodeResult decodeBuffer(const std::uint8_t* begin,
                          const std::uint8_t* end,
                          std::uint64_t startAddress);

// Disassemble a byte range into a human-readable string (one instruction
// per line: address  mnemonic operands).
std::string disassemble(const std::uint8_t* begin,
                        const std::uint8_t* end,
                        std::uint64_t startAddress);

// Check whether a single byte could be the start of a supported instruction.
// Useful for scanning / resynchronization.
bool isSupportedOpcode(std::uint8_t b);

// Get the length (in bytes) of a supported instruction without full decode.
// Returns std::nullopt if unsupported/truncated.
std::optional<std::size_t> instructionLength(const std::uint8_t* ptr,
                                             std::size_t remaining);

} // namespace Disasm
} // namespace RawrXD
