// ============================================================================
//  A first-party x64 assembler.
//
//  The toolchain needs to turn the compiler's assembly output into COFF
//  objects. The upstream assembler that used to fill this role has four
//  confirmed encoding defects and no source, so the capability is
//  implemented here instead.
//
//  The accepted syntax is the MASM-style subset that the RawrXD compilers
//  emit:
//
//      bits 64
//      default rel
//      section .text
//      global  main
//      extern  ExitProcess
//
//      main:
//          push    rbp
//          mov     rbp, rsp
//          sub     rsp, 40
//          mov     rax, 42
//          call    ExitProcess
//          mov     rsp, rbp
//          pop     rbp
//          ret
//
// The reservation is 40 bytes rather than the 32 bytes of shadow space,
// because the extra 8 bytes keep the stack pointer 16 byte aligned at the
// call. The Windows loader enters the entry point with the stack pointer at
// 8 modulo 16, and a call requires it to be at 0 modulo 16 immediately
// before the call instruction, because the call pushes the return address.
// A reservation of 32 leaves it at 8 modulo 16, and every 16 byte aligned
// move inside the callee faults.
//
// Supported: mov, lea, add, sub, and, or, xor, cmp, test, inc, dec, neg,
// push, pop, call, ret, leave, jmp, jcc, imul, idiv, cdq, movzx, movsx,
// nop, int3, and the label and memory forms those need.
//
// A memory operand has no size qualifier, so the memory forms are always
// the 32 bit ones. The register parser keeps rip apart from rax, which
// share the register number zero.
// ============================================================================

#ifndef RAWR_X64_ASSEMBLER_H
#define RAWR_X64_ASSEMBLER_H

#include "rawrstd/string.h"
#include <vector>

namespace rawr {

// One relocation the linker must fix up.
struct AsmRelocation {
    uint32_t offset = 0;      // byte offset within the section
    rawrstd::String symbol;        // the target symbol
    bool addend = false;       // true when the value is a 64-bit absolute
};

// One assembled section.
struct AsmSection {
    rawrstd::String name;
    uint32_t characteristics = 0;
    std::vector<uint8_t> data;
    std::vector<AsmRelocation> relocations;
};

// One symbol the assembler defines.
struct AsmSymbol {
    rawrstd::String name;
    rawrstd::String section;
    uint32_t value = 0;
    bool global = false;
    bool external = false;
};

struct AsmObject {
    std::vector<AsmSection> sections;
    std::vector<AsmSymbol> symbols;
};

// Assembles `source` into `out`. Returns false and fills `error` when the
// source cannot be assembled.
bool assembleX64(const rawrstd::String& source, const rawrstd::String& sourceName,
                  AsmObject& out, rawrstd::String& error);

// Assembles a file and writes a COFF object.
bool assembleX64File(const rawrstd::String& asmPath, const rawrstd::String& objPath,
                     rawrstd::String& error);

} // namespace rawr

#endif // RAWR_X64_ASSEMBLER_H
