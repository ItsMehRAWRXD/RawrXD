// C07 probe — what does the first-party assembler actually produce?
//
// This is a diagnostic, not a gate. It assembles the C07 program in memory
// and prints the sections and symbols, so the empty object can be traced to
// the stage that lost them.

#include "asm/X64Assembler.h"

#include <cstdio>
#include "rawrstd/string.h"

using namespace rawr;
using rawrstd::String;

static const char kProgram[] =
    "bits 64\n"
    "default rel\n"
    "section .text\n"
    "global main\n"
    "extern ExitProcess\n"
    "\n"
    "main:\n"
    "    sub  rsp, 40\n"
    "    mov  ecx, 42\n"
    "    call ExitProcess\n"
    "    add  rsp, 40\n"
    "    ret\n";

int main(int argc, char** argv) {
    AsmObject object;
    rawrstd::String error;
    const bool ok = assembleX64(rawrstd::String(kProgram), "probe.asm", object, error);

    std::printf("assembleX64 ok=%d error='%s'\n", ok ? 1 : 0, error.data());
    std::printf("sections=%zu symbols=%zu\n", object.sections.size(), object.symbols.size());

    for (size_t i = 0; i < object.sections.size(); ++i) {
        const AsmSection& s = object.sections[i];
        std::printf("  section[%zu] name='%s' chars=0x%08X data=%zu relocs=%zu\n",
                    i, s.name.data(), s.characteristics, s.data.size(), s.relocations.size());
    }
    for (size_t i = 0; i < object.symbols.size(); ++i) {
        const AsmSymbol& s = object.symbols[i];
        std::printf("  symbol[%zu] name='%s' section='%s' value=%u global=%d external=%d\n",
                    i, s.name.data(), s.section.data(), s.value,
                    s.global ? 1 : 0, s.external ? 1 : 0);
    }

    // ---- The memory forms of the ALU operations ----
    {
        static const char kMemoryProgram[] =
            "bits 64\n"
            "section .text\n"
            "main:\n"
            "    add  [rax], ebx\n"
            "    sub  [rax], ebx\n"
            "    add  [rax+8], ebx\n"
            "    add  ebx, [rax]\n";
        AsmObject mem;
        rawrstd::String memError;
        const bool okMem = assembleX64(rawrstd::String(kMemoryProgram), "mem.asm", mem, memError);
        std::printf("memory program ok=%d err='%s'\n", okMem ? 1 : 0, memError.data());
        for (size_t i = 0; i < mem.sections.size(); ++i) {
            const AsmSection& s = mem.sections[i];
            std::printf("  section '%s' data=%zu bytes:", s.name.data(), s.data.size());
            for (size_t b = 0; b < s.data.size(); ++b) std::printf(" %02X", s.data[b]);
            std::printf("\n");
        }
        std::printf("  expected: 01 18 29 18 01 58 08 01 18\n");

        // The same memory operands through the MOV encoder, which shares
        // EncodeMemory. If MOV is right, the parser is right and the ALU path
        // is handing over the wrong operand.
        static const char kMovMemory[] =
            "bits 64\n"
            "section .text\n"
            "main:\n"
            "    mov  [rax], ebx\n"
            "    mov  [rax+8], ebx\n";
        AsmObject movMem;
        rawrstd::String movError;
        const bool okMov = assembleX64(rawrstd::String(kMovMemory), "movmem.asm", movMem, movError);
        std::printf("mov memory program ok=%d err='%s'\n", okMov ? 1 : 0, movError.data());
        for (size_t i = 0; i < movMem.sections.size(); ++i) {
            const AsmSection& s = movMem.sections[i];
            std::printf("  section '%s' data=%zu bytes:", s.name.data(), s.data.size());
            for (size_t b = 0; b < s.data.size(); ++b) std::printf(" %02X", s.data[b]);
            std::printf("\n");
        }
        std::printf("  expected for mov [rax],ebx / mov [rax+8],ebx: 29 18 29 58 08\n");

        // Does ANY base register survive? And what does the displacement form
        // do on its own?
        static const char kBases[] =
            "bits 64\n"
            "section .text\n"
            "main:\n"
            "    mov  [rbx], ecx\n"
            "    mov  [rcx], ecx\n"
            "    mov  [rsp], ecx\n"
            "    mov  [rax+8], ecx\n";
        AsmObject bases;
        rawrstd::String baseError;
        const bool okBases = assembleX64(rawrstd::String(kBases), "bases.asm", bases, baseError);
        std::printf("base sweep ok=%d err='%s'\n", okBases ? 1 : 0, baseError.data());
        for (size_t i = 0; i < bases.sections.size(); ++i) {
            const AsmSection& s = bases.sections[i];
            std::printf("  section '%s' data=%zu bytes:", s.name.data(), s.data.size());
            for (size_t b = 0; b < s.data.size(); ++b) std::printf(" %02X", s.data[b]);
            std::printf("\n");
        }
        std::printf("  expected: 89 19 89 09 89 0C 24 89 48 08\n");
    }

    // ---- Does String::append work at all? ----
    {
        rawrstd::String t;
        t.append("0123456789", 10);
        std::printf("append 10 -> size=%zu data='%s'\n", t.size(), t.data());
        t.append("ABCDEFGHIJ", 10);
        std::printf("append 10+10 -> size=%zu data='%s'\n", t.size(), t.data());
    }

    // ---- The file path, exactly as assembleX64File does it ----
    if (argc > 1) {
        const char* asmPath = argv[1];
        std::FILE* f = std::fopen(asmPath, "rb");
        if (!f) {
            std::printf("cannot open %s\n", asmPath);
            return 1;
        }
        rawrstd::String source;
        char buffer[8192];
        size_t got;
        while ((got = std::fread(buffer, 1, sizeof(buffer), f)) > 0) {
            std::printf("  fread got=%zu\n", got);
            source.append(buffer, got);
            std::printf("  after append size=%zu\n", source.size());
        }
        std::fclose(f);
        std::printf("read '%s' -> source size=%zu\n", asmPath, source.size());
        std::printf("first 40 bytes: '%.40s'\n", source.data());

        AsmObject fromFile;
        rawrstd::String err2;
        const bool ok2 = assembleX64(source, asmPath, fromFile, err2);
        std::printf("from file: ok=%d err='%s' sections=%zu symbols=%zu\n",
                    ok2 ? 1 : 0, err2.data(), fromFile.sections.size(), fromFile.symbols.size());
        for (size_t i = 0; i < fromFile.sections.size(); ++i) {
            std::printf("  section[%zu] name='%s' data=%zu\n",
                        i, fromFile.sections[i].name.data(), fromFile.sections[i].data.size());
        }

        // And the file-based entry point itself.
        const char* objPath = (argc > 2) ? argv[2] : "probe.obj";
        rawrstd::String err3;
        const bool ok3 = assembleX64File(rawrstd::String(asmPath), rawrstd::String(objPath), err3);
        std::printf("assembleX64File ok=%d err='%s'\n", ok3 ? 1 : 0, err3.data());
        std::FILE* obj = std::fopen(objPath, "rb");
        if (obj) {
            std::fseek(obj, 0, SEEK_END);
            std::printf("object size=%ld\n", std::ftell(obj));
            std::fclose(obj);
        }
    }
    return 0;
}
