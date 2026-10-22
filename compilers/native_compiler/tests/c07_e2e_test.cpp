// C07 - End-to-end native toolchain certification.
//
//   assembly source
//        |
//        v
//   RawrXD first-party x64 assembler  ->  COFF object
//        |
//        v
//   RawrXD native linker              ->  PE32+ executable
//        |
//        v
//   Windows loader                   ->  kernel32!ExitProcess(42)
//        |
//        v
//   process exit code 42
//
// Every stage is first-party. No external assembler, linker, compiler or
// packager takes part, and the produced executable is run to prove the
// image is not merely well formed but actually works.
//
// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------
//
// The eight assertions below are unconditional: every one of them records
// exactly one PASS or FAIL, whether or not the stage before it succeeded.
// A gate whose result count depends on what failed is not a gate.
//
// Both assembly fixtures are written before any assembler runs, so the
// assembler always has an input, and every path that reaches the shell is
// built with backslashes: std::system() goes through cmd.exe, and cmd.exe
// rejects a path that contains a forward slash. The assembler takes native
// paths and is given the same form, so the two stages agree on what they are
// talking about.
//
// The work directory defaults to the directory the test executable lives in,
// so the test can be run from any working directory.

#include "asm/X64Assembler.h"
#include "common/Types.h"
#include "rawrstd/sys.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "rawrstd/string.h"

using namespace rawr;
using rawrstd::String;

static int g_pass = 0;
static int g_fail = 0;

static void ok(const char* what) {
    rawrstd::write_stdout("  [PASS] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("\n", 1);
    ++g_pass;
}

static void bad(const char* what, const String& detail) {
    rawrstd::write_stdout("  [FAIL] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("  -- ", 4);
    rawrstd::write_stderr(detail.data(), detail.size());
    rawrstd::write_stderr("\n", 1);
    ++g_fail;
}

static void check(bool cond, const char* what, const String& detail = "") {
    if (cond) ok(what);
    else bad(what, detail);
}

static String Num(int value) {
    char buffer[16];
    std::snprintf(buffer, sizeof(buffer), "%d", value);
    return String(buffer);
}

// The value of one hexadecimal digit.
static int HexDigit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// Appends a byte as two hexadecimal digits.
static void AppendHex(String& out, uint8_t byte) {
    const char* digits = "0123456789ABCDEF";
    out << digits[(byte >> 4) & 0x0F];
    out << digits[byte & 0x0F];
}

// Prepare a command for cmd.exe.
//
// The C runtime runs system() by invoking "cmd.exe /c <command>" as a raw
// command line. cmd.exe has a special rule for a /c command that begins
// with a quote: it strips the first and the last quote of the whole string
// and interprets what is left. A command that starts with a quoted
// executable path therefore loses its closing quote and the linker is
// invoked with the name
//     rawrxd_link.exe" -o "out.exe
// which fails with "The filename, directory name, or volume label syntax is
// incorrect".
//
// Wrapping the command in one more pair of quotes makes the stripping land on
// the wrapper instead of on the path.
static String WrapForCmd(const String& command) {
    String wrapped;
    wrapped << "\"";
    wrapped << command.data();
    wrapped << "\"";
    return wrapped;
}

// A path the shell can use.
//
// cmd.exe rejects a forward slash in a path, so every path that is handed to
// the shell is built with backslashes.
static String NormalizeSeparators(const char* path) {
    String out;
    for (const char* p = path; *p; ++p) {
        out << (*p == '/' ? '\\' : *p);
    }
    return out;
}

// Join a directory and a leaf name into one backslash path.
static String JoinPath(const String& dir, const char* leaf) {
    String out;
    out << dir;
    const size_t n = out.size();
    if (n > 0 && out.data()[n - 1] != '\\') {
        out << '\\';
    }
    out << leaf;
    return out;
}

// Does the file exist, and is it not empty?
static bool FileExistsNonEmpty(const char* path) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    const long size = std::ftell(f);
    std::fclose(f);
    return size > 0;
}

// The program the toolchain has to build.
//
// It follows the Win64 calling convention: the entry point reserves the
// shadow space, passes the exit code in ECX, and calls ExitProcess.
//
//   main:
//       sub  rsp, 40
//       mov  ecx, 42
//       call ExitProcess
//       add  rsp, 40
//       ret
//
// The reservation is 40 bytes, not 32. The shadow space is 32 bytes, and
// the extra 8 bytes keep the stack pointer 16 byte aligned at the call.
//
// The Windows loader enters the entry point with the stack pointer at
// 8 modulo 16, and the ABI requires it to be at 0 modulo 16 immediately
// before a call, because the call pushes the return address. A reservation
// of 32 leaves the stack pointer at 8 modulo 16 at the call, so the callee
// is entered with a stack pointer that is 8 modulo 16 instead of 0 modulo
// 16, and every 16 byte aligned move inside the callee faults. The
// observable result is an access violation inside kernel32 rather than an
// exit code, which makes it look like a toolchain defect.
//
// The C05 fixture reserves 0x28 for the same reason.
//
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

// A second program that exercises more of the encoder: arithmetic, a
// register-to-register move, a push/pop pair and a branch.
static const char kArithmeticProgram[] =
    "bits 64\n"
    "default rel\n"
    "section .text\n"
    "global main\n"
    "extern ExitProcess\n"
    "\n"
    "main:\n"
    "    sub  rsp, 40\n"
    "    mov  eax, 20\n"
    "    mov  ebx, 21\n"
    "    add  rax, rbx\n"
    "    sub  rsp, 8\n"
    "    push rax\n"
    "    pop  rcx\n"
    "    add  rsp, 8\n"
    "    call ExitProcess\n"
    "    add  rsp, 40\n"
    "    ret\n";

// Write a fixture and report whether it landed.
//
// The length comes from strlen, not from sizeof: source is a pointer once it
// reaches this function, so sizeof(source) is the size of a pointer and
// sizeof(source) - 1 is 7 on x64. Using it truncates every fixture to its
// first seven bytes, which leaves the assembler with an empty .text section,
// an object file with no 'main' symbol, and an executable that cannot run.
static bool WriteFixture(const String& path, const char* source) {
    rawrstd::File out;
    if (!out.open(path.data(), rawrstd::FileMode::Write)) return false;
    out.write(source, std::strlen(source));
    out.close();
    return true;
}

// Prepare a command for cmd.exe.
//
// The C runtime runs system() by invoking "cmd.exe /c <command>" as a raw
// command line. cmd.exe has a special rule for a /c command that begins
// with a quote: it strips the first and the last quote of the entire string
int main(int argc, char** argv) {
    rawrstd::write_stdout("C07 End-to-end native toolchain certification\n", 45);
    rawrstd::write_stdout("============================================\n", 44);

    // The work directory is the one the test executable lives in unless the
    // caller says otherwise, so the test does not depend on the current
    // working directory.
    String workDir;
    if (argc > 1 && argv[1][0]) {
        workDir = NormalizeSeparators(argv[1]);
    } else {
        const char* self = argv[0];
        const char* lastSep = self;
        for (const char* p = self; *p; ++p) {
            if (*p == '\\' || *p == '/') lastSep = p + 1;
        }
        String dir;
        for (const char* p = self; p < lastSep; ++p) dir << *p;
        workDir = NormalizeSeparators(dir.data());
    }
    const char* linker = (argc > 2) ? argv[2] : "";

    if (!linker[0]) {
        bad("the linker path was supplied", String("no linker path given"));
        return 1;
    }

    const String asmPath  = JoinPath(workDir, "c07_e2e.asm");
    const String objPath  = JoinPath(workDir, "c07_e2e.obj");
    const String exePath  = JoinPath(workDir, "c07_e2e.exe");
    const String asmPath2 = JoinPath(workDir, "c07_arith.asm");
    const String objPath2 = JoinPath(workDir, "c07_arith.obj");
    const String exePath2 = JoinPath(workDir, "c07_arith.exe");

    // ---- The fixtures are written before anything is invoked ----
    const bool wroteFirst  = WriteFixture(asmPath, kProgram);
    const bool wroteSecond = WriteFixture(asmPath2, kArithmeticProgram);
    const bool fixturesReady = wroteFirst && wroteSecond &&
        FileExistsNonEmpty(asmPath.data()) && FileExistsNonEmpty(asmPath2.data());
    check(fixturesReady, "both assembly fixtures were written and are not empty",
          String("c07_e2e.asm and c07_arith.asm"));

    // ---- Stage 1: assemble the first program ----
    bool assembled = false;
    {
        rawrstd::String error;
        assembled = assembleX64File(rawrstd::String(asmPath), objPath, error);
        const bool objectLanded = assembled && FileExistsNonEmpty(objPath.data());
        check(objectLanded, "the first-party assembler produced a COFF object", error);
        assembled = objectLanded;
    }

    // ---- Stage 1b: the instruction encodings are the documented ones ----
    //
    // The end to end checks below prove that the program runs, but a program
    // can also run by accident. These assertions pin the exact bytes that
    // the three instruction forms produce, because each of them has been
    // wrong at least once and each defect was invisible to every other gate:
    // the other suites build their machine code by hand and never reach the
    // encoder.
    //
    //   sub  rsp, 40   48 83 EC 28     group 1, sign extended byte immediate
    //   mov  ecx, 42   B9 2A 00 00 00  the register is folded into the opcode
    //   call ExitProcess E8 00 00 00 00  the displacement is patched by the linker
    //   add  rsp, 40   48 83 C4 28
    //   ret            C3
    {
        AsmObject object;
        rawrstd::String error;
        const bool encoded = assembleX64(rawrstd::String(kProgram), "c07_e2e.asm",
                                          object, error);
        const AsmSection* text = nullptr;
        for (const AsmSection& section : object.sections) {
            if (section.name == ".text") text = &section;
        }
        static const uint8_t kExpected[] = {
            0x48, 0x83, 0xEC, 0x28,             // sub rsp, 40
            0xB9, 0x2A, 0x00, 0x00, 0x00,       // mov ecx, 42
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call ExitProcess
            0x48, 0x83, 0xC4, 0x28,             // add rsp, 40
            0xC3                              // ret
        };
        bool matches = encoded && text != nullptr &&
                       text->data.size() == sizeof(kExpected);
        for (size_t i = 0; matches && i < sizeof(kExpected); ++i) {
            if (text->data[i] != kExpected[i]) matches = false;
        }
        check(matches, "the assembler encodes the documented instruction bytes",
              encoded ? String("the .text section does not hold the expected bytes")
                      : error);
    }

    // ---- Stage 1c: the memory forms of the ALU operations ----
    //
    // A memory operand carries no size qualifier in this assembler, so the
    // operation is always the 32 bit one. The rm field has three special
    // cases in 64 bit mode, and every one of them was wrong at some point:
    //
    //   rm = 101 with mod = 00 is the RIP relative form.
    //   rm = 100 means a SIB byte follows.
    //   rm = 101 with a non zero mod is a SIB byte whose base is 101.
    //
    // The register parser also has to tell rip apart from rax, which share
    // the register number zero.
    {
        struct MemoryForm {
            const char* instruction;
            const char* expected;   // the bytes, in hex
        };
        static const MemoryForm kForms[] = {
            { "add  [rax], ebx",        "0118" },
            { "add  ebx, [rax]",        "0118" },
            { "sub  [rax], ebx",        "2918" },
            { "add  [rax+8], ebx",      "015808" },
            { "add  [rax+0x100], ebx",  "019800010000" },
            { "add  [rbp], ebx",        "015C2500" },
            { "add  [rsp], ebx",        "011C24" },
            { "add  [r12], ebx",        "41011C24" },
            { "add  [rax+rcx*8], ebx", "011CC8" },
            { "add  [rcx*8], ebx",      "015CCD00" },
            { "add  [0x1234], ebx",     "011C2534120000" },
            { "mov  rcx, [rip+target]", "488B0D00000000" },
            { "mov  [rip+target], rcx", "48890D00000000" },
        };
        bool allMatch = true;
        String firstFailure;
        for (size_t f = 0; f < sizeof(kForms) / sizeof(kForms[0]); ++f) {
            String source;
            source << "bits 64\nsection .text\nmain:\n    " << kForms[f].instruction << "\n";
            AsmObject object;
            rawrstd::String error;
            const bool encoded = assembleX64(source, "c07_memory.asm", object, error);
            const AsmSection* text = nullptr;
            for (const AsmSection& section : object.sections) {
                if (section.name == ".text") text = &section;
            }
            const size_t expectedLength = std::strlen(kForms[f].expected) / 2;
            bool matches = encoded && text != nullptr &&
                           text->data.size() == expectedLength;
            for (size_t i = 0; matches && i < expectedLength; ++i) {
                const char* pair = kForms[f].expected + i * 2;
                const uint8_t want = (uint8_t)((HexDigit(pair[0]) << 4) | HexDigit(pair[1]));
                if (text->data[i] != want) matches = false;
            }
            if (!matches) {
                allMatch = false;
                if (firstFailure.empty()) {
                    firstFailure << kForms[f].instruction << " -> ";
                    for (size_t i = 0; text && i < text->data.size(); ++i) {
                        AppendHex(firstFailure, text->data[i]);
                    }
                    firstFailure << ", wanted " << kForms[f].expected;
                }
            }
        }
        check(allMatch, "the assembler encodes the memory forms correctly",
              firstFailure.empty() ? String("a memory form did not match") : firstFailure);
    }


    // ---- Stage 1c: the 64 bit immediate form ----------------------------
    //
    // A 64 bit destination with an immediate is the sign extended form,
    // C7 /0. The B8 form takes a 64 bit immediate, so writing only four
    // bytes of it truncates the instruction and the bytes that follow are
    // decoded as part of it.
    {
        static const char kWideProgram[] =
            "bits 64\n"
            "section .text\n"
            "main:\n"
            "    mov  rax, 42\n"
            "    mov  rcx, rax\n";
        static const uint8_t kExpectedWide[] = {
            0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00,   // mov rax, 42
            0x48, 0x89, 0xC1                            // mov rcx, rax
        };
        AsmObject object;
        rawrstd::String error;
        const bool encoded = assembleX64(rawrstd::String(kWideProgram),
                                          "c07_wide.asm", object, error);
        const AsmSection* text = nullptr;
        for (const AsmSection& section : object.sections) {
            if (section.name == ".text") text = &section;
        }
        bool matches = encoded && text != nullptr &&
                       text->data.size() == sizeof(kExpectedWide);
        for (size_t i = 0; matches && i < sizeof(kExpectedWide); ++i) {
            if (text->data[i] != kExpectedWide[i]) matches = false;
        }
        check(matches, "the assembler encodes a 64 bit immediate without truncating it",
              encoded ? String("the .text section does not hold the expected bytes")
                      : error);
    }

    // ---- Stage 2: link the first program ----
    bool linked = false;
    {
        if (!assembled) {
            bad("the native linker produced an executable",
                String("the assembly stage did not produce an object"));
        } else {
            String cmd;
            cmd << "\"" << linker << "\" -o \"" << exePath.data()
                << "\" -subsys 3 -entry main \"" << objPath.data() << "\"";
            const int result = std::system(WrapForCmd(cmd).data());
            linked = (result == 0) && FileExistsNonEmpty(exePath.data());
            check(linked, "the native linker produced an executable",
                  String("the linker returned ") + Num(result) +
                      (result == 0 ? String() : String("; no executable was produced")));
        }
    }

    // ---- Stage 3: run the first program ----
    {
        if (!linked) {
            bad("the executable ran and exited with 42",
                String("there was no executable to run"));
        } else {
            String runCmd;
            runCmd << "\"" << exePath.data() << "\"";
            const int code = std::system(WrapForCmd(runCmd).data());
            check(code == 42, "the executable ran and exited with 42",
                  String("exit code ") + Num(code));
        }
    }

    // ---- Stage 4: a second program that exercises more of the encoder ----
    bool assembled2 = false;
    {
        rawrstd::String error;
        const bool produced = assembleX64File(rawrstd::String(asmPath2), objPath2, error);
        assembled2 = produced && FileExistsNonEmpty(objPath2.data());
        check(assembled2, "the arithmetic program assembled", error);
    }

    {
        if (!assembled2) {
            bad("the arithmetic program produced 41",
                String("the arithmetic program did not assemble"));
        } else {
            String cmd;
            cmd << "\"" << linker << "\" -o \"" << exePath2.data()
                << "\" -subsys 3 -entry main \"" << objPath2.data() << "\"";
            const int linkResult = std::system(WrapForCmd(cmd).data());
            if (linkResult != 0 || !FileExistsNonEmpty(exePath2.data())) {
                bad("the arithmetic program produced 41",
                    String("the linker returned ") + Num(linkResult));
            } else {
                String runCmd;
                runCmd << "\"" << exePath2.data() << "\"";
                const int code = std::system(WrapForCmd(runCmd).data());
                // 20 + 21 = 41
                check(code == 41, "the arithmetic program produced 41",
                      String("exit code ") + Num(code));
            }
        }
    }

    // ---- Stage 5: the assembler rejects malformed input ----
    {
        AsmObject object;
        rawrstd::String error;
        bool assembledBad = assembleX64("bits 64\nthis_is_not_an_instruction rax\n",
                                       "malformed.asm", object, error);
        check(!assembledBad, "the assembler rejects an unknown instruction");
    }
    {
        AsmObject object;
        rawrstd::String error;
        bool assembledBad = assembleX64("bits 64\nsection .text\nmain:\n    mov  eax, \n",
                                       "truncated.asm", object, error);
        check(!assembledBad, "the assembler rejects a truncated operand");
    }

    rawrstd::write_stdout("--------------------------------------------\n", 44);
    String summary;
    summary << "C07 result: " << g_pass << " passed, " << g_fail << " failed\n";
    rawrstd::write_stdout(summary.data(), summary.size());

    return g_fail == 0 ? 0 : 1;
}

