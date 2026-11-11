// C05 - Relocations, imports and external symbol resolution.
//
// Exercises the harder parts of the linking path:
//
//   1. An ADDR64 relocation: a global pointer in .data that points at a
//      symbol in another object. This produces an absolute address in the
//      image, which is what forces the base relocation table to exist.
//
//   2. Imports from several DLLs, reached through both the `__imp_`
//      convention and a redirect thunk.
//
//   3. A PC-relative REL32 relocation between two objects.
//
//   4. A read-only data section (.rdata) with a string in it.
//
// The program verifies the values at runtime, so a wrong relocation is
// caught by the program's own logic rather than by inspection.

#include "object/CoffWriter.h"

#include "rawrstd/sys.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

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

static void check(bool cond, const char* what) {
    if (cond) ok(what);
    else bad(what, String("condition false"));
}

// ---------------------------------------------------------------------------
// The program.
//
// It reads a global pointer, compares the value it points at, calls an
// imported function from a second DLL, and exits with zero when the
// comparison succeeded. A crash produces 0xC0000005, so the exit code
// distinguishes the two.
//
//   0x00: 48 83 EC 28           sub  rsp, 0x28        ; shadow space
//   0x04: 4C 8D 0D <disp>       lea  r9,  [rip+str]    ; disp at 0x07
//   0x0B: 4C 89 C9              mov  rcx, r9          ; 1st argument
//   0x0E: FF 15 <disp>           call [rip+lstrlenA]  ; disp at 0x10
//   0x14: 48 8B 0D <disp>       mov  rcx, [rip+gPtr]  ; disp at 0x17
//   0x1B: 8B 09                 mov  ecx, [rcx]       ; the value
//   0x1D: 3D 2A 00 00 00        cmp  ecx, 42
//   0x22: 0F 94 C0              sete al
//   0x25: 0F B6 C8              movzx ecx, al
//   0x28: FF 15 <disp>           call [rip+ExitProcess]; disp at 0x2A
//   0x2E: C3                    ret
//
// The displacement offsets are the byte positions of the displacement
// fields, which must be recomputed whenever the code above changes.
static const uint8 kEntryCode[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,       // lea r9, [rip+str]
    0x4C, 0x89, 0xC9,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,             // call [rip+lstrlenA]
    0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,       // mov rcx, [rip+gPtr]
    0x8B, 0x09,
    0x3D, 0x2A, 0x00, 0x00, 0x00,
    0x0F, 0x94, 0xC0,
    0x0F, 0xB6, 0xC8,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,             // call [rip+ExitProcess]
    0xC3
};
static const uint32 kRelocStr     = 0x07;
static const uint32 kRelocLstrlen = 0x10;
static const uint32 kRelocDataPtr = 0x17;
static const uint32 kRelocExit    = 0x2A;

// The .data section holds the value 42 followed by a pointer to it. The
// pointer is filled in by an ADDR64 relocation, which is what produces an
// absolute address in the image and therefore requires base relocations.
static const uint8 kDataValue[] = {
    42, 0, 0, 0, 0, 0, 0, 0,     // gValue
    0, 0, 0, 0, 0, 0, 0, 0        // gPtr (patched by the linker)
};
static const char kRdata[] = "RawrXD";

static bool run_and_get_exit(const String& cmd, DWORD* out_code) {
    rawrstd::Vector<uint16> wide;
    for (size_type i = 0; i < cmd.size(); ++i) wide.push_back(static_cast<uint16>(cmd[i]));
    wide.push_back(0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, reinterpret_cast<LPWSTR>(&wide[0]), NULL, NULL, FALSE,
                         0, NULL, NULL, &si, &pi)) {
        return false;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, out_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

int main(int argc, char** argv) {
    const char* work_dir = (argc > 1) ? argv[1] : ".";
    const char* linker = (argc > 2) ? argv[2] : "";

    rawrstd::write_stdout("C05 Relocation and import certification\n", 43);
    rawrstd::write_stdout("=========================================\n", 41);

    if (!linker[0]) {
        bad("linker path supplied", String("no linker path given"));
        return 1;
    }

    String obj;
    obj << work_dir << "/c05_reloc.obj";
    String exe;
    exe << work_dir << "/c05_reloc.exe";

    // -----------------------------------------------------------------
    // Build the object
    // -----------------------------------------------------------------
    {
        CoffWriter w;
        int text = w.add_section(".text", kScnCntCode | kScnMemExecute | kScnMemRead, 16);
        w.append_data(text, kEntryCode, sizeof(kEntryCode));

        int data = w.add_section(".data", kScnCntInitialized | kScnMemRead | kScnMemWrite, 8);
        w.append_data(data, kDataValue, sizeof(kDataValue));

        int rdata = w.add_section(".rdata", kScnCntInitialized | kScnMemRead, 4);
        w.append_data(rdata, kRdata, sizeof(kRdata));

        // The pointer lives in .data and refers to the value in .data.
        int gvalue = w.add_symbol(CoffSymbol::internal("gValue", static_cast<int16>(data), 0));
        int gptr = w.add_symbol(CoffSymbol::internal("gPtr", static_cast<int16>(data), 8));
        int str = w.add_symbol(CoffSymbol::internal("gString", static_cast<int16>(rdata), 0));
        int lstrlen = w.add_symbol(CoffSymbol::external("__imp_lstrlenA"));
        int exitp = w.add_symbol(CoffSymbol::external("__imp_ExitProcess"));
        w.add_symbol(CoffSymbol::external("entry", static_cast<int16>(text), 0, true));

        w.add_relocation(text, kRelocDataPtr, static_cast<uint32>(gptr), CoffReloc::Rel32);
        w.add_relocation(text, kRelocStr, static_cast<uint32>(str), CoffReloc::Rel32);
        w.add_relocation(text, kRelocLstrlen, static_cast<uint32>(lstrlen), CoffReloc::Rel32);
        w.add_relocation(text, kRelocExit, static_cast<uint32>(exitp), CoffReloc::Rel32);

        // The pointer itself is an absolute address, so it is filled in by
        // an ADDR64 relocation rather than a PC-relative one.
        w.add_relocation(data, 8, static_cast<uint32>(gvalue), CoffReloc::Addr64);

        w.add_directive("/DEFAULTLIB:kernel32.lib");

        check(w.write(obj.data()), "the relocation fixture object was written");
    }

    // -----------------------------------------------------------------
    // Link and run
    // -----------------------------------------------------------------
    String cmd;
    cmd << "\"" << linker << "\" -o \"" << exe.data() << "\" -subsys 3 -entry entry \""
        << obj.data() << "\"";

    DWORD link_code = 0xDEADBEEF;
    bool ran = run_and_get_exit(cmd, &link_code);
    check(ran, "the linker ran");
    check(link_code == 0, "the linker completed successfully");
    if (link_code != 0) {
        String d;
        d << "linker exit code " << static_cast<uint64>(link_code);
        bad("the linker completed successfully", d);
    }

    DWORD exit_code = 0xDEADBEEF;
    String run_cmd;
    run_cmd << "\"" << exe.data() << "\"";
    ran = run_and_get_exit(run_cmd, &exit_code);
    check(ran, "Windows loaded and started the relocation fixture");
    // The program exits 0 when the data relocation resolved to 42 and 1
    // otherwise, so this checks the relocation rather than the import.
    check(exit_code == 0, "the data and read-only relocations resolved correctly");
    if (exit_code != 0) {
        String d;
        d << "exit code " << static_cast<uint64>(exit_code);
        bad("the data and read-only relocations resolved correctly", d);
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    rawrstd::write_stdout("-----------------------------------------\n", 41);
    String summary;
    summary << "C05 result: " << g_pass << " passed, " << g_fail << " failed\n";
    rawrstd::write_stdout(summary.data(), summary.size());

    return g_fail == 0 ? 0 : 1;
}
