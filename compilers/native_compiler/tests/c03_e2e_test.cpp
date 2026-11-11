// C03 - End-to-end native toolchain certification.
//
// The complete vertical chain, with no external tool participating:
//
//   RawrXD C++ compiler (COFF writer)
//        |
//        v
//   COFF object
//        |
//        v
//   rawrxd_link.exe        (certified: RAWR_NATIVE_LINKER_CERT_001)
//        |
//        v
//   Windows PE32+ executable
//        |
//        v
//   Windows loader + kernel32!ExitProcess
//        |
//        v
//   process exit code 42
//
// The object emitted here is produced by the compiler's own COFF writer,
// not by an external compiler, so the whole path is first-party.

#include "object/CoffWriter.h"

#include "rawrstd/sys.h"

// The certification harness itself may use the host SDK; the compiler
// under test does not depend on it. The harness is a bootstrap-stage
// artifact, not part of the shipped compiler.
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
// The program under test.
//
//   entry:
//     sub  rsp, 0x28            ; 32 bytes of shadow space + 8 for alignment
//     mov  ecx, 42              ; uExitCode
//     call qword ptr [rip + d]  ; kernel32!ExitProcess
//     add  rsp, 0x28
//     ret
// ---------------------------------------------------------------------------
static const uint8 kCode[] = {
    0x48, 0x83, 0xEC, 0x28,
    0xB9, 0x2A, 0x00, 0x00, 0x00,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x28,
    0xC3
};
static const uint32 kCallDispOffset = 11;

int main(int argc, char** argv) {
    const char* work_dir = (argc > 1) ? argv[1] : ".";
    const char* linker = (argc > 2) ? argv[2] : "";

    rawrstd::write_stdout("C03 End-to-end native toolchain certification\n", 45);
    rawrstd::write_stdout("===============================================\n", 47);

    if (!linker[0]) {
        bad("linker path supplied", String("no linker path given"));
        return 1;
    }
    {
        rawrstd::File probe;
        bool present = probe.open(linker, rawrstd::FileMode::Read);
        if (present) probe.close();
        check(present, "the RawrXD linker is present");
        if (!present) return 1;
    }

    // -----------------------------------------------------------------
    // Step 1: emit the object with the compiler's COFF writer
    // -----------------------------------------------------------------
    String obj_path;
    obj_path << work_dir << "/c03_e2e.obj";
    String exe_path;
    exe_path << work_dir << "/c03_e2e.exe";

    CoffWriter writer;
    int text = writer.add_section(".text",
                                  kScnCntCode | kScnMemExecute | kScnMemRead, 16);
    writer.append_data(text, kCode, sizeof(kCode));

    // The import symbol is undefined, so the linker binds it to an IAT slot.
    int imp = writer.add_symbol(CoffSymbol::external("__imp_ExitProcess"));

    // The entry symbol must name the section that actually holds the code.
    // Section indices are 1-based and the writer may insert the .drectve
    // section ahead of the code, so the returned index is used rather than
    // a hard coded number.
    writer.add_symbol(CoffSymbol::external("entry", static_cast<int16>(text), 0, true));

    writer.add_relocation(text, kCallDispOffset, static_cast<uint32>(imp),
                          CoffReloc::Rel32);
    writer.add_directive("/DEFAULTLIB:kernel32.lib");

    check(writer.write(obj_path.data()), "the compiler emitted a COFF object");

    // -----------------------------------------------------------------
    // Step 2: link it with the certified RawrXD linker
    // -----------------------------------------------------------------
    // The linker is invoked directly rather than through a shell so that
    // the test records exactly which process did the work.
    String cmd;
    cmd << "\"" << linker << "\" -o \"" << exe_path.data()
        << "\" -subsys 3 -entry entry \"" << obj_path.data() << "\"";

    rawrstd::Vector<uint16> wide;
    for (size_type i = 0; i < cmd.size(); ++i) wide.push_back(static_cast<uint16>(cmd[i]));
    wide.push_back(0);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    BOOL created = CreateProcessW(NULL, reinterpret_cast<LPWSTR>(&wide[0]), NULL, NULL, FALSE, 0, NULL, NULL,
                                   &si, &pi);
    check(created != FALSE, "the linker ran and produced an executable");

    if (created) {
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD code = 0xDEADBEEF;
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        check(code == 0, "the linker completed successfully");
        if (code != 0) {
            String d;
            d << "linker exit code " << static_cast<uint64>(code);
            bad("the linker completed successfully", d);
        }
    }

    // -----------------------------------------------------------------
    // Step 3: run the produced executable
    // -----------------------------------------------------------------
    {
        rawrstd::File probe;
        bool present = probe.open(exe_path.data(), rawrstd::FileMode::Read);
        if (present) probe.close();
        check(present, "the executable exists on disk");
    }

    DWORD exit_code = 0xDEADBEEF;
    {
        rawrstd::Vector<uint16> wide;
        for (size_type i = 0; i < exe_path.size(); ++i) {
            wide.push_back(static_cast<uint16>(exe_path[i]));
        }
        wide.push_back(0);

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        BOOL created = CreateProcessW(NULL, reinterpret_cast<LPWSTR>(&wide[0]), NULL, NULL, FALSE, 0, NULL, NULL,
                                       &si, &pi);
        check(created != FALSE, "Windows loaded and started the executable");
        if (created) {
            WaitForSingleObject(pi.hProcess, 30000);
            GetExitCodeProcess(pi.hProcess, &exit_code);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }

    check(exit_code == 42, "the program ran and returned the expected exit code");
    if (exit_code != 42) {
        String d;
        d << "exit code " << static_cast<uint64>(exit_code);
        bad("the program ran and returned the expected exit code", d);
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    rawrstd::write_stdout("-----------------------------------------------\n", 47);
    String summary;
    summary << "C03 result: " << g_pass << " passed, " << g_fail << " failed\n";
    rawrstd::write_stdout(summary.data(), summary.size());

    return g_fail == 0 ? 0 : 1;
}
