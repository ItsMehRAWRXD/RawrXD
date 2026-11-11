// C04 - Multiple objects and cross-object symbol resolution.
//
// The linker must merge several COFF objects into one image, resolve
// symbols that are defined in one object and referenced from another, and
// produce an executable that runs.
//
//   obj_a.obj   defines `entry`, calls `compute_value` (defined in obj_b)
//
//   entry:
//     sub  rsp, 0x28
//     mov  ecx, 0
//     call compute_value      <- external, resolved from obj_b
//     mov  ecx, eax           ; the returned value becomes the exit code
//     call [rip + d]          ; kernel32!ExitProcess
//     add  rsp, 0x28
//     ret
//
//   obj_b.obj   defines `compute_value`, which returns 7
//
// The expected result is a process exit code of 7.

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
// obj_a: the entry point, which calls into obj_b.
//
//   0: 48 83 EC 28              sub  rsp, 0x28
//   4: 31 C9                    xor  ecx, ecx
//   6: E8 00 00 00 00           call compute_value     <- reloc at 7
//  11: 89 C1                    mov  ecx, eax
//  13: FF 15 00 00 00 00        call [rip + d]         <- reloc at 15
//  19: 48 83 C4 28              add  rsp, 0x28
//  23: C3                       ret
// ---------------------------------------------------------------------------
static const uint8 kEntryCode[] = {
    0x48, 0x83, 0xEC, 0x28,
    0x31, 0xC9,
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x89, 0xC1,
    0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x83, 0xC4, 0x28,
    0xC3
};
static const uint32 kCallValueOffset = 7;
static const uint32 kCallExitOffset = 15;

// ---------------------------------------------------------------------------
// obj_b: compute_value returns 7.
//
//   0: B8 07 00 00 00           mov eax, 7
//   5: C3                       ret
// ---------------------------------------------------------------------------
static const uint8 kHelperCode[] = {
    0xB8, 0x07, 0x00, 0x00, 0x00,
    0xC3
};

// ---------------------------------------------------------------------------
// A helper that runs a command line and returns the exit code.
// ---------------------------------------------------------------------------
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

    rawrstd::write_stdout("C04 Multi-object linking certification\n", 43);
    rawrstd::write_stdout("==========================================\n", 42);

    if (!linker[0]) {
        bad("linker path supplied", String("no linker path given"));
        return 1;
    }

    // -----------------------------------------------------------------
    // obj_a: the entry point
    // -----------------------------------------------------------------
    String obj_a;
    obj_a << work_dir << "/c04_a.obj";
    String obj_b;
    obj_b << work_dir << "/c04_b.obj";

    {
        CoffWriter w;
        int text = w.add_section(".text", kScnCntCode | kScnMemExecute | kScnMemRead, 16);
        w.append_data(text, kEntryCode, sizeof(kEntryCode));

        // `compute_value` is defined in the other object.
        int helper = w.add_symbol(CoffSymbol::external("compute_value"));
        w.add_symbol(CoffSymbol::external("entry", static_cast<int16>(text), 0, true));
        int imp = w.add_symbol(CoffSymbol::external("__imp_ExitProcess"));

        w.add_relocation(text, kCallValueOffset, static_cast<uint32>(helper),
                         CoffReloc::Rel32);
        w.add_relocation(text, kCallExitOffset, static_cast<uint32>(imp),
                         CoffReloc::Rel32);
        w.add_directive("/DEFAULTLIB:kernel32.lib");

        check(w.write(obj_a.data()), "obj_a written");
    }

    // -----------------------------------------------------------------
    // obj_b: the helper
    // -----------------------------------------------------------------
    {
        CoffWriter w;
        int text = w.add_section(".text", kScnCntCode | kScnMemExecute | kScnMemRead, 16);
        w.append_data(text, kHelperCode, sizeof(kHelperCode));
        w.add_symbol(CoffSymbol::external("compute_value", static_cast<int16>(text), 0, true));
        check(w.write(obj_b.data()), "obj_b written");
    }

    // -----------------------------------------------------------------
    // Link both objects
    // -----------------------------------------------------------------
    String exe;
    exe << work_dir << "/c04_multi.exe";

    String cmd;
    cmd << "\"" << linker << "\" -o \"" << exe.data() << "\" -subsys 3 -entry entry \""
        << obj_a.data() << "\" \"" << obj_b.data() << "\"";

    DWORD link_code = 0xDEADBEEF;
    bool ran = run_and_get_exit(cmd, &link_code);
    check(ran, "the linker ran");
    check(link_code == 0, "the linker completed successfully");
    if (link_code != 0) {
        String d;
        d << "linker exit code " << static_cast<uint64>(link_code);
        bad("the linker completed successfully", d);
    }

    // -----------------------------------------------------------------
    // Run the produced executable
    // -----------------------------------------------------------------
    {
        rawrstd::File probe;
        bool present = probe.open(exe.data(), rawrstd::FileMode::Read);
        if (present) probe.close();
        check(present, "the multi-object executable exists");
    }

    DWORD exit_code = 0xDEADBEEF;
    String run_cmd;
    run_cmd << "\"" << exe.data() << "\"";
    ran = run_and_get_exit(run_cmd, &exit_code);
    check(ran, "Windows loaded and started the multi-object executable");
    check(exit_code == 7, "the cross-object call returned 7 and the program exited with it");
    if (exit_code != 7) {
        String d;
        d << "exit code " << static_cast<uint64>(exit_code);
        bad("the cross-object call returned 7 and the program exited with it", d);
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    rawrstd::write_stdout("------------------------------------------\n", 42);
    String summary;
    summary << "C04 result: " << g_pass << " passed, " << g_fail << " failed\n";
    rawrstd::write_stdout(summary.data(), summary.size());

    return g_fail == 0 ? 0 : 1;
}
