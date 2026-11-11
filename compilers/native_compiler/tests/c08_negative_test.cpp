// C08 - Negative tests, malformed inputs and deterministic linking.
//
// A production linker has to fail loudly rather than emit a broken image,
// and it has to produce the same bytes every time.
//
//   1. An undefined external with no known DLL must be a link error.
//   2. A truncated object file must be rejected, not crash the linker.
//   3. A file that is not a COFF object at all must be rejected.
//   4. An empty file must be rejected.
//   5. Two links of the same input must produce identical bytes.
//   6. A link that fails must not leave an output file behind.

#include "object/CoffWriter.h"

#include "rawrstd/sha256.h"
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

// Runs a command line and returns its exit code, or 0xFFFFFFFF on failure.
static DWORD run_and_get_exit(const String& cmd) {
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
        return 0xFFFFFFFFu;
    }
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 0xFFFFFFFFu;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code;
}

static void write_bytes(const String& path, const void* data, size_type size) {
    rawrstd::File f;
    if (!f.open(path.data(), rawrstd::FileMode::Write)) return;
    f.write(data, size);
    f.close();
}

int main(int argc, char** argv) {
    const char* work_dir = (argc > 1) ? argv[1] : ".";
    const char* linker = (argc > 2) ? argv[2] : "";

    rawrstd::write_stdout("C08 Negative and determinism certification\n", 42);
    rawrstd::write_stdout("==========================================\n", 42);

    if (!linker[0]) {
        bad("linker path supplied", String("no linker path given"));
        return 1;
    }

    // -----------------------------------------------------------------
    // A valid object, used for the determinism check
    // -----------------------------------------------------------------
    String good_obj;
    good_obj << work_dir << "/c08_good.obj";
    String exe_a;
    exe_a << work_dir << "/c08_det_a.exe";
    String exe_b;
    exe_b << work_dir << "/c08_det_b.exe";

    {
        static const uint8 code[] = {
            0x48, 0x83, 0xEC, 0x28,
            0xB9, 0x2A, 0x00, 0x00, 0x00,
            0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,
            0x48, 0x83, 0xC4, 0x28,
            0xC3
        };
        CoffWriter w;
        int text = w.add_section(".text", kScnCntCode | kScnMemExecute | kScnMemRead, 16);
        w.append_data(text, code, sizeof(code));
        int imp = w.add_symbol(CoffSymbol::external("__imp_ExitProcess"));
        w.add_symbol(CoffSymbol::external("entry", static_cast<int16>(text), 0, true));
        w.add_relocation(text, 11, static_cast<uint32>(imp), CoffReloc::Rel32);
        w.add_directive("/DEFAULTLIB:kernel32.lib");
        check(w.write(good_obj.data()), "the determinism fixture was written");
    }

    // -----------------------------------------------------------------
    // 1. An undefined external with no known DLL
    // -----------------------------------------------------------------
    {
        String undef_obj;
        undef_obj << work_dir << "/c08_undef.obj";
        String out;
        out << work_dir << "/c08_undef.exe";

        static const uint8 code[] = {
            0xB9, 0x07, 0x00, 0x00, 0x00,
            0xE8, 0x00, 0x00, 0x00, 0x00,
            0xC3
        };
        CoffWriter w;
        int text = w.add_section(".text", kScnCntCode | kScnMemExecute | kScnMemRead, 16);
        w.append_data(text, code, sizeof(code));
        int sym = w.add_symbol(CoffSymbol::external("ThisSymbolDoesNotExistAnywhere"));
        w.add_symbol(CoffSymbol::external("entry", static_cast<int16>(text), 0, true));
        w.add_relocation(text, 6, static_cast<uint32>(sym), CoffReloc::Rel32);
        w.write(undef_obj.data());

        // Remove any stale output.
        {
            rawrstd::File probe;
            bool present = probe.open(out.data(), rawrstd::FileMode::Read);
            if (present) { probe.close(); DeleteFileA(out.data()); }
        }

        String cmd;
        cmd << "\"" << linker << "\" -o \"" << out.data() << "\" -subsys 3 -entry entry \""
            << undef_obj.data() << "\"";
        DWORD link_result = run_and_get_exit(cmd);
        check(link_result != 0, "the linker failed on an unresolved symbol");

        rawrstd::File probe;
        bool produced = probe.open(out.data(), rawrstd::FileMode::Read);
        if (produced) probe.close();
        check(!produced, "no output file was left behind after the failure");
    }

    // -----------------------------------------------------------------
    // 2. A truncated object file
    // -----------------------------------------------------------------
    {
        String trunc;
        trunc << work_dir << "/c08_trunc.obj";
        String out;
        out << work_dir << "/c08_trunc.exe";

        // The first 40 bytes of a real object: a valid header claiming two
        // sections, but the file stops there.
        uint8 stub[40];
        rawrstd::memset_raw(stub, 0, sizeof(stub));
        stub[0] = 0x64; stub[1] = 0x86;   // machine AMD64
        stub[2] = 0x02; stub[3] = 0x00;   // two sections
        write_bytes(trunc, stub, sizeof(stub));

        String cmd;
        cmd << "\"" << linker << "\" -o \"" << out.data() << "\" -subsys 3 -entry entry \""
            << trunc.data() << "\"";
        DWORD code = run_and_get_exit(cmd);
        check(code != 0, "the linker rejected a truncated object without crashing");
    }

    // -----------------------------------------------------------------
    // 3. A file that is not a COFF object
    // -----------------------------------------------------------------
    {
        String junk;
        junk << work_dir << "/c08_junk.obj";
        String out;
        out << work_dir << "/c08_junk.exe";

        const char* text = "this is definitely not a COFF object file, not even close";
        write_bytes(junk, text, rawrstd::strlen_raw(text));

        String cmd;
        cmd << "\"" << linker << "\" -o \"" << out.data() << "\" -subsys 3 -entry entry \""
            << junk.data() << "\"";
        DWORD code = run_and_get_exit(cmd);
        check(code != 0, "the linker rejected a non-object file without crashing");
    }

    // -----------------------------------------------------------------
    // 4. An empty file
    // -----------------------------------------------------------------
    {
        String empty;
        empty << work_dir << "/c08_empty.obj";
        String out;
        out << work_dir << "/c08_empty.exe";

        write_bytes(empty, "", 0);

        String cmd;
        cmd << "\"" << linker << "\" -o \"" << out.data() << "\" -subsys 3 -entry entry \""
            << empty.data() << "\"";
        DWORD code = run_and_get_exit(cmd);
        check(code != 0, "the linker rejected an empty file without crashing");
    }

    // -----------------------------------------------------------------
    // 5. Determinism
    // -----------------------------------------------------------------
    {
        String cmd_a;
        cmd_a << "\"" << linker << "\" -o \"" << exe_a.data()
              << "\" -subsys 3 -entry entry -deterministic \"" << good_obj.data() << "\"";
        DWORD code_a = run_and_get_exit(cmd_a);
        check(code_a == 0, "the first deterministic link succeeded");

        String cmd_b;
        cmd_b << "\"" << linker << "\" -o \"" << exe_b.data()
              << "\" -subsys 3 -entry entry -deterministic \"" << good_obj.data() << "\"";
        DWORD code_b = run_and_get_exit(cmd_b);
        check(code_b == 0, "the second deterministic link succeeded");

        if (code_a == 0 && code_b == 0) {
            String hash_a = rawrstd::sha256_file(exe_a.data());
            String hash_b = rawrstd::sha256_file(exe_b.data());
            check(!hash_a.empty() && !hash_b.empty(), "both outputs could be hashed");
            check(hash_a == hash_b, "two links of the same input produced identical bytes");
            if (hash_a != hash_b) {
                String d;
                d << hash_a << " vs " << hash_b;
                bad("two links of the same input produced identical bytes", d);
            }
        }
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    rawrstd::write_stdout("------------------------------------------\n", 42);
    String summary;
    summary << "C08 result: " << g_pass << " passed, " << g_fail << " failed\n";
    rawrstd::write_stdout(summary.data(), summary.size());

    return g_fail == 0 ? 0 : 1;
}
