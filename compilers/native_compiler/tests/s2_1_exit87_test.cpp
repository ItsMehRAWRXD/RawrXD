// RAWR_NATIVE_COMPILER_EXIT87_001 — the exit 87 certification.
//
// Stage 2 proved the pipeline end to end with exit 42. This gate proves it
// is not a fixture: the same pipeline is asked for a different value, by
// several different routes, and Windows has to report that value.
//
//   C source
//      |  rawr_c
//      v
//    .asm
//      |  rawr_asm
//      v
//    .obj
//      |  rawrxd_link
//      v
//    .exe  ->  Windows runs it  ->  the exit code is checked
//
// The programs are:
//
//   return 87;                  a constant
//   return 80 + 7;              arithmetic
//   return 100 - 13;            arithmetic
//   int x = 29; return x * 3;   a local variable
//   int x = 174; return x / 2;  a local variable
//
// The constant case is also checked byte for byte, against the documented
// encoding:
//
//   48 83 EC 28          sub rsp, 40
//   B9 57 00 00 00       mov ecx, 87
//   E8 00 00 00 00       call ExitProcess, a REL32 the linker resolves
//   48 83 C4 28          add rsp, 40
//   C3                   ret
//
// The tools are passed in, so the suite runs against a tree built from an
// exported commit:
//
//   s2_1_exit87_test <rawr_c> <rawr_asm> <rawrxd_link> <workdir>

#include "rawrstd/string.h"
#include "rawrstd/sys.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using rawrstd::String;

static int g_pass = 0;
static int g_fail = 0;

static void ok(const char* what) {
    rawrstd::write_stdout("  [PASS] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("\n", 1);
    ++g_pass;
}

static void bad(const char* what, const char* detail) {
    rawrstd::write_stdout("  [FAIL] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("  -- ", 4);
    rawrstd::write_stderr(detail, rawrstd::strlen_raw(detail));
    rawrstd::write_stderr("\n", 1);
    ++g_fail;
}

static void check(bool cond, const char* what, const char* detail = "") {
    if (cond) ok(what);
    else bad(what, detail);
}

// A command through the shell.
//
// cmd.exe removes the first and the last quote of a string that begins and
// ends with one, so a command whose first character is a quoted executable
// path arrives mangled. The whole command is wrapped in one more pair.
static int run_command(const std::string& command) {
    const std::string wrapped = "\"" + command + "\"";
    return std::system(wrapped.c_str());
}

static bool write_text(const std::string& path, const std::string& text) {
    rawrstd::File f;
    if (!f.open(path.c_str(), rawrstd::FileMode::Write)) return false;
    f.write(text.data(), text.size());
    f.close();
    return true;
}

static bool read_bytes(const std::string& path, std::string* out) {
    rawrstd::File f;
    if (!f.open(path.c_str(), rawrstd::FileMode::Read)) return false;
    out->clear();
    char buffer[4096];
    for (;;) {
        const long long got = f.read(buffer, sizeof(buffer));
        if (got <= 0) break;
        out->append(buffer, static_cast<size_t>(got));
    }
    f.close();
    return true;
}

struct Tools {
    std::string rawr_c;
    std::string rawr_asm;
    std::string linker;
    std::string workdir;
};

struct Outcome {
    bool compiled = false;
    bool assembled = false;
    bool linked = false;
    int  exit_code = -1;
    std::string object_text;
};

// Compiles one C file, assembles it, links it and runs it.
static Outcome run_c(const Tools& t, const std::string& name, const std::string& source) {
    Outcome o;
    const std::string c_path = t.workdir + "/" + name + ".c";
    const std::string asm_path = t.workdir + "/" + name + ".asm";
    const std::string obj_path = t.workdir + "/" + name + ".obj";
    const std::string exe_path = t.workdir + "/" + name + ".exe";

    if (!write_text(c_path, source)) return o;
    if (run_command("\"" + t.rawr_c + "\" \"" + c_path + "\" \"" + asm_path + "\"") != 0) return o;
    o.compiled = true;
    if (run_command("\"" + t.rawr_asm + "\" \"" + asm_path + "\" \"" + obj_path + "\"") != 0) return o;
    o.assembled = true;
    if (run_command("\"" + t.linker + "\" -o \"" + exe_path + "\" -subsys 3 -entry main \"" +
                     obj_path + "\"") != 0) return o;
    o.linked = true;
    read_bytes(obj_path, &o.object_text);
    o.exit_code = run_command("\"" + exe_path + "\"");
    return o;
}

static std::string describe(int code) {
    char buffer[48];
    std::snprintf(buffer, sizeof(buffer), "the exit code was %d", code);
    return buffer;
}

int main(int argc, char** argv) {
    rawrstd::write_stdout("RawrXD Native Compiler - exit 87 certification\n", 47);
    rawrstd::write_stdout("===========================================\n", 43);

    if (argc < 5) {
        rawrstd::write_stderr(
            "usage: s2_1_exit87_test <rawr_c> <rawr_asm> <rawrxd_link> <workdir>\n", 76);
        return 2;
    }

    Tools t;
    t.rawr_c = argv[1];
    t.rawr_asm = argv[2];
    t.linker = argv[3];
    t.workdir = argv[4];

    // ---- the five ways of returning 87 ----
    struct Program {
        const char* name;
        const char* source;
    };
    static const Program kPrograms[] = {
        { "exit87_constant", "int main(void) { return 87; }" },
        { "exit87_add",      "int main(void) { return 80 + 7; }" },
        { "exit87_sub",      "int main(void) { return 100 - 13; }" },
        { "exit87_local_mul", "int main(void) { int x = 29; return x * 3; }" },
        { "exit87_local_div", "int main(void) { int x = 174; return x / 2; }" },
    };

    for (const Program& program : kPrograms) {
        const Outcome o = run_c(t, program.name, program.source);
        char what[128];
        std::snprintf(what, sizeof(what), "%s exits with 87", program.name);
        check(o.compiled && o.assembled && o.linked && o.exit_code == 87,
              what,
              describe(o.exit_code).c_str());
    }

    // ---- the constant case, byte for byte ----
    //
    // The documented encoding of the canonical program. A label emits no
    // bytes, so the epilogue label in the generated assembly does not appear
    // here.
    {
        static const unsigned char kExpected[] = {
            0x48, 0x83, 0xEC, 0x28,             // sub  rsp, 40
            0xB9, 0x57, 0x00, 0x00, 0x00,       // mov  ecx, 87
            0xE8, 0x00, 0x00, 0x00, 0x00,       // call ExitProcess, a REL32
            0x48, 0x83, 0xC4, 0x28,             // add  rsp, 40
            0xC3,                               // ret
        };
        const Outcome o = run_c(t, "exit87_bytes", "int main(void) { return 87; }");
        // The .text of the object starts after the COFF header and the
        // section header.
        const size_t header = 20 + 40;
        bool matches = o.assembled && o.object_text.size() > header &&
                       o.object_text.size() - header >= sizeof(kExpected);
        if (matches) {
            for (size_t i = 0; i < sizeof(kExpected); ++i) {
                if (static_cast<unsigned char>(o.object_text[header + i]) != kExpected[i]) {
                    matches = false;
                }
            }
        }
        check(matches,
              "the constant program is encoded exactly as documented",
              "the .text section does not hold the documented bytes");
    }

    // ---- a program the front end has to reject ----
    {
        const Outcome o = run_c(t, "exit87_bad", "int main(void) { return ; }");
        check(!o.compiled,
              "a program that cannot be parsed is rejected and produces no object",
              "the front end accepted a program it should have rejected");
    }

    rawrstd::write_stdout("------------------------------------------\n", 42);
    char summary[96];
    std::snprintf(summary, sizeof(summary), "S2.1 result: %d passed, %d failed\n", g_pass, g_fail);
    rawrstd::write_stdout(summary, rawrstd::strlen_raw(summary));
    return g_fail == 0 ? 0 : 1;
}
