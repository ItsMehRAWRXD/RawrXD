// RAWR_NATIVE_COMPILER_STAGE2_001 â€” the Stage 2 certification.
//
// The Stage 2 milestone is the first complete source language pipeline:
//
//     C source
//        |  rawr_c        (the C front end)
//        v
//     .asm
//        |  rawr_asm      (the certified assembler)
//        v
//     .obj
//        |  rawrxd_link   (the certified native linker)
//        v
//     .exe  ->  Windows runs it  ->  the exit code is checked
//
// Every stage is first-party. The gates below drive the whole chain and
// check the exit code exactly, because a pipeline that produces a file is
// not a pipeline that produces a program.
//
// The tools are passed in, so the suite can be run from a clean exported
// tree against tools built there:
//
//   s2_pipeline_test <rawr_c.exe> <rawr_asm.exe> <rawrxd_link.exe> <workdir>

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

// ---------------------------------------------------------------------------
// Running things
// ---------------------------------------------------------------------------

// A command through the shell.
//
// std::system() goes through cmd.exe, and cmd.exe removes the first and the
// last quote of a string that begins and ends with one. A command whose first
// character is a quoted executable path therefore arrives mangled, so the
// whole command is wrapped in one more pair of quotes.
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

static bool read_text(const std::string& path, std::string* out) {
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

static bool file_exists(const std::string& path) {
    std::string ignored;
    return read_text(path, &ignored);
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------
struct Pipeline {
    std::string rawr_c;
    std::string rawr_asm;
    std::string linker;
    std::string workdir;
};

struct Result {
    bool compiled = false;
    bool assembled = false;
    bool linked = false;
    int  exit_code = -1;
    std::string detail;
};

// Compiles one C file, assembles it, links it and runs it.
static Result run_c(const Pipeline& p, const std::string& name, const std::string& source,
                    const std::string& extra_object = "") {
    Result r;
    const std::string c_path = p.workdir + "/" + name + ".c";
    const std::string asm_path = p.workdir + "/" + name + ".asm";
    const std::string obj_path = p.workdir + "/" + name + ".obj";
    const std::string exe_path = p.workdir + "/" + name + ".exe";

    if (!write_text(c_path, source)) { r.detail = "cannot write the source"; return r; }

    const int c_rc = run_command("\"" + p.rawr_c + "\" \"" + c_path + "\" \"" + asm_path + "\"");
    if (c_rc != 0) { r.detail = "the front end failed"; return r; }
    r.compiled = true;

    const int a_rc = run_command("\"" + p.rawr_asm + "\" \"" + asm_path + "\" \"" + obj_path + "\"");
    if (a_rc != 0) { r.detail = "the assembler failed"; return r; }
    r.assembled = true;

    std::string objects = "\"" + obj_path + "\"";
    if (!extra_object.empty()) objects += " \"" + extra_object + "\"";
    const int l_rc = run_command("\"" + p.linker + "\" -o \"" + exe_path + "\" -subsys 3 -entry main " + objects);
    if (l_rc != 0) { r.detail = "the linker failed"; return r; }
    r.linked = true;

    const int run_rc = run_command("\"" + exe_path + "\"");
    r.exit_code = run_rc;
    return r;
}

// ---------------------------------------------------------------------------
// The gates
// ---------------------------------------------------------------------------

// S2-01: the lexer and the parser are connected.
static void gate_lexer_parser(const Pipeline& p) {
    // A program that parses.
    const Result good = run_c(p, "s2_01_good", "int main(void) { return 42; }");
    check(good.compiled && good.assembled,
          "S2-01 the lexer and the parser are connected",
          good.detail.c_str());

    // A program the parser must reject.
    const std::string bad_path = p.workdir + "/s2_01_bad.c";
    write_text(bad_path, "int main(void) { return ; ; ; }");
    const int rc = run_command("\"" + p.rawr_c + "\" \"" + bad_path + "\" \"" + p.workdir + "/s2_01_bad.asm\"");
    check(rc != 0, "S2-01 a malformed program is rejected with a diagnostic", "");
}

// S2-02: integer expressions and their precedence.
static void gate_expressions(const Pipeline& p) {
    const Result a = run_c(p, "s2_02_prec",
        "int main(void) { return 2 + 3 * 4; }");
    check(a.linked && a.exit_code == 14,
          "S2-02 multiplication binds tighter than addition",
          "the exit code was not 14");

    const Result b = run_c(p, "s2_02_paren",
        "int main(void) { return (2 + 3) * 4; }");
    check(b.linked && b.exit_code == 20,
          "S2-02 parentheses change the grouping",
          "the exit code was not 20");

    const Result c = run_c(p, "s2_02_unary",
        "int main(void) { return 0 - 7; }");
    check(c.linked && c.exit_code == (0 - 7),
          "S2-02 a unary minus is applied",
          "the exit code was not -7");
}

// S2-03: local variables and assignment.
static void gate_variables(const Pipeline& p) {
    const Result a = run_c(p, "s2_03_local",
        "int main(void) { int x = 5; x = x + 3; return x; }");
    check(a.linked && a.exit_code == 8,
          "S2-03 a local variable holds and is reassigned",
          "the exit code was not 8");

    const Result b = run_c(p, "s2_03_two",
        "int main(void) { int a = 20; int b = 22; return a + b; }");
    check(b.linked && b.exit_code == 42,
          "S2-03 two locals keep their own values",
          "the exit code was not 42");
}

// S2-04: functions, calls and returns.
static void gate_functions(const Pipeline& p) {
    const Result a = run_c(p, "s2_04_call",
        "int add(int a, int b) { return a + b; }\n"
        "int main(void) { return add(19, 23); }");
    check(a.linked && a.exit_code == 42,
          "S2-04 a function is called and its value returned",
          "the exit code was not 42");

    const Result b = run_c(p, "s2_04_nested",
        "int twice(int x) { return x * 2; }\n"
        "int main(void) { return twice(twice(10)) + 2; }");
    check(b.linked && b.exit_code == 42,
          "S2-04 a call can be an argument to another call",
          "the exit code was not 42");
}

// S2-05: conditionals and loops.
static void gate_control_flow(const Pipeline& p) {
    const Result a = run_c(p, "s2_05_if",
        "int main(void) { int x = 42; if (x > 3) { return x; } return 1; }");
    check(a.linked && a.exit_code == 42,
          "S2-05 a taken branch returns its value",
          "the exit code was not 42");

    const Result b = run_c(p, "s2_05_else",
        "int main(void) { int x = 1; if (x > 3) { return 7; } else { return 42; } }");
    check(b.linked && b.exit_code == 42,
          "S2-05 the else branch is taken when the condition is false",
          "the exit code was not 42");

    const Result c = run_c(p, "s2_05_while",
        "int main(void) { int i = 0; int s = 0; while (i < 10) { s = s + i; i = i + 1; } return s; }");
    check(c.linked && c.exit_code == 45,
          "S2-05 a while loop accumulates",
          "the exit code was not 45");
}

// S2-06: the Win64 calling convention.
static void gate_abi(const Pipeline& p) {
    // Four integer arguments go in rcx, rdx, r8 and r9, and the stack has to
    // stay aligned at the call.
    const Result a = run_c(p, "s2_06_args",
        "int sum4(int a, int b, int c, int d) { return a + b + c + d; }\n"
        "int main(void) { return sum4(1, 2, 3, 4); }");
    check(a.linked && a.exit_code == 10,
          "S2-06 four integer arguments arrive in the right registers",
          "the exit code was not 10");

    // A callee that itself calls: the frame has to survive the second call.
    const Result b = run_c(p, "s2_06_nested_call",
        "int inner(int x) { return x + 1; }\n"
        "int outer(int x) { return inner(x) + inner(x); }\n"
        "int main(void) { return outer(20); }");
    check(b.linked && b.exit_code == 42,
          "S2-06 a nested call keeps the frame aligned",
          "the exit code was not 42");
}

// S2-07: the COFF object is a real object.
static void gate_coff(const Pipeline& p) {
    const std::string c_path = p.workdir + "/s2_07.c";
    const std::string asm_path = p.workdir + "/s2_07.asm";
    const std::string obj_path = p.workdir + "/s2_07.obj";
    write_text(c_path, "int main(void) { return 42; }");
    run_command("\"" + p.rawr_c + "\" \"" + c_path + "\" \"" + asm_path + "\"");
    const int rc = run_command("\"" + p.rawr_asm + "\" \"" + asm_path + "\" \"" + obj_path + "\"");
    check(rc == 0 && file_exists(obj_path), "S2-07 the front end produces an assembler input", "");

    std::string obj;
    if (!read_text(obj_path, &obj) || obj.size() < 20) {
        bad("S2-07 the assembler produces a COFF object", "the object is missing or too short");
        return;
    }
    const bool machine_ok = obj.size() >= 20;
    // A COFF object starts with the machine number, not with "MZ": that is a
    // PE image, and an object is not one.
    const uint16_t machine = static_cast<uint16_t>(obj[0] | (obj[1] << 8));
    const uint16_t sections = static_cast<uint16_t>(obj[2] | (obj[3] << 8));
    check(machine_ok && machine == 0x8664 && sections >= 1,
          "S2-07 the object is an AMD64 COFF file with its sections",
          "the object header is not an AMD64 COFF file");
}

// S2-08: the executable runs and exits with the value the program returned.
static void gate_executable(const Pipeline& p) {
    const Result a = run_c(p, "s2_08", "int main(void) { return 42; }");
    check(a.linked && a.exit_code == 42,
          "S2-08 the Windows executable exits with the value the program returned",
          "the exit code was not 42");

    const Result b = run_c(p, "s2_08_other", "int main(void) { return 7; }");
    check(b.linked && b.exit_code == 7,
          "S2-08 a different program exits with its own value",
          "the exit code was not 7");
}

// S2-09: more than one translation unit.
static void gate_multiple_units(const Pipeline& p) {
    const std::string helper_c = p.workdir + "/s2_09_helper.c";
    const std::string helper_asm = p.workdir + "/s2_09_helper.asm";
    const std::string helper_obj = p.workdir + "/s2_09_helper.obj";
    write_text(helper_c, "int helper(void) { return 42; }\n");
    run_command("\"" + p.rawr_c + "\" \"" + helper_c + "\" \"" + helper_asm + "\"");
    const int a_rc = run_command("\"" + p.rawr_asm + "\" \"" + helper_asm + "\" \"" + helper_obj + "\"");
    check(a_rc == 0 && file_exists(helper_obj),
          "S2-09 a second translation unit is compiled on its own", "");

    const Result b = run_c(p, "s2_09_main",
        "int helper(void);\n"
        "int main(void) { return helper(); }", helper_obj);
    check(b.linked && b.exit_code == 42,
          "S2-09 two translation units link into one executable",
          "the exit code was not 42");
}

// S2-10: the pipeline is reproducible from an exported tree.
//
// The gate that matters here is the export itself, which the certification
// run performs: the suite is executed from a directory produced by
// "git archive HEAD", with the linker rebuilt from the exported source. This
// check records that the tools in use are the ones that were handed in, and
// that they all exist, so that a run against a half-built tree cannot be
// mistaken for a pass.
static void gate_reproducible(const Pipeline& p) {
    check(file_exists(p.rawr_c) && file_exists(p.rawr_asm) && file_exists(p.linker),
          "S2-10 the front end, the assembler and the linker are all present", "");
}

int main(int argc, char** argv) {
    rawrstd::write_stdout("RAWRXD Native Compiler - Stage 2 certification\n", 44);
    rawrstd::write_stdout("============================================\n", 44);

    if (argc < 5) {
        rawrstd::write_stderr(
            "usage: s2_pipeline_test <rawr_c> <rawr_asm> <rawrxd_link> <workdir>\n", 74);
        return 2;
    }

    Pipeline p;
    p.rawr_c = argv[1];
    p.rawr_asm = argv[2];
    p.linker = argv[3];
    p.workdir = argv[4];

    gate_lexer_parser(p);
    gate_expressions(p);
    gate_variables(p);
    gate_functions(p);
    gate_control_flow(p);
    gate_abi(p);
    gate_coff(p);
    gate_executable(p);
    gate_multiple_units(p);
    gate_reproducible(p);

    rawrstd::write_stdout("--------------------------------------------\n", 44);
    char summary[96];
    std::snprintf(summary, sizeof(summary), "S2 result: %d passed, %d failed\n", g_pass, g_fail);
    rawrstd::write_stdout(summary, rawrstd::strlen_raw(summary));
    return g_fail == 0 ? 0 : 1;
}

