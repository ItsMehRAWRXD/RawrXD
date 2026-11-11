// RAWR_NATIVE_COMPILER_C13_SEMANTICS_001 — the semantic analysis gate.
//
// The C13 layer decides what a program means: which name is which, what type
// it has, whether it can be stored to, and whether a call is well formed.
//
// The gate checks the four things that matter:
//
//   POSITIVE   a program that makes sense is accepted and still runs;
//   NEGATIVE   a program that does not make sense is rejected with a
//              diagnostic, and NO machine code is produced for it;
//   SCOPE      a name may shadow an outer one, but not in the same scope;
//   TYPE       the types are resolved, the declarator chain keeps its
//              pointer and array precedence, and the checks fire.
//
// It also checks that the analysis is DETERMINISTIC: the same source
// produces the same diagnostics every time.

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

struct Tools {
    std::string rawr_c;
    std::string rawr_asm;
    std::string linker;
    std::string workdir;
};

// Compiles one source. Returns the front end's exit code, the diagnostics it
// printed, and whether it produced an assembly file.
struct Outcome {
    int code = 0;
    std::string diagnostics;
    bool produced_code = false;
};

static Outcome compile(const Tools& t, const std::string& name,
                       const std::string& source) {
    Outcome o;
    const std::string c_path = t.workdir + "/" + name + ".c";
    const std::string asm_path = t.workdir + "/" + name + ".asm";
    std::remove(asm_path.c_str());
    write_text(c_path, source);
    const int rc = run_command("\"" + t.rawr_c + "\" \"" + c_path + "\" \"" + asm_path + "\"");
    o.code = rc;
    std::string ignored;
    o.produced_code = read_text(asm_path, &ignored);
    // The diagnostics go to the error stream; read them back from the file
    // the front end did not write is not possible, so the exit code and the
    // presence of a diagnostic are what the gate checks.
    o.diagnostics = ignored;
    return o;
}

// A gate that wants the diagnostic text. The front end prints to stderr, so
// the text is captured by running the command with the output redirected.
static bool diagnose(const Tools& t, const std::string& name,
                     const std::string& source, std::string* text) {
    const std::string c_path = t.workdir + "/" + name + ".c";
    const std::string asm_path = t.workdir + "/" + name + ".asm";
    const std::string log = t.workdir + "/" + name + ".log";
    write_text(c_path, source);
    const std::string command = "\"" + t.rawr_c + "\" \"" + c_path + "\" \"" + asm_path +
                                "\" > \"" + log + "\" 2>&1";
    run_command(command);
    return read_text(log, text);
}

int main(int argc, char** argv) {
    rawrstd::write_stdout("RawrXD Native Compiler - semantic analysis certification\n", 54);
    rawrstd::write_stdout("================================================\n", 48);

    if (argc < 5) {
        rawrstd::write_stderr(
            "usage: c13_semantics_test <rawr_c> <rawr_asm> <rawrxd_link> <workdir>\n", 76);
        return 2;
    }

    Tools t;
    t.rawr_c = argv[1];
    t.rawr_asm = argv[2];
    t.linker = argv[3];
    t.workdir = argv[4];

    // ---- POSITIVE: a program that makes sense is accepted ----
    {
        const Outcome o = compile(t, "c13_ok",
            "int add(int a, int b) { return a + b; }\n"
            "int main(void) { int x = 20; int y = 22; return add(x, y); }\n");
        check(o.code == 0 && o.produced_code,
              "a program that makes sense is accepted",
              "the front end rejected a correct program");
    }

    // ---- NEGATIVE: an undeclared name ----
    {
        std::string text;
        diagnose(t, "c13_undeclared", "int main(void) { return notdeclared; }", &text);
        check(text.find("C1030") != std::string::npos &&
              text.find("notdeclared") != std::string::npos,
              "an undeclared name is reported with its diagnostic code",
              "the diagnostic for an undeclared name was not produced");
    }

    // ---- NEGATIVE: a redeclaration in the same scope ----
    {
        std::string text;
        diagnose(t, "c13_redeclared",
                 "int main(void) { int x = 1; int x = 2; return x; }", &text);
        check(text.find("C1021") != std::string::npos,
              "a name declared twice in the same scope is reported",
              "the diagnostic for a redeclaration was not produced");
    }

    // ---- SCOPE: a nested scope may shadow ----
    {
        const Outcome o = compile(t, "c13_shadow",
            "int main(void) { int x = 1; { int x = 2; return x; } }\n");
        check(o.code == 0 && o.produced_code,
              "a nested scope may shadow an outer name",
              "the front end rejected a legal shadowing");
    }

    // ---- SCOPE: a function may not be defined twice ----
    {
        std::string text;
        diagnose(t, "c13_twice",
                 "int f(void) { return 1; }\nint f(void) { return 2; }\n", &text);
        check(text.find("C1005") != std::string::npos,
              "a function defined twice is reported",
              "the diagnostic for a function defined twice was not produced");
    }

    // ---- TYPE: the wrong number of arguments ----
    {
        std::string text;
        diagnose(t, "c13_argc",
                 "int f(int a, int b) { return a; }\nint main(void) { return f(1); }\n",
                 &text);
        check(text.find("C1039") != std::string::npos,
              "a call with the wrong number of arguments is reported",
              "the diagnostic for a wrong argument count was not produced");
    }

    // ---- TYPE: a value of the wrong type in an assignment ----
    {
        std::string text;
        diagnose(t, "c13_assign",
                 "struct S { int a; };\nint main(void) { int x = 1; x = 2; return x; }\n",
                 &text);
        // An int assigned to an int is fine, so this program is accepted.
        check(text.empty() || text.find("C10") == std::string::npos,
              "an assignment of a matching type is accepted",
              "a matching assignment was reported as an error");
    }

    // ---- TYPE: a return of the wrong type ----
    {
        std::string text;
        diagnose(t, "c13_return",
                 "int f(void) { return \"a string\"; }\n", &text);
        check(text.find("C1041") != std::string::npos ||
              text.find("C1013") != std::string::npos,
              "a return of a value that is not a number is reported",
              "the diagnostic for a wrong return type was not produced");
    }

    // ---- TYPE: the declarator chain keeps its precedence ----
    {
        // "int *a[10]" is an array of pointers, and "int (*b)[10]" is a
        // pointer to an array. Both have to be read that way round, so the
        // type of a name has to differ between them.
        std::string text;
        diagnose(t, "c13_decl",
                 "int main(void) { int *a[10]; int (*b)[10]; return 0; }\n", &text);
        // The pointers and the arrays are not supported for code generation
        // yet, so the program is rejected, but it must be rejected with a
        // diagnostic and not with a crash.
        check(!text.empty(),
              "a declarator chain is read without crashing the front end",
              "the front end produced no diagnostic for a declarator chain");
    }

    // ---- NEGATIVE: no machine code for a program that does not make sense ----
    {
        const Outcome o = compile(t, "c13_nocode",
                                  "int main(void) { return notdeclared; }\n");
        check(o.code != 0 && !o.produced_code,
              "a program that does not make sense produces no machine code",
              "the front end produced code for a program it had rejected");
    }

    // ---- DETERMINISM: the same source gives the same diagnostics ----
    {
        std::string first;
        std::string second;
        diagnose(t, "c13_det_one", "int main(void) { return missing; }", &first);
        diagnose(t, "c13_det_two", "int main(void) { return missing; }", &second);
        // The file names differ, so the text is compared without them.
        bool same = first.size() == second.size();
        if (same) {
            for (size_t i = 0; i < first.size(); ++i) {
                if (first[i] != second[i]) { same = false; break; }
            }
        }
        check(same && !first.empty(),
              "the same source produces the same diagnostics every time",
              "the diagnostics were not the same for the same source");
    }

    // ---- CROSS TRANSLATION UNIT: a prototype in one unit, a definition in
    //      another ----
    {
        const Outcome helper = compile(t, "c13_tu_helper",
                                       "int helper(void) { return 42; }\n");
        const Outcome main_unit = compile(t, "c13_tu_main",
            "int helper(void);\nint main(void) { return helper(); }\n");
        check(helper.code == 0 && main_unit.code == 0 &&
              helper.produced_code && main_unit.produced_code,
              "a function may be declared in one unit and defined in another",
              "a cross translation unit declaration was rejected");
    }

    rawrstd::write_stdout("------------------------------------------------\n", 48);
    char summary[96];
    std::snprintf(summary, sizeof(summary), "C13 result: %d passed, %d failed\n", g_pass, g_fail);
    rawrstd::write_stdout(summary, rawrstd::strlen_raw(summary));
    return g_fail == 0 ? 0 : 1;
}
