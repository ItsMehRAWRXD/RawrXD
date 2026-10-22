// C10 - Preprocessor.
//
// The preprocessor is the first stage that turns text into a token stream
// the parser can consume, so it is where the source language really starts.
// The gate covers the parts a C++ compiler cannot do without:
//
//   1. Object-like and function-like macros, including nesting.
//   2. A macro that refers to itself, which has to stop rather than loop.
//   3. The # operator, which turns an argument into a string literal.
//   4. The ## operator, which pastes two tokens into one.
//   5. The conditional directives, and the defined operator.
//   6. Arithmetic in a conditional expression.
//   7. #include, #undef and the variadic macros.
//   8. The predefined macros.
//   9. The error cases: an unclosed conditional, an unknown directive and a
//      macro invoked with the wrong number of arguments.

#include "common/Diagnostics.h"
#include "common/SourceManager.h"
#include "frontend/Preprocessor.h"
#include "rawrstd/sys.h"

#include <cstdio>

using namespace rawr;
using rawrstd::String;
using rawrstd::Vector;
using rawrstd::size_type;
using rawrstd::int64;

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

static void check(bool cond, const char* what, const String& detail) {
    if (cond) ok(what);
    else bad(what, detail);
}

// Renders a token stream as a space separated list of the token texts.
static String render(const Vector<Token>& tokens) {
    String out;
    for (size_type i = 0; i < tokens.size(); ++i) {
        if (i > 0) out << " ";
        if (tokens[i].kind == TokenKind::StringLiteral) {
            out << "\"" << tokens[i].text << "\"";
        } else {
            out << tokens[i].text;
        }
    }
    return out;
}

// The result of preprocessing one source.
struct Run {
    String text;        // the rendered token stream
    uint32 errors = 0;
    bool ok = false;
};

// Preprocesses an in-memory source with a fresh set of macro definitions.
static Run run_source(const char* source) {
    Run result;
    SourceManager sources;
    DiagnosticEngine diags(&sources);
    Preprocessor preprocessor(&sources, &diags);

    const uint32 id = sources.add_buffer("<test>", source, rawrstd::strlen_raw(source));
    Vector<Token> tokens;
    result.ok = preprocessor.run(id, &tokens);
    result.text = render(tokens);
    result.errors = diags.error_count();
    return result;
}

// Compares a preprocessing result against the expected token stream.
static void expect(const char* what, const char* source, const char* expected) {
    const Run run = run_source(source);
    if (!run.ok || run.errors != 0) {
        bad(what, String("the preprocessor reported an error: ") + run.text);
        return;
    }
    if (run.text != expected) {
        bad(what, String("got '") + run.text + "', wanted '" + expected + "'");
        return;
    }
    ok(what);
}

// Formats a number. The compiler does not use the C runtime.
static String to_text(int value) {
    String out;
    out.append_i64(value);
    return out;
}

// Writes a file, so the include test has something to include.
static bool write_file(const String& path, const char* text) {
    rawrstd::File file;
    if (!file.open(path.data(), rawrstd::FileMode::Write)) return false;
    file.write(text, rawrstd::strlen_raw(text));
    file.close();
    return true;
}

int main(int argc, char** argv) {
    // ---- 1. Object-like and function-like macros ----
    expect("an object-like macro is replaced",
           "#define N 42\nN\n", "42");

    expect("a function-like macro is replaced with its arguments",
           "#define ADD(a, b) ((a) + (b))\nADD(1, 2)\n", "( ( 1 ) + ( 2 ) )");

    expect("a macro with no arguments is replaced",
           "#define EMPTY\nEMPTY\n", "");

    expect("a macro that is not invoked is left alone",
           "#define F(x) x\nF\n", "F");

    expect("a function-like macro whose name is not followed by a bracket is left alone",
           "#define F(x) x\nF + 1\n", "F + 1");

    // ---- 2. Nesting and the recursion guard ----
    expect("a macro that expands to another macro is expanded again",
           "#define A B\n#define B 7\nA\n", "7");

    expect("a macro that refers to itself stops",
           "#define X X\nX\n", "X");

    expect("two macros that refer to each other stop",
           "#define P Q\n#define Q P\nP\n", "P");

    expect("a macro used inside its own argument is expanded once",
           "#define F(x) (x)\nF(F(1))\n", "( ( 1 ) )");

    // ---- 3. The # operator ----
    expect("the # operator turns an argument into a string literal",
           "#define S(x) #x\nS(hello)\n", "\"hello\"");

    expect("the # operator keeps the spaces of an argument",
           "#define S(x) #x\nS(a  b)\n", "\"a b\"");

    expect("the # operator does not expand the argument",
           "#define N 5\n#define S(x) #x\nS(N)\n", "\"N\"");

    // ---- 4. The ## operator ----
    expect("the ## operator pastes two tokens together",
           "#define CAT(a, b) a ## b\nCAT(foo, bar)\n", "foobar");

    expect("the ## operator pastes a macro and a token",
           "#define N 5\n#define CAT(a, b) a ## b\nCAT(N, x)\n", "Nx");

    expect("the ## operator does not expand the argument it pastes",
           "#define N 5\n#define CAT(a, b) a ## b\nCAT(x, N)\n", "xN");

    // ---- 5. The conditional directives ----
    expect("a true #if keeps its branch",
           "#if 1\nkept\n#endif\n", "kept");

    expect("a false #if drops its branch",
           "#if 0\ndropped\n#endif\n", "");

    expect("the #else branch is taken when the #if is false",
           "#if 0\ndropped\n#else\nkept\n#endif\n", "kept");

    expect("the #elif branch is taken when the #if is false",
           "#if 0\na\n#elif 1\nkept\n#else\nb\n#endif\n", "kept");

    expect("an #ifdef is true when the macro is defined",
           "#define X\n#ifdef X\nkept\n#endif\n", "kept");

    expect("an #ifdef is false when the macro is not defined",
           "#ifdef X\ndropped\n#endif\n", "");

    expect("an #ifndef is true when the macro is not defined",
           "#ifndef X\nkept\n#endif\n", "kept");

    expect("the defined operator reports a defined macro",
           "#define X\n#if defined(X)\nkept\n#endif\n", "kept");

    expect("the defined operator reports an undefined macro",
           "#if defined(X)\ndropped\n#endif\n", "");

    expect("a nested conditional is tracked",
           "#if 1\n#if 0\na\n#else\nkept\n#endif\n#endif\n", "kept");

    expect("a skipped region does not expand its macros",
           "#if 0\n#define N 1\nN\n#endif\n", "");

    // ---- 6. Arithmetic in a conditional expression ----
    expect("a conditional expression is evaluated",
           "#if (1 + 2) * 3 == 9\nkept\n#endif\n", "kept");

    expect("a comparison of two values is evaluated",
           "#if 7 > 3\nkept\n#endif\n", "kept");

    expect("a logical operator is evaluated",
           "#if defined(X) || 1\nkept\n#endif\n", "kept");

    expect("a shift is evaluated",
           "#if (1 << 4) == 16\nkept\n#endif\n", "kept");

    expect("a ternary operator is evaluated",
           "#if 1 ? 1 : 0\nkept\n#endif\n", "kept");

    // ---- 7. #undef, the variadic macros and #include ----
    expect("#undef removes a macro",
           "#define N 42\n#undef N\nN\n", "N");

    expect("a variadic macro takes the arguments that are left",
           "#define FIRST(a, ...) a\nFIRST(1, 2, 3)\n", "1");

    {
        // The include needs a file on disk, so it gets a directory of its own.
        const char* dir = (argc > 1) ? argv[1] : ".";
        const String header = String(dir) + "\\c10_header.h";
        write_file(header, "from_header\n");

        SourceManager sources;
        DiagnosticEngine diags(&sources);
        Preprocessor preprocessor(&sources, &diags);
        preprocessor.add_include_dir(dir);

        static const char kSource[] = "#include \"c10_header.h\"\nafter\n";
        const uint32 id = sources.add_buffer("<test>", kSource, rawrstd::strlen_raw(kSource));
        Vector<Token> tokens;
        const bool succeeded = preprocessor.run(id, &tokens);
        check(succeeded && diags.error_count() == 0 && render(tokens) == "from_header after",
              "an included file contributes its tokens",
              String("got '") + render(tokens) + "'");
    }

    // ---- 8. The predefined macros ----
    expect("__cplusplus is the C++20 value",
           "#if __cplusplus >= 202002L\nkept\n#endif\n", "kept");

    {
        const Run run = run_source("__LINE__\n");
        check(run.ok && run.text == "1", "__LINE__ is the line of the macro",
              String("got '") + run.text + "'");
    }

    {
        const Run run = run_source("__FILE__\n");
        check(run.ok && run.text.find("test") != String::npos,
              "__FILE__ is the name of the file",
              String("got '") + run.text + "'");
    }

    {
        const Run run = run_source("#define N 1\n#undef N\n#ifdef N\nbad\n#else\ngood\n#endif\n");
        check(run.ok && run.text == "good", "a macro removed by #undef is not defined any more",
              String("got '") + run.text + "'");
    }

    // ---- 9. The error cases ----
    {
        const Run run = run_source("#if 1\nkept\n");
        check(!run.ok && run.errors > 0, "an unclosed conditional is an error",
              String("errors=") + to_text(static_cast<int>(run.errors)));
    }
    {
        const Run run = run_source("#if 1\nkept\n#endif\n#else\n#endif\n");
        check(!run.ok && run.errors > 0, "an #else without a matching #if is an error",
              String("errors=") + to_text(static_cast<int>(run.errors)));
    }
    {
        const Run run = run_source("#nonsense\n");
        check(!run.ok && run.errors > 0, "an unknown directive is an error",
              String("errors=") + to_text(static_cast<int>(run.errors)));
    }
    {
        const Run run = run_source("#define F(a) a\nF(1, 2)\n");
        check(!run.ok && run.errors > 0, "a macro with the wrong number of arguments is an error",
              String("errors=") + to_text(static_cast<int>(run.errors)));
    }
    {
        const Run run = run_source("#error something is wrong\n");
        check(!run.ok && run.errors > 0, "an #error directive is an error",
              String("errors=") + to_text(static_cast<int>(run.errors)));
    }
    {
        const Run run = run_source("#include \"no_such_file_here.h\"\n");
        check(!run.ok && run.errors > 0, "a missing include file is an error",
              String("errors=") + to_text(static_cast<int>(run.errors)));
    }

    rawrstd::write_stdout("--------------------------------------------", 44);
    rawrstd::write_stdout("C10 result: ", 13);
    char buffer[64];
    const int n = std::snprintf(buffer, sizeof(buffer), "%d passed, %d failed\n", g_pass, g_fail);
    rawrstd::write_stdout(buffer, static_cast<size_type>(n));
    return g_fail == 0 ? 0 : 1;
}
