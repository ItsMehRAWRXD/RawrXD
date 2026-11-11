// C11 - The C parser.
//
// The parser is the stage between the token stream and the tree, so the
// gate covers the shape of the tree and the diagnostics that come out of
// it.
//
// The ten groups follow the acceptance targets:
//
//   01  Translation units and functions
//   02  Local and global declarations
//   03  Expression precedence and associativity
//   04  Assignments and compound assignments
//   05  Blocks and lexical scopes
//   06  if and else
//   07  while, do and for
//   08  break, continue and return
//   09  Calls, pointers, arrays and structs
//   10  A deterministic tree and useful syntax diagnostics
//
// Every test runs the certified preprocessor first and parses what it
// produces, so the parser is exercised on the same input a compiler would
// really see.

#include "common/Diagnostics.h"
#include "common/SourceManager.h"
#include "frontend/AST.h"
#include "frontend/Parser.h"
#include "frontend/Preprocessor.h"
#include "rawrstd/string.h"
#include "rawrstd/vector.h"

#include <cstdio>

using namespace rawr;
using rawrstd::String;
using rawrstd::Vector;
using rawrstd::size_type;
using rawrstd::uint32;

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

// Formats a number. The compiler does not use the C runtime.
static String to_text(int value) {
    String out;
    out.append_i64(value);
    return out;
}

// The result of running the front end over one source.
struct Run {
    String tree;            // the rendered tree
    uint32 errors = 0;
    uint32 error_line = 0;
    uint32 error_column = 0;
    String error_code;
    String error_message;
};

// Runs the preprocessor and the parser over a source.
static Run run(const char* source) {
    Run result;
    SourceManager sources;
    DiagnosticEngine diags(&sources);
    Preprocessor preprocessor(&sources, &diags);
    AST ast;
    Parser parser(&sources, &diags, &ast);

    const uint32 id = sources.add_buffer("<test>", source, rawrstd::strlen_raw(source));
    Vector<Token> tokens;
    if (!preprocessor.run(id, &tokens)) {
        result.errors = diags.error_count();
        if (diags.error_count() > 0) {
            const Diagnostic& first = diags.diagnostics()[0];
            result.error_line = first.line;
            result.error_column = first.column;
            result.error_code = first.code;
            result.error_message = first.message;
        }
        return result;
    }
    parser.parse_translation_unit(tokens);
    result.tree = ast.render();
    result.errors = diags.error_count();
    if (diags.error_count() > 0) {
        const Diagnostic& first = diags.diagnostics()[0];
        result.error_line = first.line;
        result.error_column = first.column;
        result.error_code = first.code;
        result.error_message = first.message;
    }
    return result;
}

// Compares the tree of a source with the expected tree.
static void expect_tree(const char* what, const char* source, const char* expected) {
    const Run result = run(source);
    if (result.errors != 0) {
        bad(what, String("the front end reported an error: ") + result.error_message +
                       " at " + to_text(static_cast<int>(result.error_line)) + ":" +
                       to_text(static_cast<int>(result.error_column)));
        return;
    }
    if (result.tree != expected) {
        // The two trees look the same on the screen, so the place they
        // differ is reported as well.
        size_type at = 0;
        while (at < result.tree.size() && at < rawrstd::strlen_raw(expected) &&
               result.tree[at] == expected[at]) {
            ++at;
        }
        String detail = String("the tree is\n") + result.tree + "  wanted\n" + expected;
        detail << "\n  they differ at byte " << to_text(static_cast<int>(at));
        if (at < result.tree.size()) {
            detail << ", the tree has ";
            detail.push_back(result.tree[at]);
            detail << " and the expectation has ";
            detail.push_back(expected[at]);
        }
        bad(what, detail);
        return;
    }
    ok(what);
}

// Checks that a source is rejected, and that the diagnostic points at the
// right place.
static void expect_error(const char* what, const char* source, uint32 line, uint32 column) {
    const Run result = run(source);
    if (result.errors == 0) {
        bad(what, String("the source was accepted, the tree is\n") + result.tree);
        return;
    }
    if (result.error_line != line || result.error_column != column) {
        bad(what, String("the error is at ") + to_text(static_cast<int>(result.error_line)) + ":" +
                       to_text(static_cast<int>(result.error_column)) + ", wanted " +
                       to_text(static_cast<int>(line)) + ":" + to_text(static_cast<int>(column)) +
                       " (" + result.error_message + ")");
        return;
    }
    ok(what);
}

int main() {
    // ---- 01: translation units and functions ----
    expect_tree("a translation unit holds a function",
        "int main(void) {\n"
        "    return 0;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl main -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    expect_tree("a translation unit holds two functions",
        "int a(void) { return 1; }\n"
        "int b(void) { return 2; }\n",
        "TranslationUnit\n"
        "  FunctionDecl a -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 1\n"
        "  FunctionDecl b -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 2\n");

    // ---- 02: local and global declarations ----
    expect_tree("a global declaration holds its initialiser",
        "int global = 7;\n",
        "TranslationUnit\n"
        "  DeclStmt\n"
        "    VarDecl global : int\n"
        "      IntegerLiteral 7\n");

    expect_tree("a declaration may carry several specifiers",
        "static unsigned long counter;\n",
        "TranslationUnit\n"
        "  DeclStmt\n"
        "    VarDecl counter : static unsigned long\n");

    expect_tree("a local declaration is inside the block",
        "void f(void) {\n"
        "    int local = 1;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> void\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      DeclStmt\n"
        "        VarDecl local : int\n"
        "          IntegerLiteral 1\n");

    // ---- 03: precedence and associativity ----
    expect_tree("the multiplication binds tighter than the addition",
        "int f(void) { return 1 + 2 * 3; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        BinaryExpr +\n"
        "          IntegerLiteral 1\n"
        "          BinaryExpr *\n"
        "            IntegerLiteral 2\n"
        "            IntegerLiteral 3\n");

    expect_tree("the subtraction is left associative",
        "int f(void) { return 1 - 2 - 3; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        BinaryExpr -\n"
        "          BinaryExpr -\n"
        "            IntegerLiteral 1\n"
        "            IntegerLiteral 2\n"
        "          IntegerLiteral 3\n");

    expect_tree("the logical and binds tighter than the logical or",
        "int f(void) { return a || b && c; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        BinaryExpr ||\n"
        "          Identifier a\n"
        "          BinaryExpr &&\n"
        "            Identifier b\n"
        "            Identifier c\n");

    expect_tree("the comparison binds tighter than the logical and",
        "int f(void) { return a < b == c; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        BinaryExpr ==\n"
        "          BinaryExpr <\n"
        "            Identifier a\n"
        "            Identifier b\n"
        "          Identifier c\n");

    expect_tree("the conditional operator is right associative",
        "int f(void) { return a ? b : c ? d : e; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        ConditionalExpr\n"
        "          Identifier a\n"
        "          Identifier b\n"
        "          ConditionalExpr\n"
        "            Identifier c\n"
        "            Identifier d\n"
        "            Identifier e\n");

    // ---- 04: assignments and compound assignments ----
    expect_tree("the assignment is right associative",
        "int f(void) { a = b = c; return 0; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ExprStmt\n"
        "        AssignExpr =\n"
        "          Identifier a\n"
        "          AssignExpr =\n"
        "            Identifier b\n"
        "            Identifier c\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    expect_tree("a compound assignment keeps its operator",
        "int f(void) { a += 1; a -= 2; a *= 3; a /= 4; a %= 5; return 0; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ExprStmt\n"
        "        AssignExpr +=\n"
        "          Identifier a\n"
        "          IntegerLiteral 1\n"
        "      ExprStmt\n"
        "        AssignExpr -=\n"
        "          Identifier a\n"
        "          IntegerLiteral 2\n"
        "      ExprStmt\n"
        "        AssignExpr *=\n"
        "          Identifier a\n"
        "          IntegerLiteral 3\n"
        "      ExprStmt\n"
        "        AssignExpr /=\n"
        "          Identifier a\n"
        "          IntegerLiteral 4\n"
        "      ExprStmt\n"
        "        AssignExpr %=\n"
        "          Identifier a\n"
        "          IntegerLiteral 5\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    // ---- 05: blocks and scopes ----
    expect_tree("a block inside a block is nested",
        "int f(void) {\n"
        "    int a = 1;\n"
        "    {\n"
        "        int b = 2;\n"
        "        a = b;\n"
        "    }\n"
        "    return a;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      DeclStmt\n"
        "        VarDecl a : int\n"
        "          IntegerLiteral 1\n"
        "      CompoundStmt\n"
        "        DeclStmt\n"
        "          VarDecl b : int\n"
        "            IntegerLiteral 2\n"
        "        ExprStmt\n"
        "          AssignExpr =\n"
        "            Identifier a\n"
        "            Identifier b\n"
        "      ReturnStmt\n"
        "        Identifier a\n");

    // ---- 06: if and else ----
    expect_tree("an if statement holds its condition and its body",
        "int f(int x) {\n"
        "    if (x > 0) {\n"
        "        return 1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl x : int\n"
        "    CompoundStmt\n"
        "      IfStmt\n"
        "        BinaryExpr >\n"
        "          Identifier x\n"
        "          IntegerLiteral 0\n"
        "        CompoundStmt\n"
        "          ReturnStmt\n"
        "            IntegerLiteral 1\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    expect_tree("an else branch is kept apart from the body",
        "int f(int x) {\n"
        "    if (x > 0) { return 1; } else { return 0; }\n"
        "    return 2;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl x : int\n"
        "    CompoundStmt\n"
        "      IfStmt\n"
        "        BinaryExpr >\n"
        "          Identifier x\n"
        "          IntegerLiteral 0\n"
        "        CompoundStmt\n"
        "          ReturnStmt\n"
        "            IntegerLiteral 1\n"
        "        CompoundStmt\n"
        "          ReturnStmt\n"
        "            IntegerLiteral 0\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 2\n");

    // ---- 07: while, do and for ----
    expect_tree("a while statement holds its condition and its body",
        "int f(void) {\n"
        "    while (x < 10) { x = x + 1; }\n"
        "    return 0;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      WhileStmt\n"
        "        BinaryExpr <\n"
        "          Identifier x\n"
        "          IntegerLiteral 10\n"
        "        CompoundStmt\n"
        "          ExprStmt\n"
        "            AssignExpr =\n"
        "              Identifier x\n"
        "              BinaryExpr +\n"
        "                Identifier x\n"
        "                IntegerLiteral 1\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    expect_tree("a do statement holds its body and its condition",
        "int f(void) {\n"
        "    do { x = x - 1; } while (x > 0);\n"
        "    return 0;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      DoStmt\n"
        "        CompoundStmt\n"
        "          ExprStmt\n"
        "            AssignExpr =\n"
        "              Identifier x\n"
        "              BinaryExpr -\n"
        "                Identifier x\n"
        "                IntegerLiteral 1\n"
        "        BinaryExpr >\n"
        "          Identifier x\n"
        "          IntegerLiteral 0\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    expect_tree("a for statement holds its three parts and its body",
        "int f(void) {\n"
        "    for (i = 0; i < 5; i = i + 1) { }\n"
        "    return 0;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ForStmt\n"
        "        ExprStmt\n"
        "          AssignExpr =\n"
        "            Identifier i\n"
        "            IntegerLiteral 0\n"
        "        BinaryExpr <\n"
        "          Identifier i\n"
        "          IntegerLiteral 5\n"
        "        AssignExpr =\n"
        "          Identifier i\n"
        "          BinaryExpr +\n"
        "            Identifier i\n"
        "            IntegerLiteral 1\n"
        "        CompoundStmt\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    // ---- 08: break, continue and return ----
    expect_tree("break, continue and return are statements of their own",
        "int f(void) {\n"
        "    while (1) {\n"
        "        if (1) { break; }\n"
        "        continue;\n"
        "    }\n"
        "    return 0;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      WhileStmt\n"
        "        IntegerLiteral 1\n"
        "        CompoundStmt\n"
        "          IfStmt\n"
        "            IntegerLiteral 1\n"
        "            CompoundStmt\n"
        "              BreakStmt\n"
        "          ContinueStmt\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    // ---- 09: calls, pointers, arrays and structs ----
    expect_tree("a call holds the function and the arguments",
        "int f(void) { return add(1, 2); }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        CallExpr\n"
        "          Identifier add\n"
        "          IntegerLiteral 1\n"
        "          IntegerLiteral 2\n");

    expect_tree("a struct holds its fields",
        "struct Point { int x; int y; };\n"
        "int f(void) { return 0; }\n",
        "TranslationUnit\n"
        "  DeclStmt\n"
        "    StructDecl Point\n"
        "      FieldDecl x : int\n"
        "      FieldDecl y : int\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    expect_tree("an array of pointers and a pointer to an array are different",
        "int f(void) {\n"
        "    int *a[10];\n"
        "    int (*b)[10];\n"
        "    return 0;\n"
        "}\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl : void\n"
        "    CompoundStmt\n"
        "      DeclStmt\n"
        "        VarDecl a : int\n"
        "          DeclaratorArray\n"
        "            DeclaratorPointer *\n"
        "              DeclaratorIdentifier a\n"
        "            IntegerLiteral 10\n"
        "      DeclStmt\n"
        "        VarDecl b : int\n"
        "          DeclaratorPointer *\n"
        "            DeclaratorArray\n"
        "              DeclaratorIdentifier b\n"
        "              IntegerLiteral 10\n"
        "      ReturnStmt\n"
        "        IntegerLiteral 0\n");

    expect_tree("a member access keeps the object and the member",
        "int f(struct Point *p) { return p->x; }\n",
        "TranslationUnit\n"
        "  FunctionDecl f -> int\n"
        "    ParamDecl p : struct Point\n"
        "      DeclaratorPointer *\n"
        "        DeclaratorIdentifier p\n"
        "    CompoundStmt\n"
        "      ReturnStmt\n"
        "        MemberExpr -> x\n"
        "          Identifier p\n");

    // ---- 10: a deterministic tree and useful diagnostics ----
    {
        const char* source =
            "int f(int a, int b) {\n"
            "    int c = a + b * 2;\n"
            "    if (c > 0) { return c; }\n"
            "    return 0;\n"
            "}\n";
        const Run first = run(source);
        const Run second = run(source);
        if (first.tree == second.tree && first.errors == second.errors) {
            ok("the same source always produces the same tree");
        } else {
            bad("the same source always produces the same tree",
                String("the two runs differ"));
        }
    }

    expect_error("a missing semicolon is reported where it is",
                 "int f(void) { int x = 1 return x; }\n", 1, 25);

    expect_error("a missing closing bracket is reported",
                 "int f(void) {\n    return 0;\n", 2, 13);

    expect_error("an expression that is not there is reported",
                 "int f(void) { return +; }\n", 1, 23);

    expect_error("a declaration without a name is reported",
                 "int f(void) { int ; return 0; }\n", 1, 19);

    expect_error("an unknown directive is reported by the preprocessor",
                 "#nonsense\nint f(void) { return 0; }\n", 1, 2);

    rawrstd::write_stdout("--------------------------------------------", 44);
    rawrstd::write_stdout("C11 result: ", 13);
    char buffer[64];
    const int n = std::snprintf(buffer, sizeof(buffer), "%d passed, %d failed\n", g_pass, g_fail);
    rawrstd::write_stdout(buffer, static_cast<size_type>(n));
    return g_fail == 0 ? 0 : 1;
}
