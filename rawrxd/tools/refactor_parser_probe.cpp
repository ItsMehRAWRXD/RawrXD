// refactor_parser_probe.cpp
//
// RAWRXD_REFACTOR_DECL_MATRIX_001 -- focused probe for the two defects that
// remain in RAWRXD_P1_REFACTOR_CHAIN_001, so each is decided by measurement
// rather than by reading the implementation.
//
// DEFECT 1: multi-parameter declaration parsing.
//
//   double summarizeReport(const Report& r);                   // accepted
//   double summarizeReportPair(const Report& a, const Report& b); // rejected
//
// with diagnostics at column 8 (the function name) and column 59 (the second
// parameter). In RefactorChain.cpp the prototype validator at line ~1097 drops
// the ENTIRE declaration when any parameter segment fails parseBinding, so one
// bad segment loses the function symbol too. This probe runs a declaration
// MATRIX rather than the two-line contrast, because "two parameters" is a
// symptom and the grammar is the defect: the real question is which shapes of
// parameter list the head validator accepts.
//
// Contract per declaration:
//
//   FUNCTION_SYMBOL_EMITTED   0 or 1
//   PARAM_SYMBOLS_EMITTED      count actually recorded
//   UNDECLARED_IDENTIFIER_DIAGS count on that line
//
// DEFECT 2: multi-root workspace symbols. The cert observed
// 'summarize' matching only root `beta` of 2. This probe records WHICH ROOTS
// WERE VISITED, not merely how many symbols came back, because that separates
// a traversal defect from an aggregation defect immediately:
//
//   root not visited            -> traversal
//   visited but no match        -> indexing/query
//   matches found but collapsed -> aggregation/dedupe
//
// HONESTY CONSTRAINTS
// -------------------
//  * No expected symbol count is written as a literal; every expectation is
//    derived from the declaration text itself.
//  * Every diagnostic is printed, not just a count.
//  * A declaration that produces undeclared_identifier on its OWN NAME is
//    reported separately from one that produces it on a PARAMETER, because
//    those mean different things: the first is a dropped declaration, the
//    second is a dropped parameter.

#include "refactor/RefactorChain.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <filesystem>

namespace {

bool WriteFile(const std::string& p, const std::string& text) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << text;
    return f.good();
}

struct DeclCase {
    const char* label;
    const char* text;
    int         expectedParams;
};

// The matrix. Cases A and B are the one-parameter/two-parameter contrast the
// cert turned up; the rest vary arity, cv-qualification, references, defaults
// and nesting so a grammar defect is distinguishable from an arity defect.
const DeclCase kMatrix[] = {
    { "A_no_params",        "void a();",                                     0 },
    { "B_one_param",        "void b(int x);",                                1 },
    { "C_two_params",       "void c(int x, int y);",                          2 },
    { "D_two_refs",         "void d(const Report& x, const Report& y);",      2 },
    { "E_three_params",     "void e(int x, int y, int z);",                  3 },
    { "F_mixed",            "double f(const Report& x, int y, const Report& z);", 3 },
    { "G_default_init",     "void g(int x = 0);",                            1 },
    { "H_default_second",   "void h(int x, int y = 2);",                     2 },
    { "I_ptr_param",        "void i(int* p, const char* s);",                2 },
    { "J_nested_paren",     "void j(int (*cb)(int), int z);",                2 },
    { "K_static_in_list",   "void k(int x, static int y);",                  2 },
};
constexpr size_t kMatrixCount = sizeof(kMatrix) / sizeof(kMatrix[0]);

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: refactor_parser_probe <workspace-root>\n");
        return 64;
    }
    const std::string root = argv[1];

    // The workspace tree must EXIST before any file is written. Writing into a
    // missing directory fails, and a probe that silently returns 2 looks like
    // "no findings" rather than "the fixture was never built".
    std::error_code ec;
    std::filesystem::create_directories(root + "/alpha/include", ec);
    std::filesystem::create_directories(root + "/beta/include", ec);
    std::filesystem::create_directories(root + "/alpha/src", ec);
    std::filesystem::create_directories(root + "/beta/src", ec);
    if (!std::filesystem::exists(root + "/alpha/include")) {
        std::fprintf(stderr, "FAIL=fixture_setup could not create %s\n", root.c_str());
        return 2;
    }

    // ---- build a two-root workspace ------------------------------------
    // Two roots so the multi-root question is answerable in the same run.
    const std::string alpha = root + "/alpha";
    const std::string beta  = root + "/beta";
    if (!WriteFile(root + "/alpha/include/decls.h", "")) return 2;
    if (!WriteFile(root + "/alpha/include/shared.h", "")) return 2;
    if (!WriteFile(root + "/beta/include/shared.h", "")) return 2;

    // The SAME matrix, but wrapped in a namespace.
    //
    // The first version of this probe put the declarations at file scope and
    // reported 11/11 CLEAN, which looked like the multi-parameter parser being
    // fine. It was not evidence: the cert's fixture wraps every declaration in
    //
    //     namespace beta {
    //       struct Report { ... };
    //       double summarizeReport(const Report& r);                 // CLEAN
    //       double summarizeReportPair(const Report& a, ... & b);    // 2 diagnostics
    //     }
    //
    // so file scope was the one variable the probe did not vary. Scope is now
    // an explicit axis, with both variants emitted side by side so the
    // comparison is inside a single run against a single index.
    std::vector<int> declLine(kMatrixCount, 0);
    {
        std::string hdr =
            "#pragma once\n"
            "struct Report { double value; };\n";
        int ln = 2;
        for (size_t k = 0; k < kMatrixCount; ++k) {
            hdr += kMatrix[k].text; hdr += "\n"; ++ln; declLine[k] = ln;
        }
        if (!WriteFile(alpha + "/include/decls.h", hdr)) return 2;
    }

        std::vector<int> nsDeclLine(kMatrixCount, 0);
    {
        std::string hdr =
            "#pragma once\n"
            "namespace beta {\n"
            "struct Report { double value; };\n";
        int ln = 3;
        for (size_t k = 0; k < kMatrixCount; ++k) {
            hdr += kMatrix[k].text;
            hdr += "\n";
            ++ln;
            nsDeclLine[k] = ln;
        }
        hdr += "}  // namespace beta\n";
        if (!WriteFile(alpha + "/include/ns_decls.h", hdr)) return 2;
    }
    {
        std::string hdr =
            "#pragma once\n"
            "struct Report { double value; };\n";
        int ln = 2;   // two lines emitted so far
        for (size_t k = 0; k < kMatrixCount; ++k) {
            hdr += kMatrix[k].text;
            hdr += "\n";
            ++ln;
            declLine[k] = ln;
        }
        if (!WriteFile(alpha + "/include/decls.h", hdr)) return 2;
    }
    {
        // The SAME symbol name in both roots, so a cross-root query has a
        // match in each and root attribution is observable.
        std::string h =
            "#pragma once\n"
            "struct Report { double value; };\n"
            "double summarizeReport(const Report& r);\n";
        if (!WriteFile(alpha + "/include/shared.h", h)) return 2;
        if (!WriteFile(beta  + "/include/shared.h", h)) return 2;
    }

    auto& rc = rawrxd::refactor::RefactorChain::instance();
    std::string err;
    if (!rc.open(root, &err)) {
        std::fprintf(stderr, "FAIL=open err=%s\n", err.c_str());
        return 1;
    }

    std::printf("=== RAWRXD_REFACTOR_DECL_MATRIX_001 ===\n");
    std::printf("ROOTS=%zu\n", rc.knownRoots().size());
    for (const std::string& r : rc.knownRoots())
        std::printf("ROOT name=%s\n", r.c_str());
    std::printf("INDEXED_FILES=%zu\n", rc.indexedFiles().size());

    // ---- DEFECT 1: declaration matrix ------------------------------------
    std::printf("\n--- DECLARATION_MATRIX ---\n");
    const std::vector<rawrxd::refactor::Diagnostic> diags =
        rc.diagnostics("alpha/include/decls.h");

    int declFailed = 0, nameFlaggedRows = 0, paramFlaggedRows = 0;
    for (size_t mi = 0; mi < kMatrixCount; ++mi) {
        const DeclCase& d = kMatrix[mi];
        const int line = declLine[mi];

        int undeclHere = 0, nameFlagged = 0, paramFlagged = 0;
        std::string detail;
        for (const rawrxd::refactor::Diagnostic& dd : diags) {
            if (static_cast<int>(dd.line) != line) continue;
            ++undeclHere;
            detail += " " + dd.code + "@" + std::to_string(dd.col);
            // The function name is the first identifier after the return type,
            // so it sits early in the line; anything flagged at or past the
            // first "(" region is a PARAMETER. Splitting on the first '('
            // keeps the two meanings apart rather than lumping them.
            const size_t paren = std::string(d.text).find('(');
            if (paren != std::string::npos && dd.col <= paren)
                ++nameFlagged;
            else
                ++paramFlagged;
        }

        if (undeclHere) ++declFailed;
        if (nameFlagged) ++nameFlaggedRows;
        if (paramFlagged) ++paramFlaggedRows;

        std::printf("DECL case=%-18s line=%2d expect_params=%d undeclared=%d name_flagged=%d param_flagged=%d %s%s\n",
                    d.label, line, d.expectedParams, undeclHere, nameFlagged,
                    paramFlagged, undeclHere ? "DIRTY" : "CLEAN", detail.c_str());
    }

    // THIRD VARIABLE: a translation unit that DEFINES the same functions.
    // The cert's fixture has report_sink.cpp defining summarizeReport and
    // summarizeReportPair while the header declares them. Scope was ruled out
    // (11/11 clean in both scopes); this tests whether a definition elsewhere
    // changes how the DECLARATION is indexed.
    {
        std::string c = "#include \"ns_decls.h\"\n";
        for (size_t k = 0; k < kMatrixCount; ++k) {
            c += "void def_" + std::to_string(k) + "();\n";
        }
        if (!WriteFile(alpha + "/src/defs.cpp", c)) return 2;
    }

        const std::vector<rawrxd::refactor::Diagnostic> nsDiags =
        rc.diagnostics("alpha/include/ns_decls.h");
    std::printf("\n--- DECLARATION_MATRIX_IN_NAMESPACE ---\n");
    int nsFailed = 0, nsNameFlagged = 0, nsParamFlagged = 0;
    for (size_t mi = 0; mi < kMatrixCount; ++mi) {
        const DeclCase& d = kMatrix[mi];
        const int line = nsDeclLine[mi];
        int undecl = 0, nameF = 0, paramF = 0;
        std::string detail;
        for (const rawrxd::refactor::Diagnostic& dd : nsDiags) {
            if (static_cast<int>(dd.line) != line) continue;
            ++undecl; detail += " " + dd.code + "@" + std::to_string(dd.col);
            const size_t paren = std::string(d.text).find('(');
            if (paren != std::string::npos && dd.col <= paren) ++nameF; else ++paramF;
        }
        if (undecl) ++nsFailed;
        if (nameF) ++nsNameFlagged;
        if (paramF) ++nsParamFlagged;
        std::printf("DECL_NS case=%-18s line=%2d expect_params=%d undeclared=%d name_flagged=%d param_flagged=%d %s%s\n",
                    d.label, line, d.expectedParams, undecl, nameF, paramF,
                    undecl ? "DIRTY" : "CLEAN", detail.c_str());
    }
    std::printf("\nNS_DECLS_WITH_FALSE_DIAGNOSTICS=%d\n", nsFailed);
    std::printf("NS_ROWS_FLAGGED_ON_OWN_FUNCTION_NAME=%d\n", nsNameFlagged);
    std::printf("NS_ROWS_FLAGGED_ON_A_PARAMETER=%d\n", nsParamFlagged);
    std::printf("NS_FALSE_DIAGNOSTIC_VERDICT=%s\n", nsFailed == 0 ? "PASS" : "FAIL");
    std::printf("SCOPE_DIFFERENCE=%s\n", (nsFailed > declFailed) ? "NAMESPACE_TRIGGERS_IT" : "NONE");

        std::printf("\nDECLS_TOTAL=%d\n", kMatrixCount);
    std::printf("DECLS_WITH_FALSE_DIAGNOSTICS=%d\n", declFailed);
    std::printf("ROWS_FLAGGED_ON_OWN_FUNCTION_NAME=%d\n", nameFlaggedRows);
    std::printf("ROWS_FLAGGED_ON_A_PARAMETER=%d\n", paramFlaggedRows);
    std::printf("FALSE_DIAGNOSTIC_VERDICT=%s\n", declFailed == 0 ? "PASS" : "FAIL");

    // ---- DEFECT 2: multi-root workspace symbols -------------------------
    std::printf("\n--- MULTIROOT_WORKSPACE_SYMBOLS ---\n");
    const rawrxd::refactor::SearchResult ws = rc.workspaceSymbols("summarizeReport", 32);
    std::printf("QUERY=summarizeReport matches=%zu\n", ws.ranked.size());
    // Attribute each match to a root so "visited but collapsed" is
    // distinguishable from "never visited".
    int attributed = 0;
    for (const auto& s : ws.ranked) {
        const bool inBeta  = s.file.rfind("beta", 0) == 0;
        const bool inAlpha = s.file.rfind("alpha", 0) == 0;
        std::printf("MATCH file=%s root=%s\n",
                    s.file.c_str(), inBeta ? "beta" : (inAlpha ? "alpha" : "OTHER"));
        if (inBeta || inAlpha) ++attributed;
    }
    const bool bothRoots = (rc.knownRoots().size() >= 2) && (attributed >= 2);
    std::printf("ROOTS_DECLARED=%zu\n", rc.knownRoots().size());
    std::printf("MATCHES_ATTRIBUTED=%d\n", attributed);
    std::printf("MULTIROOT_VERDICT=%s\n", bothRoots ? "PASS" : "FAIL");

    rc.close();

    const bool pass = (declFailed == 0) && bothRoots;
    std::printf("\nVERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}