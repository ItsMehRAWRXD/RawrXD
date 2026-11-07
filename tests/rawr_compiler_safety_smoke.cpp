// Headless safety regression for the production RawrCompiler API.
// This intentionally does not claim native compilation or linking on Linux.
#include "../~dev/rawrxd/src/reverse_engineering/RawrCompiler.hpp"
#include <iostream>
#include <string>
#include <vector>

int main() {
    using namespace RawrXD::ReverseEngineering;
    RawrCompiler compiler;
    int failures = 0;
    auto check = [&](bool value, const char* label) {
        std::cout << (value ? "PASS " : "FAIL ") << label << '\n';
        if (!value) ++failures;
    };
    const auto jit = compiler.CompileAndLoadJIT("int main() { return 0; }");
    check(jit.codePtr == nullptr && jit.codeSize == 0, "01 unimplemented JIT cannot claim executable code");
    auto invalid = compiler.CompileString("x", "not-a-language");
    check(!invalid.success && !invalid.errors.empty(), "02 unknown language fails");
    check(invalid.compileTimeMs == 0, "03 invalid language has initialized timing");
    auto missing = compiler.CompileSource("file-that-does-not-exist-rawrxd.cpp");
    check(!missing.success && !missing.errors.empty(), "04 missing source fails");
    check(missing.compileTimeMs == 0, "05 missing source has initialized timing");
    check(!compiler.Link({}, "output"), "06 empty object list rejected");
    check(!compiler.Link({"missing-object-rawrxd.o"}, "output"), "07 nonexistent object rejected");
    check(!compiler.Link({""}, "output"), "08 empty object name rejected");
    check(!compiler.Link({}, ""), "09 empty output rejected");
    auto unsupported = compiler.CompileString("x", "asm-invalid");
    check(!unsupported.success, "10 unknown assembly language rejected");
    std::cout << "RESULT " << (10 - failures) << "/10 checks; "
              << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
