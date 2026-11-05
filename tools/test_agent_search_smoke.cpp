// Standalone smoke coverage for full-line search and symbol token boundaries.
// Does not link the native IDE; validates the core scanning algorithm.
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

int main() {
    const auto path = std::filesystem::temp_directory_path() /
                      "rawrxd_agent_search_smoke_fixture.txt";
    {
        std::ofstream out(path);
        if (!out) return 2;
        out << std::string(20000, 'x') << "NEEDLE\n";
        out << "prefixsymbol symbol symbol_suffix\n";
    }
    std::ifstream in(path);
    std::string line;
    uint64_t lineNo = 0;
    bool longLine = false, tokenBoundary = false;
    while (std::getline(in, line)) {
        ++lineNo;
        if (lineNo == 1 && line.find("NEEDLE") != std::string::npos)
            longLine = true;
        const std::string sym = "symbol";
        size_t pos = 0;
        while ((pos = line.find(sym, pos)) != std::string::npos) {
            const auto ident = [](unsigned char c) {
                return std::isalnum(c) || c == '_';
            };
            const bool lo = pos == 0 ||
                !ident(static_cast<unsigned char>(line[pos - 1]));
            const size_t after = pos + sym.size();
            const bool hi = after == line.size() ||
                !ident(static_cast<unsigned char>(line[after]));
            if (lo && hi) { tokenBoundary = true; break; }
            pos += sym.size();
        }
    }
    std::filesystem::remove(path);
    std::cout << "LONG_LINE_SEARCH=" << (longLine ? "PASS" : "FAIL") << "\n";
    std::cout << "TOKEN_BOUNDARY=" << (tokenBoundary ? "PASS" : "FAIL") << "\n";
    return longLine && tokenBoundary ? 0 : 1;
}
