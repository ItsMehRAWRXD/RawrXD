#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <unordered_set>

namespace fs = std::filesystem;

namespace {

std::string Escape(const std::string& value) {
    std::string out;
    for (unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c < 0x20 ? " " : std::string(1, static_cast<char>(c));
        }
    }
    return out;
}

uint64_t Hash(const std::string& text) {
    uint64_t h = 1469598103934665603ull;
    for (unsigned char c : text) { h ^= c; h *= 1099511628211ull; }
    return h;
}

bool SourceExtension(const fs::path& path) {
    static const std::unordered_set<std::string> kExt = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".ixx", ".m", ".mm", ".cs", ".java", ".js", ".jsx", ".ts",
        ".tsx", ".py", ".rs", ".go", ".zig", ".cmake", ".ps1", ".bat",
        ".sh", ".json", ".yaml", ".yml", ".md"
    };
    return kExt.count(path.extension().string()) != 0;
}

bool SkipDirectory(const fs::path& path) {
    const std::string n = path.filename().string();
    return n == ".git" || n == ".vs" || n == "node_modules" || n == "_cert_clean" ||
           n == "build" || n == "builds" || n == "out" || n == "Release" || n == "Debug";
}

void Usage() {
    std::cerr << "usage: rawrxd_astro_index --root <repo> --output <index.jsonl> [--query <text>]\n";
}

} // namespace

int main(int argc, char** argv) {
    fs::path root;
    fs::path output;
    std::string query;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--root" && i + 1 < argc) root = argv[++i];
        else if (arg == "--output" && i + 1 < argc) output = argv[++i];
        else if (arg == "--query" && i + 1 < argc) query = argv[++i];
        else { Usage(); return 2; }
    }
    if (root.empty() || output.empty() || !fs::is_directory(root)) { Usage(); return 2; }

    std::ofstream index(output, std::ios::trunc);
    if (!index) { std::cerr << "ASTRO_INDEX_FAIL cannot create output\n"; return 1; }

    const std::regex typePattern(R"(^\s*(class|struct|enum(?:\s+class)?|namespace)\s+([A-Za-z_][A-Za-z0-9_:]*))");
    const std::regex functionPattern(R"(^\s*(?:[A-Za-z_][A-Za-z0-9_:<>*&\s,]*\s+)?([A-Za-z_][A-Za-z0-9_:]*)\s*\([^;{}]*\)\s*(?:const|noexcept|override|final|->[^\{;]+|\s)*\s*(?:\{|$))");
    const std::unordered_set<std::string> excluded = {"if", "for", "while", "switch", "catch", "return"};
    size_t files = 0, symbols = 0;
    std::error_code ec;
    fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
    for (; it != end; it.increment(ec)) {
        if (ec) { ec.clear(); continue; }
        if (it->is_directory(ec)) {
            if (SkipDirectory(it->path())) it.disable_recursion_pending();
            continue;
        }
        if (!it->is_regular_file(ec) || !SourceExtension(it->path())) continue;
        std::ifstream in(it->path(), std::ios::binary);
        if (!in) continue;
        std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        if (text.size() > 16u * 1024u * 1024u) continue;
        const fs::path relative = fs::relative(it->path(), root, ec);
        const std::string path = (ec ? it->path() : relative).generic_string();
        index << "{\"kind\":\"file\",\"path\":\"" << Escape(path)
              << "\",\"bytes\":" << text.size() << ",\"hash\":\"" << std::hex << Hash(text) << std::dec << "\"}\n";
        ++files;

        size_t lineNo = 0, begin = 0;
        while (begin <= text.size()) {
            ++lineNo;
            const size_t endLine = text.find('\n', begin);
            const std::string line = text.substr(begin, endLine == std::string::npos ? std::string::npos : endLine - begin);
            std::smatch match;
            std::string kind, name;
            if (std::regex_search(line, match, typePattern)) {
                kind = match[1].str(); name = match[2].str();
            } else if (std::regex_search(line, match, functionPattern)) {
                name = match[1].str();
                if (!excluded.count(name)) kind = "function";
            }
            if (!kind.empty()) {
                const std::string needle = query.empty() ? name : query;
                if (query.empty() || name.find(needle) != std::string::npos || path.find(needle) != std::string::npos) {
                    index << "{\"kind\":\"symbol\",\"symbol_kind\":\"" << Escape(kind)
                          << "\",\"name\":\"" << Escape(name) << "\",\"path\":\""
                          << Escape(path) << "\",\"line\":" << lineNo << "}\n";
                    ++symbols;
                }
            }
            if (endLine == std::string::npos) break;
            begin = endLine + 1;
        }
    }
    index.flush();
    if (!index) { std::cerr << "ASTRO_INDEX_FAIL write error\n"; return 1; }
    std::cout << "ASTRO_INDEX_PASS files=" << files << " symbols=" << symbols
              << " output=" << output.string() << "\n";
    return 0;
}
