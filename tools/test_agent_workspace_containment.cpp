// Standalone workspace-containment smoke. Mirrors containedSource in dispatcher.
// This is an algorithm test, not a linked native IDE integration test.
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>
#include <chrono>
#include <fstream>
namespace fs = std::filesystem;
static std::optional<fs::path> containedSource(const fs::path& workspace,
                                               const fs::path& relative) {
    if (relative.empty() || relative.is_absolute() || relative.has_root_name() ||
        relative.has_root_directory()) return std::nullopt;
    std::error_code ec;
    const auto root = fs::weakly_canonical(workspace, ec);
    if (ec || root.empty()) return std::nullopt;
    const auto full = fs::weakly_canonical(root / relative, ec);
    if (ec || full == root) return std::nullopt;
    auto a = root.begin(), b = full.begin();
    while (a != root.end() && b != full.end() && *a == *b) { ++a; ++b; }
    if (a != root.end()) return std::nullopt;
    return full;
}
int main() {
    const auto unique = std::chrono::steady_clock::now().time_since_epoch().count();
    const fs::path base = fs::temp_directory_path() /
                          ("rawrxd_workspace_smoke_" + std::to_string(unique));
    const fs::path root = base / "work";
    fs::create_directories(root / "src");
    fs::create_directories(base / "outside");
    { std::ofstream out(root / "src" / "inside.cpp"); out << "ok"; }
    std::error_code ec;
    fs::create_directory_symlink(base / "outside", root / "escape", ec);
    const bool haveEscapeLink = !ec;
    ec.clear();
    fs::create_directory_symlink(root / "src", root / "inside_link", ec);
    const bool haveInsideLink = !ec;
    const std::vector<std::pair<fs::path, bool>> cases = {
        {"src/inside.cpp", true}, {"src", true}, {"src/new.cpp", true},
        {"src/../src/inside.cpp", true}, {"src/./inside.cpp", true},
        {"", false}, {".", false}, {"..", false},
        {"../outside", false}, {"../work2/file", false},
        {"../../outside", false}, {base / "outside", false},
        {"escape/file", false}, {"inside_link/inside.cpp", true},
        {"src/../../outside/file", false}
    };
    int failed = 0;
    for (size_t i = 0; i < cases.size(); ++i) {
        if ((i == 12 && !haveEscapeLink) || (i == 13 && !haveInsideLink)) {
            std::cout << "CASE_" << i + 1 << "=SKIP_SYMLINK_UNAVAILABLE\n";
            continue;
        }
        const bool accepted = containedSource(root, cases[i].first).has_value();
        if (accepted != cases[i].second) ++failed;
        std::cout << "CASE_" << i + 1 << "="
                  << (accepted == cases[i].second ? "PASS" : "FAIL") << "\n";
    }
    fs::remove_all(base);
    return failed == 0 ? 0 : 1;
}
