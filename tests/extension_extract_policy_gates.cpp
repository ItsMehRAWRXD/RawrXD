#include "extension_extract_policy.hpp"
#include <filesystem>
#include <iostream>
#include <cstdlib>
#include <fstream>
namespace fs = std::filesystem;
int main() {
    int failed = 0, passed = 0, skipped = 0;
    auto gate = [&](const char* name, bool ok) {
        std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
        ok ? ++passed : ++failed;
    };
    std::error_code ec;
    const auto base = fs::temp_directory_path() / "rawrxd_extract_policy_test";
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    if (ec) { std::cerr << "FAIL setup: " << ec.message() << '\n'; return EXIT_FAILURE; }
    using rawrxd::extensions::safeExtractionDestination;
    gate("missing_target_allowed", safeExtractionDestination(base / "missing"));
    gate("empty_directory_allowed", safeExtractionDestination(base));
    gate("empty_path_rejected", !safeExtractionDestination({}));
    {
        const auto file = base / "file.txt";
        std::ofstream out(file);
        out << "content";
    }
    gate("nonempty_directory_rejected", !safeExtractionDestination(base));
    gate("regular_file_rejected", !safeExtractionDestination(base / "file.txt"));
    const auto target = base / "target";
    fs::create_directories(target, ec);
    const auto link = base / "link";
    fs::create_directory_symlink(target, link, ec);
    if (ec) {
        ++skipped;
        std::cout << "SKIP directory_symlink_rejected: " << ec.message() << '\n';
    } else {
        gate("directory_symlink_rejected", !safeExtractionDestination(link));
    }
    // A dangling symlink must not be treated as a missing extraction target.
    const auto dangling = base / "dangling";
    std::error_code danglingEc;
    fs::create_directory_symlink(base / "not-present", dangling, danglingEc);
    if (danglingEc) {
        ++skipped;
        std::cout << "SKIP dangling_symlink_rejected: " << danglingEc.message() << '\\n';
    } else {
        gate("dangling_symlink_rejected", !safeExtractionDestination(dangling));
    }
    fs::remove_all(base, ec);
    std::cout << "SUMMARY " << passed << " PASS; " << failed << " FAIL; " << skipped << " SKIP\n";
    return failed ? EXIT_FAILURE : EXIT_SUCCESS;
}
