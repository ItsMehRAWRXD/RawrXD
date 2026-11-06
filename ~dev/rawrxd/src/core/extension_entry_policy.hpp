#pragma once
#include <filesystem>
#include <system_error>
namespace rawrxd::extensions {
// Reject extension entry points outside the installed extension directory.
// weakly_canonical handles non-existent leaf paths and resolves existing symlinks.
inline bool entryWithinRoot(const std::filesystem::path& root,
                            const std::filesystem::path& entry) {
    if (root.empty() || entry.empty()) return false;
    // Do not interpret relative paths against the process working directory:
    // extension validation must not change when the IDE is launched elsewhere.
    if (!root.is_absolute() || !entry.is_absolute()) return false;
    std::error_code ec;
    const auto base = std::filesystem::weakly_canonical(root, ec);
    if (ec || base.empty()) return false;
    const auto target = std::filesystem::weakly_canonical(entry, ec);
    if (ec || target.empty()) return false;
    auto b = base.begin(), t = target.begin();
    for (; b != base.end(); ++b, ++t) {
        if (t == target.end() || *b != *t) return false;
    }
    return t != target.end(); // Entry must be a child, not the directory itself.
}
}
