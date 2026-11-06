#pragma once
#include <filesystem>
#include <system_error>
#include <string_view>
namespace rawrxd::extensions {
// Manifest entry paths must be relative on Windows as well as POSIX.
// A Windows drive prefix is invalid even when tested by a Linux CI runner.
inline bool validRelativeMain(std::string_view entry) noexcept {
    if (entry.empty() || entry == ".") return false;
    if (entry[0] == '/' || entry[0] == 92) return false;
    if (entry.size() >= 2 &&
        ((entry[0] >= 'A' && entry[0] <= 'Z') ||
         (entry[0] >= 'a' && entry[0] <= 'z')) &&
        entry[1] == ':') return false;
    // Treat both separator styles as path boundaries on every platform.
    // Reject parent traversal, empty components, and colon-based drive/stream syntax.
    size_t segmentStart = 0;
    bool firstSegment = true;
    for (size_t i = 0; i <= entry.size(); ++i) {
        if (i == entry.size() || entry[i] == '/' || entry[i] == 92) {
            const auto segment = entry.substr(segmentStart, i - segmentStart);
            if (segment == ".." || (segment == "." && !firstSegment) || segment.empty() ||
                (segment != "." && segment.back() == '.') || segment.back() == ' ') return false;
            // Windows treats these basenames as devices even with extensions.
            const auto dot = segment.find('.');
            const auto stem = segment.substr(0, dot);
            auto upper = [](char c) noexcept -> char {
                return c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c;
            };
            if (stem.size() == 3) {
                const char a = upper(stem[0]), b = upper(stem[1]), c = upper(stem[2]);
                if ((a == 'C' && b == 'O' && c == 'N') ||
                    (a == 'P' && b == 'R' && c == 'N') ||
                    (a == 'A' && b == 'U' && c == 'X') ||
                    (a == 'N' && b == 'U' && c == 'L')) return false;
            } else if (stem.size() == 4) {
                const char a = upper(stem[0]), b = upper(stem[1]), c = upper(stem[2]);
                if (((a == 'C' && b == 'O' && c == 'M') ||
                     (a == 'L' && b == 'P' && c == 'T')) &&
                    stem[3] >= '1' && stem[3] <= '9') return false;
            }
            firstSegment = false;
            segmentStart = i + 1;
        } else {
            const unsigned char c = static_cast<unsigned char>(entry[i]);
            if (c < 32 || c == 127 || c == ':' || c == '<' || c == '>' ||
                c == '"' || c == '|' || c == '?' || c == '*') return false;
        }
    }
    return true;
}
// Reject extension entry points outside the installed extension directory.
// weakly_canonical handles non-existent leaf paths and resolves existing symlinks.
inline bool entryWithinRoot(const std::filesystem::path& root,
                            const std::filesystem::path& entry) {
    if (root.empty() || entry.empty()) return false;
    // Never resolve caller-supplied relative paths against the process CWD.
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
