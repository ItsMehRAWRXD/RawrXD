#include "rawrxd/closure/WorkspaceGuard.hpp"
#include <algorithm>
#include <cctype>

namespace rawrxd::closure {
namespace {
std::string norm_string(const std::filesystem::path& p) {
    std::string s = p.lexically_normal().generic_string();
#ifdef _WIN32
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
#endif
    if (!s.empty() && s.back() != '/') s.push_back('/');
    return s;
}
}

WorkspaceGuard::WorkspaceGuard(std::filesystem::path root) {
    std::error_code ec;
    auto absolute = std::filesystem::absolute(root, ec);
    if (ec) {
        ec.clear();
        absolute = std::move(root);
    }
    root_ = std::filesystem::weakly_canonical(absolute, ec);
    if (ec) root_ = absolute.lexically_normal();
}

bool WorkspaceGuard::resolve(std::filesystem::path candidate,
                             std::filesystem::path& resolved,
                             std::string* error) const {
    if (candidate.empty()) { if (error) *error = "empty path"; return false; }
    if (candidate.is_relative()) candidate = root_ / candidate;

    // Canonicalize the parent to catch symlink escapes even for a not-yet-created file.
    std::error_code ec;
    auto parent = std::filesystem::weakly_canonical(candidate.parent_path(), ec);
    if (ec) { if (error) *error = "cannot canonicalize parent"; return false; }
    resolved = (parent / candidate.filename()).lexically_normal();

    const std::string root_s = norm_string(root_);
    const std::string candidate_s = norm_string(resolved.parent_path());
    if (candidate_s.rfind(root_s, 0) != 0) {
        if (error) *error = "path escapes workspace root";
        return false;
    }
    return true;
}

} // namespace rawrxd::closure
