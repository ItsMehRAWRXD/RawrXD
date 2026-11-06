#pragma once
#include <filesystem>
#include <system_error>

namespace rawrxd::extensions {
// Only a missing path or an ordinary, empty directory can receive a new VSIX.
// Inspect the final component without following symlinks/junctions.
inline bool safeExtractionDestination(const std::filesystem::path& destination) noexcept {
    if (destination.empty()) return false;
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(destination, ec);
    if (ec == std::errc::no_such_file_or_directory) return true;
    if (ec) return false;
    if (status.type() == std::filesystem::file_type::not_found) return true;
    if (status.type() != std::filesystem::file_type::directory) return false;
    const bool empty = std::filesystem::is_empty(destination, ec);
    return !ec && empty;
}
}
