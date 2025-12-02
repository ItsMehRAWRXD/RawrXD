#pragma once
#include <string>
#include <vector>
#include <optional>
#include <functional>

namespace RawrXD {
namespace Tools {

struct FileOpResult {
    bool success;
    std::string message;
    std::optional<std::string> path;
};

struct CopyOptions {
    bool overwrite = false;
    bool preserve_timestamps = true;
    bool create_dirs = true;
};

class FileOps {
public:
    static FileOpResult readText(const std::string& path, std::string& out);
    static FileOpResult writeText(const std::string& path, const std::string& content, bool create_dirs = true);
    static FileOpResult appendText(const std::string& path, const std::string& content);
    static FileOpResult remove(const std::string& path);
    static FileOpResult rename(const std::string& from, const std::string& to, bool create_dirs = true);
    static FileOpResult copy(const std::string& from, const std::string& to, const CopyOptions& opts = {});
    static FileOpResult move(const std::string& from, const std::string& to, bool overwrite = false);
    static FileOpResult ensureDir(const std::string& path);
    static FileOpResult list(const std::string& path, std::vector<std::string>& out, bool recursive = false);
    static bool exists(const std::string& path);
};

} // namespace Tools
} // namespace RawrXD
