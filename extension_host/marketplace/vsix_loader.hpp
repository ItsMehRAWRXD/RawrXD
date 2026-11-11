// vsix_loader.hpp — VSIX Package Loader
#pragma once
#include <string>
#include <filesystem>
#include <optional>

namespace RawrXD {
namespace ExtensionHost {

struct VSIXManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string publisher;
    std::string description;
    std::string engineVersion;
    std::vector<std::string> dependencies;
    std::vector<std::string> permissions;
};

class VSIXLoader {
public:
    // Load VSIX package from file
    static std::optional<VSIXManifest> Load(const std::filesystem::path& vsixPath);

    // Extract VSIX to destination
    static bool Extract(const std::filesystem::path& vsixPath, const std::filesystem::path& destDir);

    // Validate VSIX signature
    static bool ValidateSignature(const std::filesystem::path& vsixPath);

    // Get VSIX metadata without extracting
    static std::optional<VSIXManifest> Peek(const std::filesystem::path& vsixPath);

private:
    static bool Unzip(const std::filesystem::path& zipPath, const std::filesystem::path& destDir);
    static std::optional<VSIXManifest> ParseManifest(const std::filesystem::path& manifestPath);
};

} // namespace ExtensionHost
} // namespace RawrXD
