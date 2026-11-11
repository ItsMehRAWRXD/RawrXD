#pragma once
// Minimal local extension package surface for Native Win32IDE link.
// SOURCE_WIRED for InstallPackage/IdeCatalog — not marketplace CERTIFIED.

#include <cstddef>
#include <string>

namespace RawrXD {
namespace Extensions {
namespace Local {

struct ExtResult {
    bool success = false;
    std::string message;
};

struct IdeExtensionFormatInfo {
    const char* id;
    const char* name;
};

ExtResult InstallPackage(const std::string& packagePath);
const IdeExtensionFormatInfo* IdeCatalog(size_t& outCount);

}  // namespace Local
}  // namespace Extensions
}  // namespace RawrXD
