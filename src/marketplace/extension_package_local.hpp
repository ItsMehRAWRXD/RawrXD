#pragma once
// Local extension package install — top-25 IDE formats, no cloud/HTTP dependency.

#include "extension_marketplace.hpp"
#include <string>

namespace RawrXD {
namespace Extensions {
namespace Local {

ExtResult InstallPackage(const std::string& packagePath);
const IdeExtensionFormatInfo* IdeCatalog(size_t& outCount);
ExtensionPackageFormat DetectFormat(const std::string& packagePath);
const char* FormatName(ExtensionPackageFormat fmt);
std::wstring BuildInstallFileFilter();

}  // namespace Local
}  // namespace Extensions
}  // namespace RawrXD
