// Minimal SOURCE_WIRED local package — InstallPackage/IdeCatalog only.
// Honest limited: local filesystem copy; no cloud/HTTP; CERTIFIED=0.
#include "extension_package_local.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Extensions {
namespace Local {

namespace {

static const IdeExtensionFormatInfo kCatalog[] = {
    {"vsix", "VS Code / Cursor VSIX"},
    {"rawrpkg", "RawrXD Plugin"},
    {"dll", "Native DLL"},
};

std::string installRoot() {
#ifdef _WIN32
    const char* la = std::getenv("LOCALAPPDATA");
    if (la && la[0])
        return std::string(la) + "\\RawrXD\\extensions\\";
#endif
    return "extensions/";
}

}  // namespace

ExtResult InstallPackage(const std::string& packagePath) {
    ExtResult r;
    if (packagePath.empty() || !fs::exists(packagePath)) {
        r.success = false;
        r.message = "Package not found";
        return r;
    }
    try {
        const std::string root = installRoot();
        fs::create_directories(root);
        const fs::path src(packagePath);
        const fs::path dest = fs::path(root) / src.filename();
        if (fs::is_directory(src)) {
            fs::copy(src, dest,
                     fs::copy_options::recursive | fs::copy_options::overwrite_existing);
        } else {
            fs::copy_file(src, dest, fs::copy_options::overwrite_existing);
        }
        {
            std::ofstream meta(dest.string() + ".rawrxd_local.txt");
            if (meta)
                meta << "SOURCE_WIRED_LIMITED\npath=" << packagePath << "\n";
        }
        r.success = true;
        r.message = "Installed (local limited): " + dest.string();
    } catch (const std::exception& ex) {
        r.success = false;
        r.message = std::string("Install failed: ") + ex.what();
    }
    return r;
}

const IdeExtensionFormatInfo* IdeCatalog(size_t& outCount) {
    outCount = sizeof(kCatalog) / sizeof(kCatalog[0]);
    return kCatalog;
}

}  // namespace Local
}  // namespace Extensions
}  // namespace RawrXD
