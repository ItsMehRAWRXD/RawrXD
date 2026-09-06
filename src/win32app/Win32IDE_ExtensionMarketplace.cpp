#include "extension_package_local.hpp"

namespace RawrXD::IDE {

bool InstallExtensionPackage(const char* packagePath) {
    if (!packagePath) return false;
    return Extensions::Local::InstallPackage(packagePath).success;
}

int ExtensionIdeCatalogCount() {
    size_t n = 0;
    Extensions::Local::IdeCatalog(n);
    return static_cast<int>(n);
}

}  // namespace RawrXD::IDE

extern "C" {

bool RawrXD_IDE_InstallVsix(const char* vsixPath) {
    return RawrXD::IDE::InstallExtensionPackage(vsixPath);
}

bool RawrXD_IDE_InstallExtensionPackage(const char* packagePath) {
    return RawrXD::IDE::InstallExtensionPackage(packagePath);
}

bool RawrXD_IDE_SetExtensionEnabled(const char*, bool) { return false; }

int RawrXD_IDE_ExtensionCount() { return 0; }

int RawrXD_IDE_TopIdeExtensionCatalogCount() {
    return RawrXD::IDE::ExtensionIdeCatalogCount();
}

}
