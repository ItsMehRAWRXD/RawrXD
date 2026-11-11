// ProductExtensionRuntime_Manifest.cpp — real manifest load (fail-closed).
#include "ProductExtensionRuntime_Internal.hpp"
#include <fstream>
#include <sstream>

namespace ProductExtensionRuntime {

std::string LoadManifestPath(const std::string& pathOrVsix) {
    if (pathOrVsix.empty()) {
        return "{\"success\":false,\"error\":\"missing_path\","
               "\"adapter\":\"product_extension_runtime\"}";
    }
    std::filesystem::path p(pathOrVsix);
    ExtRecord rec;
    if (std::filesystem::is_directory(p)) {
        if (!ReadPackageJson(p, rec)) {
            return "{\"success\":false,\"error\":\"manifest_not_found\","
                   "\"adapter\":\"product_extension_runtime\"}";
        }
    } else if (p.filename() == "package.json" || p.filename() == "extension.json") {
        if (!ReadPackageJson(p.parent_path(), rec)) {
            return "{\"success\":false,\"error\":\"manifest_parse_failed\","
                   "\"adapter\":\"product_extension_runtime\"}";
        }
    } else {
        // Real fail-closed: missing/unsupported vsix is not invent-ack.
        if (!std::filesystem::exists(p)) {
            return "{\"success\":false,\"error\":\"vsix_or_path_missing\","
                   "\"path\":\"" + Escape(pathOrVsix) +
                   "\",\"adapter\":\"product_extension_runtime\"}";
        }
        return "{\"success\":false,\"error\":\"vsix_extract_unsupported\","
               "\"hint\":\"pass extension directory or package.json\","
               "\"adapter\":\"product_extension_runtime\"}";
    }
    {
        std::lock_guard<std::mutex> lock(Mu());
        Exts()[rec.id] = rec;
        Host().extensionsLoaded = static_cast<int>(Exts().size());
    }
    return "{\"success\":true,\"id\":\"" + Escape(rec.id) +
           "\",\"manifest\":{\"name\":\"" + Escape(rec.name) +
           "\",\"version\":\"" + Escape(rec.version) +
           "\",\"publisher\":\"" + Escape(rec.publisher) +
           "\",\"path\":\"" + Escape(rec.path) +
           "\"},\"adapter\":\"product_extension_runtime\"}";
}

} // namespace ProductExtensionRuntime
