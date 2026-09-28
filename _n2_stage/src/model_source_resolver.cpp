#include "model_source_resolver.h"

namespace RawrXD {

static std::string s_resolvedPath;
static bool s_resolved = false;
static bool s_loaded = false;

std::string ModelSourceResolver::Resolve(const std::string& args,
    std::function<void(const ModelDownloadProgress&)> progress) {
    s_resolvedPath = args;
    s_resolved = true;
    if (progress) {
        progress(ModelDownloadProgress{});
    }
    return s_resolvedPath;
}

bool ModelSourceResolver::isResolved() const {
    return s_resolved;
}

std::string ModelSourceResolver::getPath() const {
    return s_resolvedPath;
}

bool StreamingGGUFLoader::load(const std::string& path) {
    s_loaded = true;
    return true;
}

bool StreamingGGUFLoader::isLoaded() const {
    return s_loaded;
}

void StreamingGGUFLoader::unload() {
    s_loaded = false;
}

} // namespace RawrXD
