#pragma once
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {

struct ModelDownloadProgress {
    int64_t bytesDownloaded = 0;
    int64_t totalBytes = 0;
    std::string status;
};

class ModelSourceResolver {
public:
    std::string Resolve(const std::string& args, std::function<void(const ModelDownloadProgress&)> progress);
    bool isResolved() const;
    std::string getPath() const;
};

class StreamingGGUFLoader {
public:
    bool load(const std::string& path);
    bool isLoaded() const;
    void unload();
};

} // namespace RawrXD
