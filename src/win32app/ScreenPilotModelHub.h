#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD::ScreenPilot {

struct ModelRecommend {
    const char* id;
    const char* label;
    const char* sizeHint;
    const char* purpose;
    const char* lane;
};

struct LocalModelEntry {
    std::string fileName;
    std::string fullPath;
    uint64_t bytes = 0;
};

class ModelHub {
public:
    static const std::vector<ModelRecommend>& topRecommendations();
    static std::vector<std::string> storageRoots();
    static std::vector<LocalModelEntry> scanLocalInventory(size_t maxEntries = 128);
    static LocalModelEntry findByFileName(const std::string& name,
                                          const std::vector<LocalModelEntry>& inv);
};

}  // namespace RawrXD::ScreenPilot
