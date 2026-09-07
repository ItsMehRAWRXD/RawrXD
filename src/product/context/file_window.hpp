#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace rawr::product {

struct EditorSnap {
    std::string path;
    std::string language;
    std::string prefix;
    std::string suffix;
    std::string selected;
    uint32_t line = 1;
    uint32_t col = 1;
    std::vector<std::string> openFiles;
    std::vector<std::string> diagnostics;
};

struct FileWindow {
    std::string path;
    std::string before;
    std::string after;
    uint32_t cursorLine = 1;
    uint32_t radius = 80;

    static FileWindow fromSnap(const EditorSnap& e, uint32_t radius = 80) {
        FileWindow w;
        w.path = e.path;
        w.cursorLine = e.line;
        w.radius = radius;
        w.before = e.prefix;
        w.after = e.suffix;
        if (w.before.size() > 8000) w.before.erase(0, w.before.size() - 8000);
        if (w.after.size() > 4000) w.after.resize(4000);
        return w;
    }
};

} // namespace rawr::product
