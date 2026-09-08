#pragma once
#include <string>
#include <vector>
namespace rawr::product {

struct FileExplorer {
    std::vector<std::string> files;
    void add(const std::string& path) { files.push_back(path); }
};

} // namespace rawr::product
