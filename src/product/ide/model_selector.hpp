#pragma once
#include <cstring>
#include <string>
#include <vector>
namespace rawr::product {

struct ModelSelector {
    std::vector<std::string> aliases;
    uint32_t index = 0;
    void add(const char* alias) {
        if (alias && alias[0]) aliases.push_back(alias);
    }
    const char* current() const {
        if (index >= aliases.size()) return "";
        return aliases[index].c_str();
    }
};

enum { IDC_PRODUCT_MODEL = 4011 };

} // namespace rawr::product
