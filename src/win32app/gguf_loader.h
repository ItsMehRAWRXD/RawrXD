#pragma once

#include <string>

class GGUFLoader {
public:
    GGUFLoader() = default;
    ~GGUFLoader() = default;

    bool Load(const std::string& modelPath) {
        (void)modelPath;
        return false;
    }

    void Unload() {
    }
};
