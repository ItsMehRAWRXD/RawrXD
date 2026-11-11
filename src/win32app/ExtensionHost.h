// ExtensionHost.h — Extension Host (Batch 5 X04)
#pragma once

#include <string>
#include <vector>
#include <memory>

class ExtensionHost {
public:
    ExtensionHost();
    ~ExtensionHost();

    bool Start();
    void Stop();
    bool LoadExtension(const std::string& extensionPath);
    void UnloadExtension(const std::string& extensionId);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
