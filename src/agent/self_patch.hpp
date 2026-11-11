#pragma once
#include <string>
#include <memory>
#include <vector>

class ISnapshotEngine;

class SelfPatch {
public:
    SelfPatch();
    ~SelfPatch();

    // Set snapshot engine for pre-write capture (optional; null = no capture)
    void setSnapshotEngine(std::unique_ptr<ISnapshotEngine> engine);

    // Add Vulkan kernel from template
    bool addKernel(const std::string& name, const std::string& templateName);

    // Add C++ wrapper for kernel
    bool addCpp(const std::string& name, const std::string& deps);

    // Patch existing file
    bool patchFile(const std::string& filename, const std::string& patch);

private:
    std::unique_ptr<ISnapshotEngine> m_snapshotEngine;
};
