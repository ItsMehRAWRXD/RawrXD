#pragma once
#include <iterator>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <windows.h>

inline std::vector<char> readShaderFile(const std::string& filename) {
    wchar_t modulePath[32768] = {};
    DWORD length = GetModuleFileNameW(nullptr, modulePath, static_cast<DWORD>(std::size(modulePath)));
    if (length == 0 || length >= std::size(modulePath)) {
        throw std::runtime_error("Failed to resolve executable path");
    }
    auto shaderPath = std::filesystem::path(std::wstring(modulePath, length)).parent_path()
        / "shaders" / filename;
    std::ifstream file(shaderPath, std::ios::ate | std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open shader: " << shaderPath.string() << std::endl;
        return {};
    }
    std::vector<char> buffer(static_cast<size_t>(file.tellg()));
    file.seekg(0);
    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    return buffer;
}
