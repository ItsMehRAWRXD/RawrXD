#pragma once
#include <cstdint>
#include <filesystem>

bool writeStoredPng(const std::filesystem::path& path, const uint8_t* pixels,
    uint32_t width, uint32_t height, bool bgra);
