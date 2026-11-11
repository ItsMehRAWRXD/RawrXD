#pragma once
#include "render_metrics.hpp"
#include <string>

bool writeFrameReport(const std::string& path, const FrameFacts& facts, const char* frameName, int triangles);
bool writeClipHeatmap(const std::string& path, const uint8_t* pixels, int width, int height, bool bgra);
