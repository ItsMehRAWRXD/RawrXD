#pragma once
#include <cstdint>

struct FrameFacts {
    int width = 0;
    int height = 0;
    double meanLuminance = 0;
    double clipHigh = 0;
    double clipLow = 0;
    double bandContrast[8] = {};
    int clipX = 0, clipY = 0, clipW = 0, clipH = 0;
    int clipPixels = 0;
};

FrameFacts measureColor(const uint8_t* pixels, int width, int height, bool bgra);
