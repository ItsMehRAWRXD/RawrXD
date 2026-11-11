#include "render_metrics.hpp"
#include <cmath>

FrameFacts measureColor(const uint8_t* pixels, int width, int height, bool bgra) {
    FrameFacts facts;
    facts.width = width;
    facts.height = height;
    if (!pixels || width <= 0 || height <= 0) return facts;
    const int count = width * height;
    double sum = 0;
    int high = 0, low = 0;
    int minX = width, minY = height, maxX = -1, maxY = -1;
    double bandSum[8] = {};
    double bandSq[8] = {};
    int bandN[8] = {};
    for (int y = 0; y < height; ++y) {
        int band = y * 8 / height;
        if (band > 7) band = 7;
        for (int x = 0; x < width; ++x) {
            const uint8_t* p = pixels + (static_cast<long long>(y) * width + x) * 4;
            int r = bgra ? p[2] : p[0];
            int g = p[1];
            int b = bgra ? p[0] : p[2];
            double lum = r * 0.2126 + g * 0.7152 + b * 0.0722;
            sum += lum;
            bandSum[band] += lum;
            bandSq[band] += lum * lum;
            bandN[band] += 1;
            if (r >= 250 && g >= 250 && b >= 250) {
                ++high;
                if (x < minX) minX = x;
                if (y < minY) minY = y;
                if (x > maxX) maxX = x;
                if (y > maxY) maxY = y;
            } else if (r <= 4 && g <= 4 && b <= 4) {
                ++low;
            }
        }
    }
    facts.meanLuminance = sum / count;
    facts.clipHigh = static_cast<double>(high) / count;
    facts.clipLow = static_cast<double>(low) / count;
    facts.clipPixels = high;
    if (high > 0) {
        facts.clipX = minX;
        facts.clipY = minY;
        facts.clipW = maxX - minX + 1;
        facts.clipH = maxY - minY + 1;
    }
    for (int i = 0; i < 8; ++i) {
        if (bandN[i] < 1) continue;
        double mean = bandSum[i] / bandN[i];
        double var = bandSq[i] / bandN[i] - mean * mean;
        facts.bandContrast[i] = std::sqrt(var < 0 ? 0 : var);
    }
    return facts;
}
