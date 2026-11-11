#include "render_metrics.hpp"
#include "render_report.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static bool sameFacts(const FrameFacts& a, const FrameFacts& b) {
    return a.clipPixels == b.clipPixels && a.clipX == b.clipX && a.clipY == b.clipY
        && a.clipW == b.clipW && a.clipH == b.clipH;
}

int main() {
    const int width = 64, height = 64;
    std::vector<uint8_t> clean(static_cast<size_t>(width) * height * 4, 40);
    std::vector<uint8_t> defect = clean;
    const int x0 = 10, y0 = 12, w = 8, h = 6;
    for (int y = y0; y < y0 + h; ++y) {
        for (int x = x0; x < x0 + w; ++x) {
            uint8_t* p = defect.data() + (static_cast<size_t>(y) * width + x) * 4;
            p[0] = p[1] = p[2] = p[3] = 255;
        }
    }
    FrameFacts plain = measureColor(clean.data(), width, height, false);
    FrameFacts once = measureColor(defect.data(), width, height, false);
    FrameFacts twice = measureColor(defect.data(), width, height, false);
    bool found = once.clipPixels == w * h && once.clipX == x0 && once.clipY == y0
        && once.clipW == w && once.clipH == h && plain.clipPixels == 0 && sameFacts(once, twice);
    const char* dir = "F:/rawrxd/kartgib/evidence";
    std::string report = std::string(dir) + "/render_intro_defect.json";
    std::string heat = std::string(dir) + "/render_intro_defect_heat.bmp";
    bool wrote = writeFrameReport(report, once, "injected_clip", -1);
    bool mapped = writeClipHeatmap(heat, defect.data(), width, height, false);
    std::printf("DEFECT_FOUND=%d REGION=%d,%d,%d,%d REPEAT=%d REPORT=%d HEAT=%d PLAIN_CLIP=%d\n",
        found ? 1 : 0, once.clipX, once.clipY, once.clipW, once.clipH,
        sameFacts(once, twice) ? 1 : 0, wrote ? 1 : 0, mapped ? 1 : 0, plain.clipPixels);
    return found && wrote && mapped ? 0 : 1;
}
