#include "render_report.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

bool writeFrameReport(const std::string& path, const FrameFacts& facts, const char* frameName, int triangles) {
    FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "w") != 0 || !file) return false;
    std::fprintf(file, "{\n  \"schema\": \"rawrxd.render.frame.v1\",\n");
    std::fprintf(file, "  \"frame\": \"%s\",\n  \"resolution\": [%d, %d],\n", frameName ? frameName : "", facts.width, facts.height);
    std::fprintf(file, "  \"attachments\": {\n");
    std::fprintf(file, "    \"color\": \"READ\",\n    \"depth\": \"NOT_AVAILABLE\",\n");
    std::fprintf(file, "    \"normal\": \"NOT_AVAILABLE\",\n    \"object_id\": \"NOT_AVAILABLE\",\n");
    std::fprintf(file, "    \"motion\": \"NOT_AVAILABLE\"\n  },\n");
    std::fprintf(file, "  \"metrics\": {\n");
    if (triangles >= 0) std::fprintf(file, "    \"triangle_count\": %d,\n", triangles);
    else std::fprintf(file, "    \"triangle_count\": null,\n");
    std::fprintf(file, "    \"mean_luminance\": %.4f,\n", facts.meanLuminance);
    std::fprintf(file, "    \"exposure_clipped_fraction\": %.6f,\n", facts.clipHigh);
    std::fprintf(file, "    \"under_exposed_fraction\": %.6f,\n", facts.clipLow);
    std::fprintf(file, "    \"band_contrast\": [");
    for (int i = 0; i < 8; ++i) std::fprintf(file, "%s%.4f", i ? ", " : "", facts.bandContrast[i]);
    std::fprintf(file, "],\n    \"gpu_frame_ms\": null,\n    \"invalid_normal_count\": null\n  },\n");
    std::fprintf(file, "  \"findings\": [");
    if (facts.clipPixels > 0) {
        std::fprintf(file, "{\n      \"code\": \"EXPOSURE_CLIP\",\n      \"severity\": \"warning\",\n");
        std::fprintf(file, "      \"pass\": \"color\",\n      \"object_id\": null,\n");
        std::fprintf(file, "      \"pixel_region\": [%d, %d, %d, %d],\n", facts.clipX, facts.clipY, facts.clipW, facts.clipH);
        std::fprintf(file, "      \"measured_error\": %.6f,\n", facts.clipHigh);
        std::fprintf(file, "      \"suggested_investigation\": [\"exposure\", \"tone_map\"]\n    }");
    }
    std::fprintf(file, "]\n}\n");
    std::fclose(file);
    return true;
}

bool writeClipHeatmap(const std::string& path, const uint8_t* pixels, int width, int height, bool bgra) {
    if (!pixels || width < 1 || height < 1) return false;
    const int stride = (width * 3 + 3) & ~3;
    std::vector<uint8_t> rows(static_cast<size_t>(stride) * height);
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            const uint8_t* p = pixels + (static_cast<long long>(y) * width + x) * 4;
            int r = bgra ? p[2] : p[0], g = p[1], b = bgra ? p[0] : p[2];
            uint8_t* dst = rows.data() + static_cast<size_t>(height - 1 - y) * stride + x * 3;
            if (r >= 250 && g >= 250 && b >= 250) { dst[0] = 0; dst[1] = 0; dst[2] = 255; }
            else { auto lum = static_cast<uint8_t>(r * 0.2126 + g * 0.7152 + b * 0.0722); dst[0] = dst[1] = dst[2] = lum; }
        }
    }
    FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "wb") != 0 || !file) return false;
    uint8_t hdr[54] = {};
    hdr[0] = 'B'; hdr[1] = 'M';
    int size = 54 + stride * height;
    std::memcpy(hdr + 2, &size, 4);
    int off = 54; std::memcpy(hdr + 10, &off, 4);
    int hs = 40; std::memcpy(hdr + 14, &hs, 4);
    std::memcpy(hdr + 18, &width, 4); std::memcpy(hdr + 22, &height, 4);
    short planes = 1, bits = 24;
    std::memcpy(hdr + 26, &planes, 2); std::memcpy(hdr + 28, &bits, 2);
    std::fwrite(hdr, 1, 54, file);
    std::fwrite(rows.data(), 1, rows.size(), file);
    std::fclose(file);
    return true;
}
