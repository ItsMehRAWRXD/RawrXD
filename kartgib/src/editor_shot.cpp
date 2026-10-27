#include "editor_api.hpp"
#include "forensics_png.hpp"
#include "render_metrics.hpp"
#include "render_report.hpp"
#include <cstring>
#include <filesystem>
#include <iostream>
#include <string>

static EditorShot gShots[8];
static int gShotN = 0;
static uint64_t fnv(const uint8_t* p, int n) {
    uint64_t h = 14695981039346656037ull;
    for (int i = 0; i < n; i += 16) { h ^= p[i]; h *= 1099511628211ull; }
    return h;
}
static int tone(const uint8_t* p, int n, bool bgra, bool red) {
    int count = 0;
    for (int i = 0; i < n; ++i) {
        const uint8_t* s = p + i * 4;
        int b = bgra ? s[0] : s[2], g = s[1], r = bgra ? s[2] : s[0];
        if (red ? (r > 180 && g < 90 && b < 90) : (r > 220 && g > 220 && b > 220)) ++count;
    }
    return count;
}
void VulkanRenderer::freezeEditorTime() { editorFreeze_ = true; }
void VulkanRenderer::requestEditorShot(const char* name) {
    editorShot_ = true;
    std::memset(editorShotName_, 0, sizeof(editorShotName_));
    if (name) for (int i = 0; i < 15 && name[i]; ++i) editorShotName_[i] = name[i];
}
void VulkanRenderer::prepareEditorShot() {
    if (!editorShot_) return;
    readbackThisFrame_ = true;
    g04Label_ = "editor";
}
void VulkanRenderer::noteEditorShot(const uint8_t* pixels, bool bgra) {
    if (!editorShot_) return;
    int n = g04Width_ * g04Height_;
    uint64_t hash = fnv(pixels, n * 4);
    wchar_t modulePath[32768]{};
    GetModuleFileNameW(nullptr, modulePath, 32768);
    auto evidence = std::filesystem::path(modulePath).parent_path().parent_path().parent_path().parent_path() / "evidence";
    std::filesystem::create_directories(evidence);
    writeStoredPng(evidence / (std::string("kartgib_editor_") + editorShotName_ + ".png"), pixels, g04Width_, g04Height_, bgra);
    FrameFacts facts = measureColor(pixels, static_cast<int>(g04Width_), static_cast<int>(g04Height_), bgra);
    writeFrameReport((evidence / (std::string("render_frame_") + editorShotName_ + ".json")).string(), facts, editorShotName_, -1);
    if (gShotN < 8) {
        std::memset(gShots[gShotN].name, 0, 16);
        std::memcpy(gShots[gShotN].name, editorShotName_, 15);
        gShots[gShotN].hash = hash;
        gShots[gShotN].white = tone(pixels, n, bgra, false);
        gShots[gShotN].red = tone(pixels, n, bgra, true);
        int gold = 0;
        for (int i = 0; i < n; ++i) {
            const uint8_t* s = pixels + i * 4;
            int b = bgra ? s[0] : s[2], g = s[1], r = bgra ? s[2] : s[0];
            if (r > 220 && g > 180 && b < 80) ++gold;
        }
        gShots[gShotN].gold = gold;
        ++gShotN;
    }
    std::cout << "[EDITOR] shot=" << editorShotName_ << " hash=" << hash;
    if (gShotN > 0) std::cout << " white=" << gShots[gShotN - 1].white << " gold=" << gShots[gShotN - 1].gold;
    std::cout << std::endl;
    editorShot_ = false;
}
int editorShotCount() { return gShotN; }
const EditorShot* editorShotAt(int i) { return (i >= 0 && i < gShotN) ? &gShots[i] : nullptr; }
