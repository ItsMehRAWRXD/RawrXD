// rawrxd_text_engine.h — Stub for build compatibility
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <windows.h>

namespace rawrxd {
namespace ui {

struct SyntaxColorRun {
    uint32_t start = 0;
    uint32_t length = 0;
    COLORREF color = 0;
};

struct DocumentLine {
    std::string text;
    uint32_t lineNumber = 0;
};

struct TextLayoutViewport {
    int32_t firstVisibleLine = 0;
    int32_t visibleLineCount = 0;
    int32_t charWidth = 0;
    int32_t lineHeight = 0;
};

struct RenderBufferWorkspace {
    std::vector<DocumentLine> lines;
};

struct LineStreamWorkspace {
    void initialize() {}
};

struct SovereignWorkspaceController {
    void initialize() {}
};

struct AgentVirtualCursor {
    int32_t line = 0;
    int32_t column = 0;
};

struct TextEngine {
    void initialize() {}
};

} // namespace ui
} // namespace rawrxd
