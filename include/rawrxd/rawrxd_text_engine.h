#pragma once

#include <string>
#include <cstdint>

namespace rawrxd::ui {
    struct SyntaxColorRun {
        int offset;
        int byteOffset;
        int length;
        std::uint32_t color;
    };

    struct DocumentLine {
        std::string text;
        const char* rawBufferStart = nullptr;
        std::uint32_t lengthBytes = 0;
        std::uint32_t lineVersion = 0;
    };

    struct TextLineSpan {
        const char* textStart;
        std::uint32_t length;
    };

    struct RenderBufferWorkspace {
        std::uint32_t poolCount;
        TextLineSpan* visibleLinesPool;
    };

    struct TextLayoutViewport {
        struct {
            int left;
            int top;
            int right;
            int bottom;
        } renderBounds;
        int scrollOffsetX;
        int scrollOffsetY;
        std::uint32_t firstVisibleLine;
        std::uint32_t lastVisibleLine;
    };

    struct AgentVirtualCursor {
        int line;
        int column;
    };

    struct LineRenderBatch {
        int lineIndex;
        int tokenCount;
    };
} // namespace rawrxd::ui
