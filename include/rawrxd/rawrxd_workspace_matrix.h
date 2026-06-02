#pragma once
#include <cstdint>
#include <cstddef>

// Types are defined in rawrxd_text_engine.h and rawrxd_linestream_raster.h
#include "rawrxd_text_engine.h"
#include "rawrxd_linestream_raster.h"

namespace rawrxd::ui {
    
    struct LineStripCacheWorkspace {
        int cellWidth = 8;
        int cellHeight = 16;
    };
    
    struct SovereignWorkspaceController {
        static std::size_t requiredArenaBytes(std::uint32_t maxLines, 
                                               std::int32_t cellWidth, 
                                               std::int32_t cellHeight, 
                                               std::uint32_t maxCharsPerLine);
        
        bool initialize(void* arenaBuffer, 
                       std::size_t arenaSize,
                       std::uint32_t maxLines,
                       std::int32_t cellWidth,
                       std::int32_t cellHeight,
                       std::uint32_t maxCharsPerLine);
        
        void shutdown();
        
        void invalidateLineStructure(std::uint32_t lineIndex, std::uint32_t lineVersion);
        
        void synchronizeDirtyStrips(LineStreamWorkspace* stream,
                                    DocumentLine* lines,
                                    std::uint32_t lineCount,
                                    const SyntaxColorRun** runTable,
                                    std::uint32_t* runCounts,
                                    bool forceSync);
        
        LineStripCacheWorkspace workspaceProxy() const;
    };
    
    bool lineStripCacheEnabled();
    
    bool fillLineRenderBatchFromWin32Tokens(LineRenderBatch* batch,
                                           const std::string& lineText,
                                           int lineStartOffset,
                                           const void* tokens,
                                           std::size_t tokenCount,
                                           std::size_t tokenSize);
    
    std::uint32_t exportBatchToSyntaxColorRuns(const LineRenderBatch& batch,
                                               SyntaxColorRun* runStorage,
                                               std::uint32_t* runCount);
    
    void clearSoftwareSurfaceRect(void* surface, std::uint32_t color, void* rect);
    
    void renderViewportLineStrips(void* surface,
                                  const LineStripCacheWorkspace* workspace,
                                  const std::uint32_t* visibleLines,
                                  std::uint32_t visibleCount,
                                  int horzScroll,
                                  int viewportStartY,
                                  bool enabled);
} // namespace rawrxd::ui
