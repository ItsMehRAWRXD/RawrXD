// ============================================================================
// ZeroCopySurface.hpp - GPU Zero-Copy Surface for Direct Memory Mapping
// Maps GPU buffers directly into CPU address space for zero-serialization rendering
// ============================================================================

#pragma once

#include <cstdint>
#include <memory>
#include <functional>

namespace Sovereign {

// Surface memory type
enum class SurfaceMemoryType {
    DEFAULT,        // GPU-optimal
    UPLOAD,         // CPU write, GPU read
    READBACK,       // GPU write, CPU read
    CROSS_ADAPTER   // Shared across adapters
};

// Surface mapping
struct SurfaceMapping {
    void* cpuAddress;
    uint64_t gpuAddress;
    uint64_t size;
    uint32_t rowPitch;
    bool isMapped;
    bool isCoherent;
};

// Zero-copy surface
class ZeroCopySurface {
public:
    ZeroCopySurface();
    ~ZeroCopySurface();

    // Initialize
    bool Initialize(uint32_t width, uint32_t height, SurfaceMemoryType type = SurfaceMemoryType::DEFAULT);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Mapping
    SurfaceMapping Map();
    void Unmap();
    bool IsMapped() const { return mapped_; }

    // Direct pixel access
    void* GetPixelPointer() { return mapping_.cpuAddress; }
    uint32_t GetRowPitch() const { return mapping_.rowPitch; }

    // Zero-copy blit from GPU buffer
    bool BlitFromGPU(uint64_t srcGPUAddress, uint32_t srcWidth, uint32_t srcHeight);
    bool BlitToGPU(uint64_t dstGPUAddress, uint32_t dstWidth, uint32_t dstHeight);

    // Clear
    void Clear(uint32_t color = 0xFF000000); // ARGB

    // Fill rect
    void FillRect(int x, int y, int w, int h, uint32_t color);

    // Copy from CPU buffer
    bool CopyFromCPU(const void* data, uint32_t width, uint32_t height);
    bool CopyToCPU(void* data, uint32_t width, uint32_t height);

    // Properties
    uint32_t GetWidth() const { return width_; }
    uint32_t GetHeight() const { return height_; }
    uint64_t GetSize() const { return size_; }
    uint64_t GetGPUAddress() const { return mapping_.gpuAddress; }
    void* GetCPUAddress() const { return mapping_.cpuAddress; }

    // Statistics
    uint64_t GetBytesTransferred() const { return bytesTransferred_; }
    void ResetStats() { bytesTransferred_ = 0; }

private:
    bool initialized_ = false;
    bool mapped_ = false;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
    uint64_t size_ = 0;
    SurfaceMemoryType memoryType_ = SurfaceMemoryType::DEFAULT;
    SurfaceMapping mapping_;
    uint64_t bytesTransferred_ = 0;
    
    // GPU resource handle
    void* resource_ = nullptr;
    void* heap_ = nullptr;
};

// GPU-accelerated text rasterizer
class GPUTextRasterizer {
public:
    GPUTextRasterizer();
    ~GPUTextRasterizer();

    // Initialize with font data
    bool Initialize(const void* fontData, size_t fontSize, float dpiScale = 1.0f);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Glyph rendering
    bool RenderGlyph(uint32_t codepoint, float size, uint8_t* bitmap, uint32_t& width, uint32_t& height);
    bool RenderGlyphToSurface(ZeroCopySurface& surface, uint32_t codepoint, float size, int x, int y, uint32_t color);

    // Text rendering
    bool RenderText(ZeroCopySurface& surface, const char* text, float size, int x, int y, uint32_t color);
    bool RenderTextW(ZeroCopySurface& surface, const wchar_t* text, float size, int x, int y, uint32_t color);

    // Text measurement
    void MeasureText(const char* text, float size, float& width, float& height);
    void MeasureTextW(const wchar_t* text, float size, float& width, float& height);

    // Font atlas
    bool BuildAtlas(float size, const uint32_t* codepoints, size_t count);
    bool BindAtlas(ZeroCopySurface& atlas);

    // Properties
    float GetDPIScale() const { return dpiScale_; }
    float GetLineHeight(float size) const;

private:
    bool initialized_ = false;
    float dpiScale_ = 1.0f;
    
    // Font face handle
    void* fontFace_ = nullptr;
    void* library_ = nullptr;
    
    // Glyph cache
    struct GlyphCacheEntry {
        uint32_t codepoint;
        float size;
        uint32_t atlasX;
        uint32_t atlasY;
        uint32_t width;
        uint32_t height;
        float advanceX;
        float bearingX;
        float bearingY;
    };
    std::vector<GlyphCacheEntry> glyphCache_;
    
    // Atlas
    ZeroCopySurface atlas_;
    bool atlasBuilt_ = false;
};

} // namespace Sovereign
