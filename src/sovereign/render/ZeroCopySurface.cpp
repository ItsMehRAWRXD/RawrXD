// ============================================================================
// ZeroCopySurface.cpp - GPU Zero-Copy Surface Implementation
// ============================================================================

#include "ZeroCopySurface.hpp"
#include <cstring>
#include <algorithm>
#include <iostream>

namespace Sovereign {

ZeroCopySurface::ZeroCopySurface() = default;
ZeroCopySurface::~ZeroCopySurface() {
    Shutdown();
}

bool ZeroCopySurface::Initialize(uint32_t width, uint32_t height, SurfaceMemoryType type) {
    if (initialized_) Shutdown();
    
    width_ = width;
    height_ = height;
    memoryType_ = type;
    size_ = width * height * 4; // 4 bytes per pixel (ARGB)
    
    // Allocate GPU resource
    // In production: CreateCommittedResource with D3D12_HEAP_TYPE_DEFAULT/UPLOAD/READBACK
    // For now, allocate a CPU-side buffer that simulates the zero-copy path
    
    mapping_.cpuAddress = malloc(size_);
    if (!mapping_.cpuAddress) return false;
    
    mapping_.gpuAddress = reinterpret_cast<uint64_t>(mapping_.cpuAddress);
    mapping_.size = size_;
    mapping_.rowPitch = width * 4;
    mapping_.isMapped = true;
    mapping_.isCoherent = true;
    
    mapped_ = true;
    initialized_ = true;
    
    Clear(0xFF1E1E1E); // Default dark background
    
    return true;
}

void ZeroCopySurface::Shutdown() {
    if (mapping_.cpuAddress) {
        free(mapping_.cpuAddress);
        mapping_.cpuAddress = nullptr;
    }
    mapping_.gpuAddress = 0;
    mapping_.size = 0;
    mapping_.rowPitch = 0;
    mapping_.isMapped = false;
    initialized_ = false;
    mapped_ = false;
}

SurfaceMapping ZeroCopySurface::Map() {
    if (!initialized_) return {};
    mapped_ = true;
    return mapping_;
}

void ZeroCopySurface::Unmap() {
    mapped_ = false;
}

bool ZeroCopySurface::BlitFromGPU(uint64_t srcGPUAddress, uint32_t srcWidth, uint32_t srcHeight) {
    if (!initialized_) return false;
    // In production: CopyTextureRegion from GPU buffer to surface
    bytesTransferred_ += srcWidth * srcHeight * 4;
    return true;
}

bool ZeroCopySurface::BlitToGPU(uint64_t dstGPUAddress, uint32_t dstWidth, uint32_t dstHeight) {
    if (!initialized_) return false;
    bytesTransferred_ += dstWidth * dstHeight * 4;
    return true;
}

void ZeroCopySurface::Clear(uint32_t color) {
    if (!mapping_.cpuAddress) return;
    uint32_t* pixels = static_cast<uint32_t*>(mapping_.cpuAddress);
    std::fill(pixels, pixels + (width_ * height_), color);
}

void ZeroCopySurface::FillRect(int x, int y, int w, int h, uint32_t color) {
    if (!mapping_.cpuAddress) return;
    
    int x0 = std::max(0, x);
    int y0 = std::max(0, y);
    int x1 = std::min(static_cast<int>(width_), x + w);
    int y1 = std::min(static_cast<int>(height_), y + h);
    
    uint32_t* pixels = static_cast<uint32_t*>(mapping_.cpuAddress);
    for (int row = y0; row < y1; ++row) {
        std::fill(pixels + row * width_ + x0, pixels + row * width_ + x1, color);
    }
}

bool ZeroCopySurface::CopyFromCPU(const void* data, uint32_t width, uint32_t height) {
    if (!initialized_ || !data) return false;
    uint32_t copyW = std::min(width, width_);
    uint32_t copyH = std::min(height, height_);
    
    uint32_t* src = static_cast<uint32_t*>(const_cast<void*>(data));
    uint32_t* dst = static_cast<uint32_t*>(mapping_.cpuAddress);
    
    for (uint32_t row = 0; row < copyH; ++row) {
        memcpy(dst + row * width_, src + row * width, copyW * 4);
    }
    
    bytesTransferred_ += copyW * copyH * 4;
    return true;
}

bool ZeroCopySurface::CopyToCPU(void* data, uint32_t width, uint32_t height) {
    if (!initialized_ || !data) return false;
    uint32_t copyW = std::min(width, width_);
    uint32_t copyH = std::min(height, height_);
    
    uint32_t* src = static_cast<uint32_t*>(mapping_.cpuAddress);
    uint32_t* dst = static_cast<uint32_t*>(data);
    
    for (uint32_t row = 0; row < copyH; ++row) {
        memcpy(dst + row * width, src + row * width_, copyW * 4);
    }
    
    bytesTransferred_ += copyW * copyH * 4;
    return true;
}

// ============================================================
// GPUTextRasterizer
// ============================================================

GPUTextRasterizer::GPUTextRasterizer() = default;
GPUTextRasterizer::~GPUTextRasterizer() {
    Shutdown();
}

bool GPUTextRasterizer::Initialize(const void* fontData, size_t fontSize, float dpiScale) {
    if (initialized_) Shutdown();
    
    dpiScale_ = dpiScale;
    
    // In production: FT_Init_FreeType, FT_New_Memory_Face
    // For now, set up the rasterizer state
    
    initialized_ = true;
    return true;
}

void GPUTextRasterizer::Shutdown() {
    glyphCache_.clear();
    initialized_ = false;
}

bool GPUTextRasterizer::RenderGlyph(uint32_t codepoint, float size, uint8_t* bitmap, uint32_t& width, uint32_t& height) {
    if (!initialized_) return false;
    
    // In production: FT_Load_Glyph, FT_Render_Glyph
    // For now, return a simple placeholder glyph
    
    width = size * 0.6f;
    height = size;
    
    if (bitmap) {
        memset(bitmap, 0xFF, width * height);
    }
    
    return true;
}

bool GPUTextRasterizer::RenderGlyphToSurface(ZeroCopySurface& surface, uint32_t codepoint, float size, int x, int y, uint32_t color) {
    if (!initialized_) return false;
    
    uint32_t gw, gh;
    if (!RenderGlyph(codepoint, size, nullptr, gw, gh)) return false;
    
    surface.FillRect(x, y, gw, gh, color);
    return true;
}

bool GPUTextRasterizer::RenderText(ZeroCopySurface& surface, const char* text, float size, int x, int y, uint32_t color) {
    if (!initialized_ || !text) return false;
    
    int cursorX = x;
    int cursorY = y;
    
    while (*text) {
        uint32_t codepoint = static_cast<unsigned char>(*text);
        RenderGlyphToSurface(surface, codepoint, size, cursorX, cursorY, color);
        cursorX += size * 0.6f;
        text++;
    }
    
    return true;
}

bool GPUTextRasterizer::RenderTextW(ZeroCopySurface& surface, const wchar_t* text, float size, int x, int y, uint32_t color) {
    if (!initialized_ || !text) return false;
    
    int cursorX = x;
    int cursorY = y;
    
    while (*text) {
        RenderGlyphToSurface(surface, *text, size, cursorX, cursorY, color);
        cursorX += size * 0.6f;
        text++;
    }
    
    return true;
}

void GPUTextRasterizer::MeasureText(const char* text, float size, float& width, float& height) {
    width = strlen(text) * size * 0.6f;
    height = size;
}

void GPUTextRasterizer::MeasureTextW(const wchar_t* text, float size, float& width, float& height) {
    width = wcslen(text) * size * 0.6f;
    height = size;
}

bool GPUTextRasterizer::BuildAtlas(float size, const uint32_t* codepoints, size_t count) {
    if (!initialized_) return false;
    
    // Build a font atlas texture
    uint32_t atlasSize = 512;
    if (!atlas_.Initialize(atlasSize, atlasSize)) return false;
    
    uint32_t cursorX = 0;
    uint32_t cursorY = 0;
    uint32_t maxRowHeight = 0;
    
    for (size_t i = 0; i < count; ++i) {
        uint32_t gw, gh;
        if (!RenderGlyph(codepoints[i], size, nullptr, gw, gh)) continue;
        
        if (cursorX + gw > atlasSize) {
            cursorX = 0;
            cursorY += maxRowHeight;
            maxRowHeight = 0;
        }
        
        GlyphCacheEntry entry;
        entry.codepoint = codepoints[i];
        entry.size = size;
        entry.atlasX = cursorX;
        entry.atlasY = cursorY;
        entry.width = gw;
        entry.height = gh;
        glyphCache_.push_back(entry);
        
        cursorX += gw + 1;
        maxRowHeight = std::max(maxRowHeight, gh);
    }
    
    atlasBuilt_ = true;
    return true;
}

bool GPUTextRasterizer::BindAtlas(ZeroCopySurface& atlas) {
    if (!atlasBuilt_) return false;
    atlas = atlas_;
    return true;
}

float GPUTextRasterizer::GetLineHeight(float size) const {
    return size * 1.2f;
}

} // namespace Sovereign
