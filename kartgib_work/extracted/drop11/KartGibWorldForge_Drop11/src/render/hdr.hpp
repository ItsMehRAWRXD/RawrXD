#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
namespace kg::render {
struct Rgb { float r=0,g=0,b=0; };
struct Image { uint32_t width=0,height=0; std::vector<Rgb> pixels; bool valid() const; Rgb& at(uint32_t x,uint32_t y); const Rgb& at(uint32_t x,uint32_t y) const; };
struct Exposure { float ev=0, middleGray=.18f; };
struct BloomSettings { float threshold=1.0f, knee=.5f, strength=.12f; uint32_t radius=3; };
struct RenderSettings { Exposure exposure; BloomSettings bloom; bool bloomEnabled=true; };
struct Viewport { uint32_t x=0,y=0,width=0,height=0; };
struct FrameMetrics { uint64_t pixels=0, clippedChannels=0; float maxLuminance=0, averageLuminance=0; };
// 15 portable reference functions for validating the matching Vulkan implementation.
float luminance(Rgb c);                                // 01
float exposureScale(Exposure e);                       // 02
Rgb applyExposure(Rgb c, Exposure e);                 // 03
Rgb acesToneMap(Rgb c);                               // 04
float linearToSrgb(float c);                          // 05
Rgb encodeSrgb(Rgb c);                                // 06
Rgb bloomPrefilter(Rgb c, BloomSettings s);          // 07
Image downsample2x(const Image& source);              // 08
Image upsampleBilinear(const Image& source,uint32_t width,uint32_t height); // 09
Image blurSeparable(const Image& source,uint32_t radius); // 10
Image makeBloom(const Image& source,BloomSettings s); // 11
Image composite(const Image& hdr,const Image& bloom,RenderSettings settings); // 12
FrameMetrics analyze(const Image& hdr);               // 13
bool validateSettings(RenderSettings s,std::string* error=nullptr); // 14
std::array<float,4> viewportNormalized(Viewport v,uint32_t width,uint32_t height); // 15
// Asset-free image export for CPU golden references.
bool writePpm(const Image& image,const std::string& path);
}
