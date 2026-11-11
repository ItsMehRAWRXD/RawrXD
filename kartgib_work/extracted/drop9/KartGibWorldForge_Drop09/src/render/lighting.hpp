#pragma once
#include "render/hdr.hpp"
#include <array>
#include <cstdint>
#include <string>
#include <vector>
namespace kg::render {
struct Vec3 {float x=0,y=0,z=0;};
struct Mat4 {std::array<float,16> m{};}; // column-major, Vulkan clip convention
struct Light {Vec3 direction{-.4f,-1.f,-.3f}; Rgb color{1,1,1}; float intensity=3.f;};
struct PointLight {Vec3 position{}; Rgb color{1,1,1}; float intensity=1,range=10;};
struct ShadowMap {uint32_t width=0,height=0;std::vector<float> depth; bool valid() const;};
struct Cascades {std::vector<float> splits;};
struct ShadowSettings {float bias=.0015f,normalBias=.002f;uint32_t pcfRadius=1;float cascadeLambda=.65f;};
struct LightingSettings {float ambient=.07f;ShadowSettings shadow{};};
// Drop 04: 15 independent portable lighting and shadow reference functions.
float dot(Vec3 a,Vec3 b); // 01
Vec3 normalize(Vec3 v); // 02
Vec3 transformPoint(Mat4 m,Vec3 v); // 03
Mat4 orthographic(float left,float right,float bottom,float top,float nearPlane,float farPlane); // 04
Mat4 lookAt(Vec3 eye,Vec3 target,Vec3 up); // 05
Cascades cascadeSplits(float nearPlane,float farPlane,uint32_t count,float lambda); // 06
uint32_t chooseCascade(float viewDepth,const Cascades& cascades); // 07
float slopeBias(Vec3 normal,Vec3 lightDirection,ShadowSettings settings); // 08
float sampleShadowNearest(const ShadowMap& map,float u,float v,float receiverDepth,float bias); // 09
float sampleShadowPcf(const ShadowMap& map,float u,float v,float receiverDepth,float bias,uint32_t radius); // 10
float lambert(Vec3 normal,Vec3 towardLight); // 11
float ggxDistribution(float ndoth,float roughness); // 12
float smithGeometry(float ndotv,float ndotl,float roughness); // 13
Rgb shadeDirectional(Rgb albedo,Vec3 normal,Vec3 viewDirection,Light sun,float roughness,float metallic,float visibility,float ambient); // 14
Rgb shadePoint(Rgb albedo,Vec3 worldPosition,Vec3 normal,PointLight light); // 15
bool validateShadowSettings(const ShadowSettings& settings,std::string* error=nullptr);
}
