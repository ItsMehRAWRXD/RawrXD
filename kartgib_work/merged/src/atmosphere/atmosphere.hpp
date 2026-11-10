#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace kartgib::atmosphere {
struct Vec3 {float x{},y{},z{};};
struct SkySettings {Vec3 sunDirection{.3f,.8f,.2f}; float turbidity{2.5f}, cloudCoverage{.45f}, cloudScale{2.5f}, fogDensity{.012f}, waterLevel{0}; uint32_t seed{42};};
struct Image {int width{},height{}; std::vector<Vec3> rgb;};
float saturate(float x);                                          // 01
Vec3 normalize(Vec3 v);                                          // 02
float dot(Vec3 a,Vec3 b);                                        // 03
float hash3(int x,int y,int z,uint32_t seed);                    // 04
float noise3(float x,float y,float z,uint32_t seed);             // 05
float fbm3(float x,float y,float z,uint32_t seed);               // 06
Vec3 skyColor(Vec3 view,SkySettings s);                          // 07
float sunDisc(Vec3 view,Vec3 sun,float angularRadius=.012f);     // 08
float cloudDensity(Vec3 position,SkySettings s);                // 09
float cloudShadow(Vec3 position,SkySettings s);                 // 10
float fogTransmittance(float distance,float density);           // 11
Vec3 applyFog(Vec3 scene,Vec3 fog,float distance,float density);// 12
float waterHeight(float x,float z,float time,uint32_t seed);     // 13
Vec3 waterNormal(float x,float z,float time,uint32_t seed);     // 14
Image renderSky(int width,int height,SkySettings s);            // 15
bool writePpm(const Image& image,const std::string& path);
}
