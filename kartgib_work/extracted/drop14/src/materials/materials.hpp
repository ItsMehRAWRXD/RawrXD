#pragma once
#include <array>
#include <cstdint>
#include <vector>
namespace kartgib::materials {
struct Vec3 { float x{},y{},z{}; };
struct Pixel { float r{},g{},b{},a{1}; };
struct PBR { Vec3 albedo{}; float roughness{.8f},metallic{},ao{1},emissive{}; };
enum class Surface { Asphalt, RoadLine, Kerb, Stone, Rock, Sand, Grass, Snow, PaintedMetal, BareMetal, Neon, Dirt, Foliage, Water, Glass };
struct TextureSet { int width{},height{}; std::vector<Pixel> albedo, normal, orm, emissive; };
struct Config { int width{256},height{256}; uint32_t seed{1}; Surface surface{Surface::Asphalt}; float scale{8.f}; };
uint32_t hash2(int x,int y,uint32_t seed);                     // 1
float noise2(float x,float y,uint32_t seed);                  // 2
float fbm(float x,float y,uint32_t seed,int octaves=5);      // 3
float voronoi(float x,float y,uint32_t seed);                 // 4
float smoothstep(float a,float b,float x);                   // 5
PBR preset(Surface surface);                                 // 6
float asphalt_grain(float x,float y,uint32_t seed);          // 7
float road_marking(float u,float v);                         // 8
float kerb_stripes(float u,float v);                         // 9
float stone_mortar(float u,float v);                         // 10
float terrain_blend(float height,float slope);               // 11
float metal_wear(float u,float v,uint32_t seed);             // 12
Vec3 normal_from_height(const std::vector<float>& h,int w,int ht,int x,int y,float strength); // 13
TextureSet bake(const Config& config);                       // 14
bool write_ppm(const char* path,const TextureSet& t);       // 15
}
