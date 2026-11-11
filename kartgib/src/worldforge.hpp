#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
namespace kg {
struct Vec3 { double x=0,y=0,z=0; };
struct Vertex { Vec3 p,n; float u=0,v=0; };
struct Mesh { std::string name; std::vector<Vertex> vertices; std::vector<uint32_t> indices; };
enum class Biome { Tropical, Gothic, Voxel, Floating };
struct Settings { uint64_t seed=42; Biome biome=Biome::Tropical; int terrainResolution=129; int trackSamples=256; double worldSize=2048; int propCount=800; };
struct TrackPoint { Vec3 center; double heading=0, width=12; };
struct Prop { Vec3 position; uint8_t kind=0; double scale=1; };
struct World { Settings settings; Mesh terrain,road,props; std::vector<TrackPoint> track; std::vector<Prop> instances; double closureResidual=0, headingError=0; };
World generate(const Settings&);
double sampleHeight(double x, double z, const Settings&);
void exportObj(const World&, const std::filesystem::path&);
void exportHeightmap(const World&, const std::filesystem::path&);
void exportManifest(const World&, const std::filesystem::path&);
std::string biomeName(Biome);
Biome parseBiome(const std::string&);
}
