#pragma once
#include "worldforge.hpp"
#include <cstdint>
#include <filesystem>
#include <vector>
namespace kg::assets {
struct Bounds { Vec3 min{},max{}; };
struct Placement { uint32_t asset=0; Vec3 position{}; double yaw=0,scale=1; };
struct Catalog { std::vector<Mesh> meshes; std::vector<Placement> placements; };
uint64_t hash(uint64_t value);
double random01(uint64_t value);
Mesh box(double width,double height,double depth);
Mesh cylinder(double radius,double height,int sides);
Mesh cone(double radius,double height,int sides);
Mesh tree(uint64_t seed,int branches=7);
Mesh palm(uint64_t seed);
Mesh rock(uint64_t seed);
Mesh house(uint64_t seed);
Mesh tower(uint64_t seed);
Mesh bridge(uint64_t seed);
Mesh arch(uint64_t seed);
Mesh fence(uint64_t seed);
Bounds bounds(const Mesh& mesh);
void translate(Mesh& mesh,Vec3 offset);
void merge(Mesh& dst,const Mesh& src,Vec3 offset);
Catalog generate(uint64_t seed,Biome biome,int count);
void exportObj(const Catalog& catalog,const std::filesystem::path& path);
void exportManifest(const Catalog& catalog,const std::filesystem::path& path);
}
