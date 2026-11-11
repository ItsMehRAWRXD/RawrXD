#pragma once
#include "worldforge.hpp"
#include <array>
#include <string>
#include <vector>
namespace kg::systems {
struct Bounds { Vec3 lo,hi; };
struct Ray { Vec3 origin,direction; };
struct Hit { bool hit=false; double distance=0; Vec3 point; };
struct Weather { double cloud=0,rain=0,fog=0,wind=0; };
struct Sun { Vec3 direction; double intensity=0; };
struct Camera { Vec3 eye,target; double fovDegrees=70; };
struct Material { const char* name; double roughness,metallic,emission; };
struct Checkpoint { Vec3 center; double radius=0; };
struct Quality { bool pass=false; int invalidTriangles=0; double maximumGrade=0; double minimumWidth=0; std::string reason; };
struct Cell { int x=0,z=0; std::vector<uint32_t> propIndices; };
// Fifteen standalone deterministic runtime/editor building blocks.
// 01: Mesh index/finite validation.
bool validateMesh(const Mesh& m);
// 02: Mesh axis-aligned bounds.
Bounds bounds(const Mesh& m);
// 03: Recompute triangle-weighted vertex normals.
void recalculateNormals(Mesh& m);
// 04: Triangle count for profiling.
size_t triangleCount(const World& w);
// 05: Ray/triangle mesh intersection (CPU picking).
Hit raycast(const Mesh& m, Ray ray, double maxDistance=1e9);
// 06: Bilinear terrain height query.
double sampleTerrain(const World& w,double x,double z);
// 07: Track checkpoint generation.
std::vector<Checkpoint> checkpoints(const World& w,int count);
// 08: Nearest track point index.
size_t nearestTrackPoint(const World& w,Vec3 position);
// 09: Normalized lap progress from track index.
double lapProgress(const World& w,Vec3 position);
// 10: Seeded weather state.
Weather weather(uint64_t seed,double timeSeconds);
// 11: Time-of-day directional sunlight.
Sun sunlight(double hour);
// 12: Chase-camera target (stateless).
Camera chaseCamera(Vec3 position,double heading,double speed);
// 13: Distance-based mesh LOD level.
int chooseLod(double distance,double bias=1.0);
// 14: Prop spatial grid for visibility queries.
std::vector<Cell> buildPropGrid(const World& w,double cellSize);
// 15: Conservative geometry/track quality gate.
Quality assess(const World& w,double maximumGrade=1.0);
std::array<Material,4> biomeMaterials(Biome biome);
void exportSceneReport(const World& w,const std::filesystem::path& path);
}
