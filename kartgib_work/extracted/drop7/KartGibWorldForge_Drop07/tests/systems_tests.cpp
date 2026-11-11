#include "systems.hpp"
#include <cassert>
#include <cmath>
#include <filesystem>
#include <iostream>
int main(){kg::Settings s;s.seed=20261025;s.terrainResolution=33;s.trackSamples=64;s.propCount=100;auto w=kg::generate(s);using namespace kg::systems;
assert(validateMesh(w.terrain)&&validateMesh(w.road)&&validateMesh(w.props));
assert(bounds(w.terrain).hi.x>bounds(w.terrain).lo.x);
auto m=w.terrain;recalculateNormals(m);assert(validateMesh(m));
assert(triangleCount(w)>0);
auto hit=raycast(w.terrain,{{0,1000,0},{0,-1,0}});assert(hit.hit);
assert(std::isfinite(sampleTerrain(w,0,0)));
assert(checkpoints(w,4).size()==4);
assert(nearestTrackPoint(w,w.track[3].center)==3);
assert(std::abs(lapProgress(w,w.track[16].center)-.25)<1e-12);
assert(weather(42,10).rain==weather(42,10).rain);
assert(sunlight(12).intensity>sunlight(0).intensity);
assert(chaseCamera({0,0,0},0,80).fovDegrees>65);
assert(chooseLod(0)==0&&chooseLod(500)==3);
auto cells=buildPropGrid(w,64);size_t sum=0;for(auto&c:cells)sum+=c.propIndices.size();assert(sum==w.instances.size());
assert(assess(w,100).pass);
assert(biomeMaterials(s.biome)[0].roughness>0);
auto file=std::filesystem::temp_directory_path()/"kartgib_scene_test.json";exportSceneReport(w,file);assert(std::filesystem::file_size(file)>50);std::filesystem::remove(file);
std::cout<<"WORLD_FORGE_DROP02_15_SYSTEMS_PASS\n";}
