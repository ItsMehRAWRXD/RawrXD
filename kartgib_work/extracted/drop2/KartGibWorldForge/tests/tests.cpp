#include "worldforge.hpp"
#include <cassert>
#include <cmath>
#include <iostream>
int main(){kg::Settings s;s.seed=123;s.terrainResolution=33;s.trackSamples=64;s.propCount=40;for(auto b:{kg::Biome::Tropical,kg::Biome::Gothic,kg::Biome::Voxel,kg::Biome::Floating}){s.biome=b;auto a=kg::generate(s),c=kg::generate(s);assert(a.terrain.vertices.size()==1089);assert(a.track.size()==64);assert(a.road.indices.size()==64*6);assert(a.terrain.indices.size()==32*32*6);assert(a.closureResidual==0);assert(a.headingError==0);assert(a.terrain.vertices[42].p.y==c.terrain.vertices[42].p.y);assert(a.props.indices.size()==c.props.indices.size());for(auto&v:a.terrain.vertices)assert(std::isfinite(v.p.y));}std::cout<<"WORLD_FORGE_TESTS_PASS\n";}
