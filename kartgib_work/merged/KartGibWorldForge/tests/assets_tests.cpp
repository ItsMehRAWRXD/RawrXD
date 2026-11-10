#include "assets/assets.hpp"
#include <cassert>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace kg::assets;
int main(){auto a=generate(42,kg::Biome::Tropical,50),b=generate(42,kg::Biome::Tropical,50);assert(a.meshes.size()==8&&a.placements.size()==50);for(size_t i=0;i<a.placements.size();i++){assert(a.placements[i].asset==b.placements[i].asset);assert(a.placements[i].position.x==b.placements[i].position.x);}for(auto&m:a.meshes){assert(!m.vertices.empty()&&!m.indices.empty());for(auto idx:m.indices)assert(idx<m.vertices.size());auto bb=bounds(m);assert(bb.min.y<=bb.max.y);}auto c=box(2,3,4);assert(c.indices.size()==36);auto cy=cylinder(1,2,12);assert(cy.indices.size()==12*12);auto co=cone(1,2,8);assert(co.indices.size()==8*6);bool threw=false;try{box(-1,1,1);}catch(const std::invalid_argument&){threw=true;}assert(threw);threw=false;try{generate(1,kg::Biome::Tropical,-1);}catch(const std::invalid_argument&){threw=true;}assert(threw);auto p=std::filesystem::temp_directory_path()/"kg_assets_test.obj",j=std::filesystem::temp_directory_path()/"kg_assets_test.json";exportObj(a,p);exportManifest(a,j);assert(std::filesystem::file_size(p)>100&&std::filesystem::file_size(j)>100);std::filesystem::remove(p);std::filesystem::remove(j);std::cout<<"ASSET_TEST_PASS\n";}
