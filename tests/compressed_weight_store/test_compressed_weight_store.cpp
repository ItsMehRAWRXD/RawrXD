#include "CompressedWeightStore.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <random>
#include <vector>
using rawrxd::compression::CompressedWeightStore;
int main(){
 CompressedWeightStore store(4096,1024);std::vector<std::uint8_t> input(8193);
 for(std::size_t i=0;i<input.size();++i)input[i]=static_cast<std::uint8_t>((i/97)%13);
 std::string error;assert(store.addTensor("layer.0.weight",input.data(),input.size(),&error));
 assert(!store.addTensor("layer.0.weight",input.data(),input.size(),&error));assert(store.tensorBlocks("layer.0.weight")==9);
 std::vector<std::uint8_t> output(input.size());assert(store.readRange("layer.0.weight",997,output.data()+997,7000,&error));
 assert(std::equal(input.begin()+997,input.end(),output.begin()+997));
 auto lease=store.acquireBlock("layer.0.weight",0,&error);assert(lease&&lease->size()==1024);store.setDecodedCacheBudget(0);assert((*lease)[0]==input[0]);
 assert(!store.readRange("layer.0.weight",input.size(),output.data(),1,&error));
 std::vector<std::uint8_t> random_data(4096);std::mt19937 rng(7);for(auto& b:random_data)b=static_cast<std::uint8_t>(rng());
 assert(store.addTensor("random",random_data.data(),random_data.size(),&error));std::vector<std::uint8_t> random_out(random_data.size());
 assert(store.readRange("random",0,random_out.data(),random_out.size(),&error));assert(random_data==random_out);
 const auto s=store.stats();assert(s.tensors==2&&s.raw_bytes==input.size()+random_data.size());
 std::cout<<"CompressedWeightStore PASS tensors="<<s.tensors<<" blocks="<<s.blocks<<" raw="<<s.raw_bytes<<" encoded="<<s.compressed_bytes<<'\n';
}