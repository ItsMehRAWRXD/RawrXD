#include "CompressedWeightStore.hpp"
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iostream>
#include <limits>
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
 assert(store.addTensor("random",random_data.data(),random_data.size(),&error));
 assert(!store.addTensor("random.no_gain",random_data.data(),random_data.size(),&error,
                        rawrxd::compression::GGML_TYPE_OPAQUE,true,random_data.size()));
 assert(!store.contains("random.no_gain"));
 std::vector<std::uint8_t> random_out(random_data.size());
 assert(store.readRange("random",0,random_out.data(),random_out.size(),&error));assert(random_data==random_out);
 const float f32[]={1.0f,-2.0f,65504.0f,0.00006103515625f,0.0f,std::numeric_limits<float>::infinity(),std::numeric_limits<float>::quiet_NaN()};
 assert(store.addTensorF32AsF16("fp16.weights",f32,7,&error));
 assert(store.tensorType("fp16.weights")==rawrxd::compression::GGML_TYPE_F16);
 assert(store.tensorBytes("fp16.weights")==14);
 std::uint16_t half[7]={};assert(store.readRange("fp16.weights",0,half,sizeof(half),&error));
 assert(half[0]==0x3C00u&&half[1]==0xC000u&&half[2]==0x7BFFu&&half[3]==0x0400u&&half[4]==0u&&half[5]==0x7C00u&&(half[6]&0x7E00u)==0x7E00u);
 assert(rawrxd::compression::floatToHalfRNE(1.00048828125f)==0x3C00u); // halfway rounds to even
 assert(rawrxd::compression::floatToHalfRNE(1.00146484375f)==0x3C02u); // odd halfway rounds up
 assert(store.addTensor("empty",nullptr,0,&error));assert(store.tensorBlocks("empty")==0);assert(store.readRange("empty",0,nullptr,0,&error));
 const auto s=store.stats();assert(s.tensors==4&&s.raw_bytes==input.size()+random_data.size()+14);assert(s.compressed_bytes<s.raw_bytes);
 std::cout<<"CompressedWeightStore PASS tensors="<<s.tensors<<" blocks="<<s.blocks<<" raw="<<s.raw_bytes<<" encoded="<<s.compressed_bytes<<'\n';
}