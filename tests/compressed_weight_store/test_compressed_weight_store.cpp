#include "CompressedWeightStore.hpp"
#include <algorithm>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <limits>
#include <random>
#include <vector>
using rawrxd::compression::CompressedWeightStore;

// Keep test checks active in Release builds (NDEBUG disables assert()).
#define REQUIRE(condition) do { \
    if (!(condition)) { \
        std::cerr << "FAIL: " #condition << " at " << __FILE__ << ':' << __LINE__ << '\n'; \
        return 1; \
    } \
} while (false)

static float halfToFloat(std::uint16_t h) {
 std::uint32_t sign=std::uint32_t(h&0x8000u)<<16;
 std::uint32_t exp=(h>>10)&0x1fu;
 std::uint32_t mant=h&0x03ffu;
 std::uint32_t bits=0;
 if(exp==0) {
  if(mant==0) bits=sign;
  else {
   int e=-14;
   while((mant&0x0400u)==0) { mant<<=1; --e; }
   mant&=0x03ffu;
   bits=sign|(std::uint32_t(e+127)<<23)|(mant<<13);
  }
 } else if(exp==31) {
  bits=sign|0x7f800000u|(mant<<13);
 } else {
  bits=sign|((exp+112u)<<23)|(mant<<13);
 }
 float value=0.0f;
 std::memcpy(&value,&bits,sizeof(value));
 return value;
}

int main(){
 CompressedWeightStore store(4096,1024);std::vector<std::uint8_t> input(8193);
 for(std::size_t i=0;i<input.size();++i)input[i]=static_cast<std::uint8_t>((i/97)%13);
 std::string error;REQUIRE(store.addTensor("layer.0.weight",input.data(),input.size(),&error));
 REQUIRE(!store.addTensor("layer.0.weight",input.data(),input.size(),&error));REQUIRE(store.tensorBlocks("layer.0.weight")==9);
 std::vector<std::uint8_t> output(input.size());REQUIRE(store.readRange("layer.0.weight",997,output.data()+997,7000,&error));
 REQUIRE(std::equal(input.begin()+997,input.end(),output.begin()+997));
 auto lease=store.acquireBlock("layer.0.weight",0,&error);REQUIRE(lease&&lease->size()==1024);store.setDecodedCacheBudget(0);REQUIRE((*lease)[0]==input[0]);
 REQUIRE(!store.readRange("layer.0.weight",input.size(),output.data(),1,&error));
 std::vector<std::uint8_t> random_data(4096);std::mt19937 rng(7);for(auto& b:random_data)b=static_cast<std::uint8_t>(rng());
 REQUIRE(store.addTensor("random",random_data.data(),random_data.size(),&error));
 REQUIRE(!store.addTensor("random.no_gain",random_data.data(),random_data.size(),&error,
                        rawrxd::compression::GGML_TYPE_OPAQUE,true,random_data.size()));
 REQUIRE(!store.contains("random.no_gain"));
 std::vector<std::uint8_t> random_out(random_data.size());
 REQUIRE(store.readRange("random",0,random_out.data(),random_out.size(),&error));REQUIRE(random_data==random_out);
 const float f32[]={1.0f,-2.0f,65504.0f,0.00006103515625f,0.0f,std::numeric_limits<float>::infinity(),std::numeric_limits<float>::quiet_NaN()};
 const std::uint8_t q4_payload[18]={0x00}; // one packed Q4_0 block payload
 REQUIRE(store.addTensor("quant.q4_0",q4_payload,sizeof(q4_payload),&error,2u));
 REQUIRE(store.tensorType("quant.q4_0")==2u); // GGML_TYPE_Q4_0
 std::uint8_t q4_roundtrip[sizeof(q4_payload)]={};
 REQUIRE(store.readRange("quant.q4_0",0,q4_roundtrip,sizeof(q4_roundtrip),&error));
 REQUIRE(std::equal(q4_payload,q4_payload+sizeof(q4_payload),q4_roundtrip));
 REQUIRE(store.addTensorF32AsF16("fp16.weights",f32,7,&error));
 REQUIRE(store.tensorType("fp16.weights")==rawrxd::compression::GGML_TYPE_F16);
 REQUIRE(store.tensorBytes("fp16.weights")==14);
 std::uint16_t half[7]={};REQUIRE(store.readRange("fp16.weights",0,half,sizeof(half),&error));
 REQUIRE(half[0]==0x3C00u&&half[1]==0xC000u&&half[2]==0x7BFFu&&half[3]==0x0400u&&half[4]==0u&&half[5]==0x7C00u&&(half[6]&0x7E00u)==0x7E00u);
 REQUIRE(rawrxd::compression::floatToHalfRNE(1.00048828125f)==0x3C00u); // halfway rounds to even
 REQUIRE(rawrxd::compression::floatToHalfRNE(1.00146484375f)==0x3C02u); // odd halfway rounds up
 REQUIRE(rawrxd::compression::floatToHalfRNE(0x1.0p-25f)==0x0000u); // exact subnormal midpoint rounds to even zero
 REQUIRE(rawrxd::compression::floatToHalfRNE(0x1.8p-25f)==0x0001u); // above midpoint rounds to minimum subnormal
 // Exhaustively round-trip every binary16 encoding. Signaling NaNs are
 // intentionally quieted; finite values, infinities and signed zero retain
 // their exact representation.
 for(std::uint32_t bits=0;bits<=0xffffu;++bits) {
  const auto h=static_cast<std::uint16_t>(bits);
  const auto roundTrip=rawrxd::compression::floatToHalfRNE(halfToFloat(h));
  const auto expected=((h&0x7c00u)==0x7c00u && (h&0x03ffu)!=0)
      ? static_cast<std::uint16_t>(h|0x0200u) : h;
  REQUIRE(roundTrip==expected);
 }
 REQUIRE(store.addTensor("empty",nullptr,0,&error));REQUIRE(store.tensorBlocks("empty")==0);REQUIRE(store.readRange("empty",0,nullptr,0,&error));
 const auto s=store.stats();REQUIRE(s.tensors==5&&s.raw_bytes==input.size()+random_data.size()+sizeof(q4_payload)+14);REQUIRE(s.compressed_bytes<s.raw_bytes);
 std::cout<<"CompressedWeightStore PASS tensors="<<s.tensors<<" blocks="<<s.blocks<<" raw="<<s.raw_bytes<<" encoded="<<s.compressed_bytes<<'\n';
}