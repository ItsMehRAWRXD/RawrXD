#include "CompressedWeightStore.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <future>
#include <mutex>
#include <thread>
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
 std::vector<std::uint8_t> output(input.size());
 constexpr std::size_t range_offset = 997;
 constexpr std::size_t range_length = 7000;
 REQUIRE(store.readRange("layer.0.weight",range_offset,output.data()+range_offset,range_length,&error));
 REQUIRE(std::equal(input.begin()+range_offset,
                    input.begin()+range_offset+range_length,
                    output.begin()+range_offset));

 // A slow source reader must not hold the store mutex: an existing inference
 // read must complete while another tensor is still being encoded/admitted.
 struct SlowReaderContext {
  const std::vector<std::uint8_t>* bytes;
  std::mutex mutex;
  std::condition_variable cv;
  bool entered=false;
  bool release=false;
 } slowContext{nullptr};
 std::vector<std::uint8_t> slowData(2u*1024u*1024u,static_cast<std::uint8_t>('S'));
 slowContext.bytes=&slowData;
 bool slowWriterOk=false;
 std::string slowWriterError;
 std::thread slowWriter([&] {
  slowWriterOk=store.addTensorFromReader(
   "slow.admission",slowData.size(),
   [](void* opaque,std::size_t offset,void* destination,std::size_t length)->bool {
    auto& ctx=*static_cast<SlowReaderContext*>(opaque);
    {
     std::unique_lock<std::mutex> lock(ctx.mutex);
     if(!ctx.entered) {
      ctx.entered=true;
      ctx.cv.notify_all();
      ctx.cv.wait(lock,[&]{return ctx.release;});
     }
    }
    if(length) std::memcpy(destination,ctx.bytes->data()+offset,length);
    return true;
   },
   &slowContext,&slowWriterError,rawrxd::compression::GGML_TYPE_OPAQUE,false);
 });
 bool slowReaderEntered=false;
 {
  std::unique_lock<std::mutex> lock(slowContext.mutex);
  slowReaderEntered=slowContext.cv.wait_for(
   lock,std::chrono::seconds(5),[&]{return slowContext.entered;});
 }
 if(!slowReaderEntered) {
  {
   std::lock_guard<std::mutex> lock(slowContext.mutex);
   slowContext.release=true;
  }
  slowContext.cv.notify_all();
  slowWriter.join();
  REQUIRE(slowReaderEntered);
 }
 std::vector<std::uint8_t> concurrentRead(range_length);
 auto readFuture=std::async(std::launch::async,[&] {
  std::string readError;
  return store.readRange("layer.0.weight",range_offset,
                         concurrentRead.data(),concurrentRead.size(),&readError);
 });
 const bool readCompletedDuringAdmission =
  readFuture.wait_for(std::chrono::seconds(2))==std::future_status::ready;
 {
  std::lock_guard<std::mutex> lock(slowContext.mutex);
  slowContext.release=true;
 }
 slowContext.cv.notify_all();
 slowWriter.join();
 REQUIRE(readCompletedDuringAdmission);
 REQUIRE(readFuture.get());
 REQUIRE(slowWriterOk);
 REQUIRE(concurrentRead==std::vector<std::uint8_t>(
  input.begin()+range_offset,input.begin()+range_offset+range_length));

 // Exercise simultaneous range reads across overlapping encoded blocks.
 std::vector<std::future<bool>> concurrentReaders;
 for(std::size_t worker=0;worker<8;++worker) {
  concurrentReaders.emplace_back(std::async(std::launch::async,[&,worker] {
   const std::size_t offset=(worker*127u)%(input.size()-257u);
   const std::size_t length=257u+worker*31u;
   std::vector<std::uint8_t> bytes(length);
   std::string readError;
   if(!store.readRange("layer.0.weight",offset,bytes.data(),bytes.size(),&readError))
    return false;
   return std::equal(bytes.begin(),bytes.end(),input.begin()+offset);
  }));
 }
 for(auto& reader:concurrentReaders) REQUIRE(reader.get());
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

 // Lossy F32->F16 admission is allowed only inside the caller's absolute
 // error tolerance and can reject non-finite source values transactionally.
 bool precisionRejected=false;
 const float exactF32[]={1.0f,2.0f,4.0f};
 REQUIRE(store.addTensorF32AsF16FromReader(
  "fp16.exact",exactF32,3,&error,
  (std::numeric_limits<std::size_t>::max)(),0.0f,true,&precisionRejected));
 REQUIRE(!precisionRejected);
 const float inexactF32[]={1.0001f};
 precisionRejected=false;
 REQUIRE(!store.addTensorF32AsF16FromReader(
  "fp16.too_inexact",inexactF32,1,&error,
  (std::numeric_limits<std::size_t>::max)(),0.0f,true,&precisionRejected));
 REQUIRE(precisionRejected&&!store.contains("fp16.too_inexact"));
 const float nonFiniteF32[]={std::numeric_limits<float>::infinity()};
 precisionRejected=false;
 REQUIRE(!store.addTensorF32AsF16FromReader(
  "fp16.non_finite",nonFiniteF32,1,&error,
  (std::numeric_limits<std::size_t>::max)(),
  (std::numeric_limits<float>::infinity)(),true,&precisionRejected));
 REQUIRE(precisionRejected&&!store.contains("fp16.non_finite"));
 const float overflowF32[]={1.0e20f};
 precisionRejected=false;
 REQUIRE(!store.addTensorF32AsF16FromReader(
  "fp16.overflow",overflowF32,1,&error,
  (std::numeric_limits<std::size_t>::max)(),
  (std::numeric_limits<float>::infinity)(),true,&precisionRejected));
 REQUIRE(precisionRejected&&!store.contains("fp16.overflow"));
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
 const auto s=store.stats();REQUIRE(s.tensors==7&&s.raw_bytes==input.size()+random_data.size()+sizeof(q4_payload)+14+6+slowData.size());
 REQUIRE(s.f32_to_f16_tensors==2&&s.f32_source_bytes==40);REQUIRE(s.compressed_bytes<s.raw_bytes);
 REQUIRE(s.encoded_capacity_bytes>=s.compressed_bytes);
 REQUIRE(s.metadata_bytes_estimate>0);
 REQUIRE(s.resident_bytes_estimate>=s.encoded_capacity_bytes);
 REQUIRE(s.resident_bytes_estimate>=s.metadata_bytes_estimate);
 REQUIRE(s.resident_bytes_estimate==s.encoded_capacity_bytes+s.metadata_bytes_estimate+s.cached_decoded_bytes);
 std::cout<<"CompressedWeightStore PASS tensors="<<s.tensors<<" blocks="<<s.blocks<<" raw="<<s.raw_bytes<<" encoded="<<s.compressed_bytes<<" resident_estimate="<<s.resident_bytes_estimate<<'\n';
}
