#pragma once
#include "deep2_sha256.hpp"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

namespace deep2 {
static constexpr uint32_t D2E_TRACE_VERSION=1;
static constexpr uint32_t D2E_GLOBAL=0xffffffffu;
static constexpr uint32_t D2E_NO_LAYER=0xffffffffu;

enum class E2EEvent : uint32_t {
    DISCOVER=1, OPEN=2, BACKEND_DEEP2=3, TOKENIZE_DONE=4, WEIGHT_TOUCH=5,
    FORWARD_LAYER=6, KV_COMMIT=7, LOGITS_READY=8, SAMPLE=9, DETOKENIZE=10,
    STREAM=11, SYNTHETIC=12, PROXY=13, FALLBACK=14, END=15
};
#pragma pack(push,1)
struct TraceHeader {
    char magic[8]; uint32_t version; uint32_t header_bytes; uint32_t layers;
    uint32_t max_generated_tokens; uint32_t min_generated_tokens; uint32_t model_files;
    uint64_t prompt_tokens; char model_name[160]; char reserved[80];
};
struct ModelRecord { char path[768]; uint64_t claimed_bytes; uint8_t claimed_sha256[32]; };
struct EventRecord {
    uint64_t seq; uint32_t type; uint32_t token_index; uint32_t layer_index; int64_t token_id;
    uint64_t value0; uint64_t value1; uint32_t payload_bytes; uint32_t reserved;
};
#pragma pack(pop)

class E2ETraceWriter {
    std::ofstream f_; std::mutex mu_; uint64_t seq_=0; bool ok_=false;
public:
    bool open(const std::string& trace,const std::string& model,uint32_t layers,uint32_t max_gen,uint32_t min_gen,
              uint64_t prompt_tokens,const std::vector<std::string>& model_files){
        std::lock_guard<std::mutex> g(mu_); f_.open(trace,std::ios::binary|std::ios::trunc); if(!f_)return false;
        TraceHeader h{};std::memcpy(h.magic,"D2E2TRC",7);h.version=D2E_TRACE_VERSION;h.header_bytes=sizeof(h);h.layers=layers;
        h.max_generated_tokens=max_gen;h.min_generated_tokens=min_gen;h.model_files=(uint32_t)model_files.size();h.prompt_tokens=prompt_tokens;
        std::strncpy(h.model_name,model.c_str(),sizeof(h.model_name)-1);f_.write((char*)&h,sizeof(h));
        for(const auto& p:model_files){ModelRecord r{};std::strncpy(r.path,p.c_str(),sizeof(r.path)-1);std::array<uint8_t,32>d{};uint64_t n=0;
            if(!sha256_file(p,d,&n)) return false;
            r.claimed_bytes=n;
            std::memcpy(r.claimed_sha256,d.data(),32);
            f_.write((char*)&r,sizeof(r));
        }
        ok_=(bool)f_;return ok_;
    }
    bool event(E2EEvent t,uint32_t tok=D2E_GLOBAL,uint32_t layer=D2E_NO_LAYER,int64_t token_id=-1,
               uint64_t v0=0,uint64_t v1=0,const void* payload=nullptr,uint32_t payload_bytes=0){
        std::lock_guard<std::mutex>g(mu_);if(!ok_)return false;EventRecord e{};e.seq=++seq_;e.type=(uint32_t)t;e.token_index=tok;e.layer_index=layer;
        e.token_id=token_id;e.value0=v0;e.value1=v1;e.payload_bytes=payload_bytes;f_.write((char*)&e,sizeof(e));if(payload_bytes)f_.write((const char*)payload,payload_bytes);
        f_.flush();return (bool)f_;
    }
    bool discover(){return event(E2EEvent::DISCOVER);} bool opened(){return event(E2EEvent::OPEN);} bool backend(){return event(E2EEvent::BACKEND_DEEP2);}
    bool tokenized(uint64_t n){return event(E2EEvent::TOKENIZE_DONE,D2E_GLOBAL,D2E_NO_LAYER,-1,n);}
    bool weight_touch(uint64_t bytes){return event(E2EEvent::WEIGHT_TOUCH,D2E_GLOBAL,D2E_NO_LAYER,-1,bytes);}
    bool forward(uint32_t tok,uint32_t layer){return event(E2EEvent::FORWARD_LAYER,tok,layer);}
    bool kv(uint32_t tok,uint32_t layer=D2E_NO_LAYER){return event(E2EEvent::KV_COMMIT,tok,layer);}
    bool logits(uint32_t tok,uint64_t vocab){return event(E2EEvent::LOGITS_READY,tok,D2E_NO_LAYER,-1,vocab);}
    bool sample(uint32_t tok,int64_t id){return event(E2EEvent::SAMPLE,tok,D2E_NO_LAYER,id);}
    bool detokenize(uint32_t tok,int64_t id,const void* p,uint32_t n){return event(E2EEvent::DETOKENIZE,tok,D2E_NO_LAYER,id,n,0,p,n);}
    bool stream(uint32_t tok,int64_t id,const void* p,uint32_t n){return event(E2EEvent::STREAM,tok,D2E_NO_LAYER,id,n,0,p,n);}
    bool synthetic(uint32_t tok){return event(E2EEvent::SYNTHETIC,tok);} bool proxy(){return event(E2EEvent::PROXY);}
    bool fallback(){return event(E2EEvent::FALLBACK);} bool end(){return event(E2EEvent::END);}
};
}
