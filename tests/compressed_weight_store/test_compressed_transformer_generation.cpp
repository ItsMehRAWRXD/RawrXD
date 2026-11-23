#include "../../src/deep2/compression/CompressedTransformerRuntime.hpp"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <cstring>
#include <limits>
#include <cmath>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
struct OwnedTensor {
    std::string name;
    std::vector<std::int64_t> shape;
    std::vector<std::uint8_t> bytes;
};
void appendF16(OwnedTensor& t, float value) {
    const auto h = rawrxd::compression::floatToHalfRNE(value);
    t.bytes.push_back(static_cast<std::uint8_t>(h & 0xffu));
    t.bytes.push_back(static_cast<std::uint8_t>(h >> 8));
}
void addVector(std::vector<OwnedTensor>& all, const std::string& name,
               const std::vector<float>& values) {
    OwnedTensor t{name, {static_cast<std::int64_t>(values.size())}, {}};
    for (float v : values) appendF16(t, v);
    all.emplace_back(std::move(t));
}
void addMatrix(std::vector<OwnedTensor>& all, const std::string& name,
               std::size_t rows, std::size_t cols,
               const std::vector<float>& values) {
    assert(values.size() == rows * cols);
    OwnedTensor t{name, {static_cast<std::int64_t>(cols),
                         static_cast<std::int64_t>(rows)}, {}};
    for (float v : values) appendF16(t, v);
    all.emplace_back(std::move(t));
}
std::vector<float> diagonal(std::size_t n, float scale) {
    std::vector<float> v(n*n, 0.0f);
    for (std::size_t i=0;i<n;++i) v[i*n+i]=scale;
    return v;
}
float halfValue(std::uint16_t h) {
    const std::uint32_t sign=std::uint32_t(h&0x8000u)<<16;
    std::uint32_t exp=(h>>10)&31u, mant=h&1023u, bits=0;
    if(exp==0) {
        if(!mant) bits=sign;
        else { int e=-14; while((mant&0x400u)==0){mant<<=1;--e;}
            mant&=0x3ffu; bits=sign|(std::uint32_t(e+127)<<23)|(mant<<13); }
    } else if(exp==31) bits=sign|0x7f800000u|(mant<<13);
    else bits=sign|((exp+112u)<<23)|(mant<<13);
    float v=0; std::memcpy(&v,&bits,sizeof(v)); return v;
}
const OwnedTensor& findTensor(const std::vector<OwnedTensor>& all,const std::string& name) {
    for(const auto& t:all) if(t.name==name) return t;
    throw std::runtime_error("reference tensor missing: "+name);
}
std::vector<float> rawValues(const std::vector<OwnedTensor>& all,const std::string& name) {
    const auto& t=findTensor(all,name);
    std::vector<float> out(t.bytes.size()/2);
    for(std::size_t i=0;i<out.size();++i)
        out[i]=halfValue(std::uint16_t(t.bytes[2*i])|(std::uint16_t(t.bytes[2*i+1])<<8));
    return out;
}
std::vector<float> rawMatvec(const std::vector<OwnedTensor>& all,const std::string& name,
                             const std::vector<float>& x,std::size_t rows,std::size_t cols) {
    const auto w=rawValues(all,name);
    assert(w.size()==rows*cols && x.size()==cols);
    std::vector<float> y(rows,0.0f);
    for(std::size_t r=0;r<rows;++r)
        for(std::size_t col=0;col<cols;++col) y[r]+=w[r*cols+col]*x[col];
    return y;
}
void rawNorm(const std::vector<OwnedTensor>& all,std::vector<float>& x,
             const std::string& name,float eps) {
    const auto w=rawValues(all,name);
    double sum=0; for(float v:x) sum+=double(v)*v;
    const float inv=1.0f/std::sqrt(float(sum/x.size())+eps);
    for(std::size_t i=0;i<x.size();++i) x[i]=x[i]*inv*w[i];
}
void rawRope(std::vector<float>& x,std::size_t pos,std::size_t heads,
             std::size_t headDim,float theta) {
    for(std::size_t h=0;h<heads;++h) for(std::size_t d=0;d<headDim;d+=2) {
        const float f=1.0f/std::pow(theta,float(d)/float(headDim));
        const float a=float(pos)*f, co=std::cos(a), si=std::sin(a);
        const auto i=h*headDim+d; const float x0=x[i],x1=x[i+1];
        x[i]=x0*co-x1*si; x[i+1]=x0*si+x1*co;
    }
}
std::vector<int32_t> rawReferenceGenerate(const std::vector<OwnedTensor>& all,
    const std::vector<int32_t>& prompt,std::size_t steps,std::size_t hidden,
    std::size_t intermediate,std::size_t vocab,std::size_t layers,
    std::size_t heads,std::size_t headDim,float eps,float theta) {
    std::vector<std::vector<std::vector<float>>> keys(layers),values(layers);
    auto forward=[&](int32_t token,std::size_t pos) {
        auto emb=rawValues(all,"token_embd.weight");
        std::vector<float> h(emb.begin()+std::size_t(token)*hidden,
                             emb.begin()+(std::size_t(token)+1)*hidden);
        for(std::size_t l=0;l<layers;++l) {
            const std::string p="blk."+std::to_string(l)+".";
            auto residual=h,n=h; rawNorm(all,n,p+"attn_norm.weight",eps);
            auto q=rawMatvec(all,p+"attn_q.weight",n,hidden,hidden);
            auto k=rawMatvec(all,p+"attn_k.weight",n,hidden,hidden);
            auto v=rawMatvec(all,p+"attn_v.weight",n,hidden,hidden);
            rawRope(q,pos,heads,headDim,theta); rawRope(k,pos,heads,headDim,theta);
            keys[l].push_back(k); values[l].push_back(v);
            std::vector<float> a(hidden,0.0f);
            for(std::size_t hd=0;hd<heads;++hd) {
                const auto base=hd*headDim; std::vector<float> scores(keys[l].size());
                float mx=-std::numeric_limits<float>::infinity();
                for(std::size_t t=0;t<keys[l].size();++t) {
                    float dot=0; for(std::size_t d=0;d<headDim;++d) dot+=q[base+d]*keys[l][t][base+d];
                    scores[t]=dot/std::sqrt(float(headDim)); mx=std::max(mx,scores[t]);
                }
                float z=0; for(float& s:scores){s=std::exp(s-mx);z+=s;}
                for(std::size_t t=0;t<scores.size();++t)
                    for(std::size_t d=0;d<headDim;++d)
                        a[base+d]+=(scores[t]/z)*values[l][t][base+d];
            }
            auto ao=rawMatvec(all,p+"attn_output.weight",a,hidden,hidden);
            for(std::size_t i=0;i<hidden;++i) h[i]=residual[i]+ao[i];
            residual=h; n=h; rawNorm(all,n,p+"ffn_norm.weight",eps);
            auto g=rawMatvec(all,p+"ffn_gate.weight",n,intermediate,hidden);
            auto u=rawMatvec(all,p+"ffn_up.weight",n,intermediate,hidden);
            for(std::size_t i=0;i<intermediate;++i) g[i]=(g[i]/(1.0f+std::exp(-g[i])))*u[i];
            auto d=rawMatvec(all,p+"ffn_down.weight",g,hidden,intermediate);
            for(std::size_t i=0;i<hidden;++i) h[i]=residual[i]+d[i];
        }
        rawNorm(all,h,"output_norm.weight",eps);
        return rawMatvec(all,"output.weight",h,vocab,hidden);
    };
    std::vector<float> logits;
    std::size_t pos=0;
    for(auto token:prompt) logits=forward(token,pos++);
    std::vector<int32_t> out;
    for(std::size_t n=0;n<steps;++n) {
        const auto next=static_cast<int32_t>(std::distance(logits.begin(),
            std::max_element(logits.begin(),logits.end())));
        out.push_back(next); logits=forward(next,pos++);
    }
    return out;
}

std::vector<Deep2::GGUFTensor> descriptors(std::vector<OwnedTensor>& owned) {
    std::vector<Deep2::GGUFTensor> out;
    out.reserve(owned.size());
    for (auto& src : owned) {
        Deep2::GGUFTensor t;
        t.name = src.name;
        t.type = static_cast<Deep2::GGMLType>(1); // GGML_TYPE_F16
        t.shape = src.shape;
        t.data = src.bytes.data();
        t.sizeBytes = src.bytes.size();
        t.mapped = true;
        out.emplace_back(std::move(t));
    }
    return out;
}
} // namespace

int main() {
    constexpr std::size_t hidden=4, intermediate=8, vocab=8;
    std::vector<OwnedTensor> owned;
    owned.reserve(24);

    std::vector<float> embedding(vocab*hidden);
    for (std::size_t r=0;r<vocab;++r) {
        embedding[r*hidden+0]=0.10f*float(r+1);
        embedding[r*hidden+1]=0.05f*float(r%3);
        embedding[r*hidden+2]=0.025f*float(r%2);
        embedding[r*hidden+3]=-0.02f*float(r);
    }
    addMatrix(owned,"token_embd.weight",vocab,hidden,embedding);
    addVector(owned,"output_norm.weight",std::vector<float>(hidden,1.0f));
    std::vector<float> output(vocab*hidden);
    for(std::size_t r=0;r<vocab;++r)
        for(std::size_t c=0;c<hidden;++c)
            output[r*hidden+c]=0.05f*float(int((r*3+c*5)%11)-5);
    addMatrix(owned,"output.weight",vocab,hidden,output);

    // Two complete pre-norm decoder blocks, each with multi-head causal
    // self-attention, RoPE, residual paths, SwiGLU and a second residual.
    for (std::size_t layer=0; layer<2; ++layer) {
        const std::string p="blk."+std::to_string(layer)+".";
        const float layerScale = layer==0 ? 1.0f : 0.8f;
        addVector(owned,p+"attn_norm.weight",std::vector<float>(hidden,1.0f));
        addMatrix(owned,p+"attn_q.weight",hidden,hidden,diagonal(hidden,0.75f*layerScale));
        addMatrix(owned,p+"attn_k.weight",hidden,hidden,diagonal(hidden,0.50f*layerScale));
        addMatrix(owned,p+"attn_v.weight",hidden,hidden,diagonal(hidden,1.0f));
        addMatrix(owned,p+"attn_output.weight",hidden,hidden,diagonal(hidden,1.0f));
        addVector(owned,p+"ffn_norm.weight",std::vector<float>(hidden,1.0f));

        std::vector<float> gate(intermediate*hidden), up(intermediate*hidden);
        for(std::size_t r=0;r<intermediate;++r)
            for(std::size_t col=0;col<hidden;++col) {
                gate[r*hidden+col]=0.04f*layerScale*float(1+((r+col)%4));
                up[r*hidden+col]=0.10f*float(1+((2*r+col+layer)%3));
            }
        addMatrix(owned,p+"ffn_gate.weight",intermediate,hidden,gate);
        addMatrix(owned,p+"ffn_up.weight",intermediate,hidden,up);
        std::vector<float> down(hidden*intermediate,0.0f);
        for(std::size_t r=0;r<hidden;++r)
            for(std::size_t col=0;col<intermediate;++col)
                down[r*intermediate+col]=(col%hidden==r)?0.25f:0.025f;
        addMatrix(owned,p+"ffn_down.weight",hidden,intermediate,down);
    }

    auto tensors=descriptors(owned);
    rawrxd::compression::CompressedGGUFModel::Options storeOptions;
    storeOptions.decoded_cache_bytes=0;
    storeOptions.block_bytes=64;
    storeOptions.require_savings=false;
    rawrxd::compression::CompressedGGUFModel model(storeOptions);
    std::string error, failed;
    assert(model.loadMappedTensors(tensors,&error,&failed));
    assert(model.loaded() && model.tensorCount()==owned.size());
    assert(model.stats().cached_decoded_bytes==0);

    rawrxd::compression::CompressedTransformerRuntime::Config config;
    config.hidden=hidden;
    config.intermediate=intermediate;
    config.vocabulary=vocab;
    config.layers=2;
    config.heads=2;
    config.head_dim=hidden/2;
    config.rms_epsilon=1.0e-5f;
    config.rope_theta=10000.0f;

    rawrxd::compression::CompressedTransformerRuntime runtime(model,config);
    const std::vector<int32_t> prompt{1,2};
    const auto generated=runtime.generate(prompt,6);
    assert(generated.size()==6);
    for(auto token:generated) assert(token>=0 && token<static_cast<int32_t>(vocab));
    const auto reference=rawReferenceGenerate(owned,prompt,6,hidden,intermediate,vocab,
                                               2,2,hidden/2,config.rms_epsilon,
                                               config.rope_theta);
    assert(generated==reference);

    // Recreate request-local KV state and require deterministic autoregressive
    // output. All projections still read the compressed store; no full decoded
    // weights or persistent decoded-block cache are allowed.
    const auto repeated=runtime.generate(prompt,6);
    assert(repeated==generated);
    const auto stats=model.stats();
    assert(stats.tensors==owned.size());
    assert(stats.compressed_bytes>0 && stats.raw_bytes>0);
    assert(stats.cached_decoded_bytes==0);
    assert(stats.cache_misses>0);
    return 0;
}
