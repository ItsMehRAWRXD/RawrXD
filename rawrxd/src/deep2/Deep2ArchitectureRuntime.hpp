#pragma once
// RAWRXD_MODEL_ARCH_PACK_001
//
// Deep2 architecture binder + autoregressive reference recurrent provider.
// Header-only on purpose: drop-in does not require changing CMake source lists.
//
// Include this ONLY after Deep2Engine.h in Deep2Engine.cpp.

#include "Deep2ModelArchitecture.hpp"
#include "Deep2RecurrentMath.hpp"
#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"

#include <algorithm>
#include <cstring>
#include <functional>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace Deep2::Arch {

using LinearFn = std::function<void(const WeightTensor&,const float*,float*,std::size_t)>;

struct RecurrentWeights {
    WeightTensor qkv;
    WeightTensor attnGate;      // Qwen3.5 z gate
    WeightTensor betaAlpha;     // Qwen3-Next combined beta/alpha
    WeightTensor beta;          // Qwen3.5
    WeightTensor alpha;         // Qwen3.5

    WeightTensor ssmIn;         // Nemotron-H Mamba2 in-proj
    WeightTensor conv;
    WeightTensor convBias;
    WeightTensor dtBias;
    WeightTensor a;
    WeightTensor d;
    WeightTensor norm;
    WeightTensor out;

    bool recurrent=false;
};

struct LayerState {
    std::vector<float> convHistory;
    std::vector<float> recurrentState;
};

class ArchitectureRuntime {
public:
    bool bind(GGUFLoader& loader,const std::string& arch,std::size_t layers,
              float normEps,std::string& error) {
        traits_=resolve(arch);
        arch_=arch;
        normEps_=normEps>0.0f?normEps:1e-6f;
        if(traits_.kind==Kind::Unknown) {
            error="unknown GGUF architecture: "+arch;
            return false;
        }

        recurrent_.assign(layers,{});
        state_.assign(layers,{});

        auto meta=[&](const char* suffix,std::size_t def=0)->std::size_t {
            const auto v=loader.getMetaInt(arch+"."+suffix,static_cast<std::int64_t>(def));
            return v>0?static_cast<std::size_t>(v):def;
        };

        ssmConvKernel_=meta("ssm.conv_kernel",0);
        ssmInner_=meta("ssm.inner_size",0);
        ssmState_=meta("ssm.state_size",0);
        ssmDtRank_=meta("ssm.time_step_rank",0);
        ssmGroups_=meta("ssm.group_count",0);

        if(traits_.family==ForwardFamily::GatedDeltaNet ||
           traits_.family==ForwardFamily::Mamba2) {
            if(!ssmConvKernel_||!ssmInner_||!ssmState_||!ssmDtRank_||!ssmGroups_) {
                error="recurrent architecture missing ssm.* geometry metadata";
                return false;
            }
        }

        for(std::size_t i=0;i<layers;++i) {
            const std::string p="blk."+std::to_string(i)+".";
            auto& w=recurrent_[i];

            // Common recurrent tensors.
            bind(loader,p+"ssm_conv1d.weight",w.conv);
            bind(loader,p+"ssm_conv1d.bias",w.convBias);
            bind(loader,p+"ssm_dt.bias",w.dtBias);
            bind(loader,p+"ssm_a",w.a);
            bind(loader,p+"ssm_d",w.d);
            bind(loader,p+"ssm_norm.weight",w.norm);
            bind(loader,p+"ssm_out.weight",w.out);

            if(traits_.family==ForwardFamily::GatedDeltaNet) {
                bind(loader,p+"attn_qkv.weight",w.qkv);
                bind(loader,p+"attn_gate.weight",w.attnGate);
                bind(loader,p+"ssm_beta_alpha.weight",w.betaAlpha);
                bind(loader,p+"ssm_beta.weight",w.beta);
                bind(loader,p+"ssm_alpha.weight",w.alpha);
                w.recurrent=w.conv.data && w.out.data && w.a.data && w.dtBias.data &&
                            w.qkv.data &&
                            ((traits_.kind==Kind::Qwen3Next && w.betaAlpha.data) ||
                             ((traits_.kind==Kind::Qwen35 || traits_.kind==Kind::Qwen35Moe) &&
                              w.beta.data && w.alpha.data && w.attnGate.data));
            } else if(traits_.family==ForwardFamily::Mamba2) {
                bind(loader,p+"ssm_in.weight",w.ssmIn);
                w.recurrent=w.ssmIn.data && w.conv.data && w.out.data &&
                            w.a.data && w.d.data && w.dtBias.data;
            }
        }

        recurrentLayerCount_=0;
        for(const auto& w:recurrent_) recurrentLayerCount_+=w.recurrent?1u:0u;

        // A hybrid architecture is allowed to have non-recurrent attention
        // layers, but a recurrent family with zero recurrent tensors is not.
        if((traits_.family==ForwardFamily::GatedDeltaNet ||
            traits_.family==ForwardFamily::Mamba2) && recurrentLayerCount_==0) {
            error="recurrent architecture declared but no recurrent layer tensors were bound";
            return false;
        }
        return true;
    }

    void reset() {
        for(auto& s:state_) {
            std::fill(s.convHistory.begin(),s.convHistory.end(),0.0f);
            std::fill(s.recurrentState.begin(),s.recurrentState.end(),0.0f);
        }
    }

    const Traits& traits() const noexcept { return traits_; }
    bool isRecurrentLayer(std::size_t i) const noexcept {
        return i<recurrent_.size() && recurrent_[i].recurrent;
    }
    std::size_t recurrentLayerCount() const noexcept { return recurrentLayerCount_; }

    bool forward(std::size_t layer,const float* input,float* output,
                 std::size_t hidden,LinearFn linear,std::string& error) {
        if(layer>=recurrent_.size()||!isRecurrentLayer(layer)) {
            error="layer is not recurrent";
            return false;
        }
        try {
            if(traits_.family==ForwardFamily::GatedDeltaNet)
                return forwardGdn(layer,input,output,hidden,std::move(linear),error);
            if(traits_.family==ForwardFamily::Mamba2)
                return forwardMamba2(layer,input,output,hidden,std::move(linear),error);
            error="architecture runtime family is not recurrent";
            return false;
        } catch(const std::exception& e) {
            error=e.what(); return false;
        }
    }

private:
    static bool bind(GGUFLoader& loader,const std::string& name,WeightTensor& wt) {
        const GGUFTensor* t=loader.getTensor(name);
        if(!t||!t->data||!t->sizeBytes) return false;
        wt={};
        wt.data=const_cast<std::uint8_t*>(t->data);
        wt.type=static_cast<int>(t->type);
        wt.sizeBytes=t->sizeBytes;
        wt.name=t->name;
        wt.shape=t->shape;
        wt.mapped=true;
        wt.shardId=t->shardId;
        wt.fileOffset=t->fileOffset;
        wt.hasFileBacking=true;
        if(t->shape.size()>=2) {
            wt.cols=static_cast<std::size_t>(t->shape[0]);
            std::size_t rows=1;
            for(std::size_t j=1;j<t->shape.size();++j) {
                const auto d=static_cast<std::size_t>(t->shape[j]);
                if(d&&rows>std::numeric_limits<std::size_t>::max()/d) return false;
                rows*=d;
            }
            wt.rows=rows;
        } else if(t->shape.size()==1) {
            wt.rows=static_cast<std::size_t>(t->shape[0]);
            wt.cols=1;
        } else return false;
        return true;
    }

    static bool dequantAll(const WeightTensor& wt,std::vector<float>& out) {
        const std::size_t n=wt.numElements();
        if(!wt.data||!n) return false;
        out.resize(n);
        if(wt.sizeBytes==n*sizeof(float)) {
            std::memcpy(out.data(),wt.data,n*sizeof(float));
            return Ref::finite(out.data(),out.size());
        }
        auto dq=QuantKernelRegistry::Instance().GetDequant(wt.type);
        if(!dq) return false;
        dq(static_cast<const std::uint8_t*>(wt.data),out.data(),n);
        return Ref::finite(out.data(),out.size());
    }

    bool ensureSmall(const WeightTensor& wt,std::vector<float>& dst,const char* name,std::string& error) {
        if(!dequantAll(wt,dst)) {
            error=std::string("cannot dequant recurrent tensor ")+name;
            return false;
        }
        return true;
    }

    bool prepareConv(std::size_t layer,std::size_t channels,std::size_t kernel,
                     std::vector<float>& k,std::vector<float>& b,std::string& error) {
        auto& w=recurrent_[layer];
        if(!ensureSmall(w.conv,k,"ssm_conv1d",error)) return false;
        if(k.size()!=channels*kernel) {
            error="ssm_conv1d geometry mismatch";
            return false;
        }
        if(w.convBias.data) {
            if(!ensureSmall(w.convBias,b,"ssm_conv1d.bias",error)) return false;
            if(b.size()!=channels) { error="ssm_conv1d.bias geometry mismatch"; return false; }
        } else b.assign(channels,0.0f);
        auto& st=state_[layer];
        const std::size_t need=channels*(kernel-1);
        if(st.convHistory.size()!=need) st.convHistory.assign(need,0.0f);
        return true;
    }

    bool forwardGdn(std::size_t layer,const float* input,float* output,
                    std::size_t hidden,LinearFn linear,std::string& error) {
        auto& w=recurrent_[layer];
        const std::size_t kDim=ssmState_;
        const std::size_t kHeads=ssmGroups_;
        const std::size_t vHeads=ssmDtRank_;
        if(vHeads%kHeads||ssmInner_%vHeads) { error="GDN metadata geometry invalid"; return false; }
        const std::size_t vDim=ssmInner_/vHeads;
        const std::size_t keyTotal=kHeads*kDim;
        const std::size_t valueTotal=vHeads*vDim;
        const std::size_t convChannels=2*keyTotal+valueTotal;

        const bool next=(traits_.kind==Kind::Qwen3Next);
        const std::size_t projRows=next ? (2*keyTotal+2*valueTotal)
                                        : (2*keyTotal+valueTotal);
        std::vector<float> proj(projRows,0.0f);
        linear(w.qkv,input,proj.data(),projRows);

        std::vector<float> convIn(convChannels,0.0f),z(valueTotal,0.0f);
        std::copy_n(proj.data(),2*keyTotal+valueTotal,convIn.data());
        if(next) std::copy_n(proj.data()+2*keyTotal+valueTotal,valueTotal,z.data());
        else linear(w.attnGate,input,z.data(),valueTotal);

        std::vector<float> convK,convB,convOut(convChannels,0.0f);
        if(!prepareConv(layer,convChannels,ssmConvKernel_,convK,convB,error)) return false;
        Ref::depthwiseConvStep(convIn.data(),convChannels,convK.data(),ssmConvKernel_,
                               state_[layer].convHistory.data(),convB.data(),convOut.data());
        for(float& x:convOut) x=Ref::silu(x);

        float* q=convOut.data();
        float* k=convOut.data()+keyTotal;
        float* v=convOut.data()+2*keyTotal;
        for(std::size_t h=0;h<kHeads;++h) {
            Ref::l2Normalize(q+h*kDim,kDim,normEps_);
            Ref::l2Normalize(k+h*kDim,kDim,normEps_);
        }

        std::vector<float> beta(vHeads),alpha(vHeads),tmp(next?2*vHeads:vHeads);
        if(next) {
            linear(w.betaAlpha,input,tmp.data(),2*vHeads);
            const std::size_t ratio=vHeads/kHeads;
            for(std::size_t g=0;g<kHeads;++g) {
                for(std::size_t j=0;j<ratio;++j) {
                    beta[g*ratio+j]=tmp[g*(2*ratio)+j];
                    alpha[g*ratio+j]=tmp[g*(2*ratio)+ratio+j];
                }
            }
        } else {
            linear(w.beta,input,beta.data(),vHeads);
            linear(w.alpha,input,alpha.data(),vHeads);
        }

        std::vector<float> dt,a;
        if(!ensureSmall(w.dtBias,dt,"ssm_dt.bias",error) ||
           !ensureSmall(w.a,a,"ssm_a",error)) return false;
        if(dt.size()<vHeads||a.size()<vHeads) { error="GDN dt/A geometry mismatch"; return false; }

        std::vector<float> gate(vHeads);
        for(std::size_t h=0;h<vHeads;++h) {
            beta[h]=Ref::sigmoid(beta[h]);
            // Upstream stores the multiplicative A term in ssm_a and forms
            // g = softplus(alpha + dt_bias) * A; GDN consumes exp(g).
            gate[h]=Ref::softplus(alpha[h]+dt[h])*a[h];
        }

        auto& st=state_[layer];
        const std::size_t stateN=vHeads*kDim*vDim;
        if(st.recurrentState.size()!=stateN) st.recurrentState.assign(stateN,0.0f);

        std::vector<float> y(valueTotal,0.0f);
        Ref::gatedDeltaNetStep(q,k,v,gate.data(),beta.data(),
                               kHeads,vHeads,kDim,vDim,
                               st.recurrentState.data(),y.data());

        std::vector<float> normW;
        if(!ensureSmall(w.norm,normW,"ssm_norm.weight",error)) return false;
        if(normW.size()<vDim) { error="GDN norm geometry mismatch"; return false; }
        Ref::rmsNormGated(y.data(),normW.data(),z.data(),vDim,vHeads,normEps_);

        linear(w.out,y.data(),output,hidden);
        if(!Ref::finite(output,hidden)) { error="GDN produced non-finite output"; return false; }
        return true;
    }

    bool forwardMamba2(std::size_t layer,const float* input,float* output,
                       std::size_t hidden,LinearFn linear,std::string& error) {
        auto& w=recurrent_[layer];
        const std::size_t inner=ssmInner_;
        const std::size_t stateN=ssmState_;
        const std::size_t heads=ssmDtRank_;
        const std::size_t groups=ssmGroups_;
        if(!inner||!stateN||!heads||!groups||inner%heads||heads%groups) {
            error="Mamba2 metadata geometry invalid"; return false;
        }
        const std::size_t headDim=inner/heads;
        const std::size_t groupBC=groups*stateN;
        const std::size_t inRows=2*inner+2*groupBC+heads;

        std::vector<float> p(inRows,0.0f);
        linear(w.ssmIn,input,p.data(),inRows);

        // Nemotron-H layout: z | x | B | C | dt.
        const float* z=p.data();
        const float* x0=z+inner;
        const float* B0=x0+inner;
        const float* C0=B0+groupBC;
        const float* dt0=C0+groupBC;

        const std::size_t convChannels=inner+2*groupBC;
        std::vector<float> convInput(convChannels);
        std::copy_n(x0,inner,convInput.data());
        std::copy_n(B0,2*groupBC,convInput.data()+inner);

        std::vector<float> convK,convB,convOut(convChannels);
        if(!prepareConv(layer,convChannels,ssmConvKernel_,convK,convB,error)) return false;
        Ref::depthwiseConvStep(convInput.data(),convChannels,convK.data(),ssmConvKernel_,
                               state_[layer].convHistory.data(),convB.data(),convOut.data());
        for(float& x:convOut) x=Ref::silu(x);

        const float* x=convOut.data();
        const float* B=convOut.data()+inner;
        const float* C=B+groupBC;

        std::vector<float> dtBias,A,D;
        if(!ensureSmall(w.dtBias,dtBias,"ssm_dt.bias",error) ||
           !ensureSmall(w.a,A,"ssm_a",error) ||
           !ensureSmall(w.d,D,"ssm_d",error)) return false;
        if(dtBias.size()<heads||A.size()<heads||D.size()<heads) {
            error="Mamba2 scalar tensor geometry mismatch"; return false;
        }

        std::vector<float> dt(heads);
        for(std::size_t h=0;h<heads;++h) {
            dt[h]=dt0[h]+dtBias[h];
            // GGUF Mamba2 A can be stored either as already-negative A or
            // A_log depending on converter generation. Positive values are
            // interpreted as A_log and converted to -exp(A_log).
            if(A[h]>0.0f) A[h]=-std::exp(A[h]);
        }

        auto& st=state_[layer];
        const std::size_t need=heads*headDim*stateN;
        if(st.recurrentState.size()!=need) st.recurrentState.assign(need,0.0f);

        std::vector<float> y(inner,0.0f);
        Ref::mamba2Step(x,B,C,dt.data(),A.data(),D.data(),
                        heads,groups,headDim,stateN,st.recurrentState.data(),y.data());

        // Nemotron-H uses a gated normalization before out_proj. Its GGUF
        // ssm_norm can be [headDim,groups]. If unavailable, fail closed rather
        // than claiming architecture parity.
        std::vector<float> normW;
        if(!ensureSmall(w.norm,normW,"ssm_norm.weight",error)) return false;
        if(normW.empty()) { error="Mamba2 norm missing"; return false; }

        // Apply per-channel RMS normalization; cycle group-shaped weights.
        for(std::size_t h=0;h<heads;++h) {
            float* yh=y.data()+h*headDim;
            double ss=0.0; for(std::size_t d=0;d<headDim;++d) ss+=double(yh[d])*double(yh[d]);
            const float inv=1.0f/std::sqrt(float(ss/double(headDim))+normEps_);
            for(std::size_t d=0;d<headDim;++d) {
                const float nw=normW[d%normW.size()];
                yh[d]=yh[d]*inv*nw*Ref::silu(z[h*headDim+d]);
            }
        }

        linear(w.out,y.data(),output,hidden);
        if(!Ref::finite(output,hidden)) { error="Mamba2 produced non-finite output"; return false; }
        return true;
    }

    Traits traits_{};
    std::string arch_;
    float normEps_=1e-6f;
    std::size_t ssmConvKernel_=0,ssmInner_=0,ssmState_=0,ssmDtRank_=0,ssmGroups_=0;
    std::size_t recurrentLayerCount_=0;
    std::vector<RecurrentWeights> recurrent_;
    std::vector<LayerState> state_;
};

} // namespace Deep2::Arch
