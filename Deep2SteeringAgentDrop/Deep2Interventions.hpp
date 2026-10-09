#pragma once
// Opt-in inference interventions; raw parity must run with enabled=false.
#include "Deep2Steering.hpp"
#include <functional>
#include <string>
namespace rawrxd::deep2 {
enum class InterventionPoint { Residual, AttentionScores, AttentionWeights, Logits };
struct Intervention {
    InterventionPoint point=InterventionPoint::Residual;
    uint32_t layer=0;
    float strength=0;
    std::vector<float> direction; // same width as selected tensor
};
class InterventionController {
    bool enabled_=false, certification_=false;
    std::vector<Intervention> rules_;
public:
    void Enable(bool on){enabled_=on;}
    void CertificationMode(bool on){certification_=on;}
    void Clear(){rules_.clear();}
    bool Add(const Intervention& r){
        if(!std::isfinite(r.strength)||r.strength < -10.f||r.strength > 10.f||r.direction.empty())return false;
        for(float x:r.direction)if(!std::isfinite(x))return false;
        rules_.push_back(r);return true;
    }
    bool Apply(InterventionPoint point,uint32_t layer,float* data,size_t n)const{
        if(!enabled_||certification_)return true;
        if(!data||!n)return false;
        for(const auto& r:rules_)if(r.point==point&&r.layer==layer){
            if(r.direction.size()!=n)return false;
            for(size_t i=0;i<n;++i){
                const double v=double(data[i])+double(r.strength)*r.direction[i];
                if(!std::isfinite(v)||v>std::numeric_limits<float>::max()||v< -std::numeric_limits<float>::max())return false;
            }
            for(size_t i=0;i<n;++i)data[i]+=r.strength*r.direction[i];
        }
        return true;
    }
};
// Restrict a token choice to continuations of a finite set of canonical output strings.
// For schema-constrained calls, populate candidates from validated ToolSchema arguments.
// This is a finite-language decoder, not a general JSON grammar decoder.
class ConstrainedGenerator {
    std::vector<std::string> candidates_;
    std::string prefix_;
public:
    explicit ConstrainedGenerator(std::vector<std::string> candidates):candidates_(std::move(candidates)){}
    void Reset(){prefix_.clear();}
    const std::string& Prefix()const{return prefix_;}
    bool Complete()const{for(const auto& c:candidates_)if(c==prefix_)return true;return false;}
    // decodedPieces must be exact, context-independent UTF-8 token bytes.
    bool Mask(std::vector<float>& logits,const std::vector<std::string>& decodedPieces)const{
        if(logits.size()!=decodedPieces.size()||Complete())return false;
        bool any=false;for(size_t t=0;t<logits.size();++t){
            bool valid=false;const auto& piece=decodedPieces[t];
            if(!piece.empty())for(const auto& candidate:candidates_)
                if(candidate.size()>=prefix_.size()+piece.size()&&
                   candidate.compare(0,prefix_.size(),prefix_)==0&&
                   candidate.compare(prefix_.size(),piece.size(),piece)==0){valid=true;break;}
            if(!valid)logits[t]=-std::numeric_limits<float>::infinity();else any=true;
        }return any;
    }
    bool Accept(const std::string& piece){
        if(piece.empty())return false;
        const std::string next=prefix_+piece;
        for(const auto& c:candidates_)if(c.compare(0,next.size(),next)==0){prefix_=next;return true;}
        return false;
    }
};
} // namespace rawrxd::deep2
