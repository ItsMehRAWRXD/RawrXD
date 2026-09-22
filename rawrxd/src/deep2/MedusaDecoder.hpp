#pragma once
#include "Deep2Speculative.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace Deep2 {

// Historical class name retained for ABI/source compatibility.
// This is a generic verified speculative drafter, not trained Medusa heads.
struct MedusaConfig {
    uint32_t window=4;
    uint32_t ngram=4;
    uint32_t minMatch=2;
    size_t maxHistory=32768;
};

struct MedusaStats {
    int accepted=0;
    int rejected=0;
    SpeculativeCounters exact{};
};

class MedusaDecoder {
public:
    explicit MedusaDecoder(const MedusaConfig& c={}):cfg_(c){}

    void reset() {
        history_.clear();
        nextByToken_.clear();
        stats={};
    }

    void observe(int32_t token) {
        if(!history_.empty())
            nextByToken_[history_.back()]=token;
        history_.push_back(token);
        if(history_.size()>cfg_.maxHistory) {
            const size_t drop=history_.size()-cfg_.maxHistory;
            history_.erase(history_.begin(),history_.begin()+drop);
            rebuildNext();
        }
    }

    void observe(const int* tokens,size_t n) {
        if(!tokens) return;
        for(size_t i=0;i<n;++i) observe((int32_t)tokens[i]);
    }

    // Returns up to cfg_.window proposals. No proposal is authoritative.
    std::vector<int32_t> propose() {
        std::vector<int32_t> out;
        if(history_.empty()||cfg_.window==0) return out;

        const size_t maxN=std::min<size_t>(
            {cfg_.ngram,history_.size(),history_.size()>1?history_.size()-1:0});

        // Longest suffix match first.
        for(size_t n=maxN;n>=cfg_.minMatch && n>0;--n) {
            if(history_.size()<=n) continue;
            const size_t suffix=history_.size()-n;
            for(size_t pos=0;pos+n<history_.size();++pos) {
                bool same=true;
                for(size_t j=0;j<n;++j) {
                    if(history_[pos+j]!=history_[suffix+j]) {
                        same=false; break;
                    }
                }
                if(!same) continue;

                size_t k=pos+n;
                while(k<history_.size()&&out.size()<cfg_.window)
                    out.push_back(history_[k++]);
                if(!out.empty()) {
                    ++stats.exact.draftWindows;
                    stats.exact.proposedTokens+=out.size();
                    return out;
                }
            }
            if(n==cfg_.minMatch) break;
        }

        auto it=nextByToken_.find(history_.back());
        if(it!=nextByToken_.end()) out.push_back(it->second);
        if(!out.empty()) {
            ++stats.exact.draftWindows;
            stats.exact.proposedTokens+=out.size();
        }
        return out;
    }

    void recordVerification(size_t proposed,size_t accepted,size_t emitted) {
        stats.accepted+=(int)accepted;
        stats.rejected+=(int)(proposed-std::min(proposed,accepted));
        ++stats.exact.targetPasses;
        stats.exact.acceptedTokens+=accepted;
        stats.exact.rejectedTokens+=
            proposed-std::min(proposed,accepted);
        stats.exact.verifiedOutputTokens+=emitted;
        if(proposed) {
            const double ratio=
                static_cast<double>(accepted)/static_cast<double>(proposed);
            stats.exact.acceptanceEwma=
                stats.exact.acceptanceEwma*0.875+ratio*0.125;
        }
    }

    uint32_t suggestedWindow() const noexcept {
        const double a=stats.exact.acceptanceEwma;
        if(a>=0.72) return 4;
        if(a>=0.45) return 3;
        return 2;
    }
    uint32_t suggestedSelfDraftLayers() const noexcept {
        const double a=stats.exact.acceptanceEwma;
        if(a>=0.72) return 8;
        if(a>=0.45) return 12;
        return 16;
    }
    uint32_t suggestedWindowByMeasuredCost() noexcept {
        // Explore each legal window once before exploiting the measured best.
        for(uint32_t w=2;w<=4;++w)
            if(stats.exact.windowAttempts[w]==0)
                return w;

        uint32_t best=2;
        long double bestRate=-1.0L;
        for(uint32_t w=2;w<=4;++w) {
            const uint64_t ns=stats.exact.windowVerifyNs[w];
            const uint64_t tok=stats.exact.windowVerified[w];
            if(!ns) continue;
            const long double rate=
                (long double)tok*1000000000.0L/(long double)ns;
            if(rate>bestRate) {bestRate=rate;best=w;}
        }
        ++stats.exact.costControllerSelections;
        return best;
    }
    void recordWindowCost(uint32_t window,uint64_t verified,uint64_t ns) {
        if(window<2||window>4||!ns) return;
        ++stats.exact.windowAttempts[window];
        stats.exact.windowVerified[window]+=verified;
        stats.exact.windowVerifyNs[window]+=ns;
    }

    MedusaStats stats;

    const MedusaConfig& config() const noexcept { return cfg_; }

private:
    void rebuildNext() {
        nextByToken_.clear();
        for(size_t i=1;i<history_.size();++i)
            nextByToken_[history_[i-1]]=history_[i];
    }

    MedusaConfig cfg_{};
    std::vector<int32_t> history_;
    std::unordered_map<int32_t,int32_t> nextByToken_;
};
} // namespace Deep2

