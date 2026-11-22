#pragma once
#include "ReapStrataBudget.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
namespace Deep2 { namespace ReapQuant {
enum class LocalResult { Completed, Cancelled, AdmissionDenied, BackendFailed, ConsumerStopped, Invalid };
enum class TokenStep { Token, End, Failed };
// Backend is request-local and implements Step(uint32_t&, const atomic<bool>&).
// Factory constructs the real backend only after admission. Consumer runs inline.
// Backend destruction must drain outstanding device work before returning.
template<class Factory,class Consumer>
LocalResult RunLocalRequest(StrataBudget& budget,StrataBudget::Amount amount,
 size_t maxTokens,const std::atomic<bool>& cancel,Factory&& factory,Consumer&& consume){
    if(!maxTokens)return LocalResult::Invalid;
    if(cancel.load(std::memory_order_acquire))return LocalResult::Cancelled;
    StrataBudget::Lease reservation;
    if(!budget.Acquire(amount,reservation))return LocalResult::AdmissionDenied;
    try {
        if(cancel.load(std::memory_order_acquire))return LocalResult::Cancelled;
        auto backend=factory();
        if(!backend)return LocalResult::BackendFailed;
        for(size_t i=0;i<maxTokens;++i){
            if(cancel.load(std::memory_order_acquire))return LocalResult::Cancelled;
            uint32_t token=0;
            const auto step=backend->Step(token,cancel);
            if(cancel.load(std::memory_order_acquire))return LocalResult::Cancelled;
            if(step==TokenStep::End)return LocalResult::Completed;
            if(step!=TokenStep::Token)return LocalResult::BackendFailed;
            if(!consume(token))return LocalResult::ConsumerStopped;
        }
        return LocalResult::Completed;
    }catch(...){return LocalResult::BackendFailed;}
}
} }
