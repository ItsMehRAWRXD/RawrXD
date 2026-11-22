#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
namespace Deep2 { namespace ReapQuant {
// Independent pools: host RAM, per-device VRAM, disk staging and I/O slots.
// Callers must account all allocations in the appropriate pool.
class StrataBudget {
public:
    using Amount=std::array<uint64_t,5>; // host, GPU0, GPU1, disk, I/O slots
private:
    struct State {
        std::mutex mutex;
        Amount limit,used{};
        explicit State(Amount n):limit(n){}
    };
    struct Reservation {
        std::shared_ptr<State> state;
        Amount amount;
        Reservation(std::shared_ptr<State> s,Amount a):state(std::move(s)),amount(a){}
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        Reservation(Reservation&&) = delete;
        Reservation& operator=(Reservation&&) = delete;
        ~Reservation(){
            std::lock_guard<std::mutex> lock(state->mutex);
            for(size_t i=0;i<amount.size();++i)state->used[i]-=amount[i];
        }
    };
    std::shared_ptr<State> state_;
public:
    using Lease=std::shared_ptr<const Reservation>;
    explicit StrataBudget(Amount limit):state_(std::make_shared<State>(limit)){}
    bool Acquire(Amount request,Lease& out){
        Lease next;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            bool any=false;
            for(size_t i=0;i<request.size();++i){
                if(request[i]>state_->limit[i]-state_->used[i])return false;
                any=any||request[i]!=0;
            }
            if(!any)return false;
            try {next=std::make_shared<Reservation>(state_,request);}catch(...){return false;}
            for(size_t i=0;i<request.size();++i)state_->used[i]+=request[i];
        }
        out=std::move(next);return true;
    }
    bool SetLimits(Amount limit){
        std::lock_guard<std::mutex> lock(state_->mutex);
        for(size_t i=0;i<limit.size();++i)if(limit[i]<state_->used[i])return false;
        state_->limit=limit;return true;
    }
    Amount Used() const {
        std::lock_guard<std::mutex> lock(state_->mutex);return state_->used;
    }
    Amount Available() const {
        std::lock_guard<std::mutex> lock(state_->mutex);
        Amount result{};
        for(size_t i=0;i<result.size();++i)result[i]=state_->limit[i]-state_->used[i];
        return result;
    }
};
} }
