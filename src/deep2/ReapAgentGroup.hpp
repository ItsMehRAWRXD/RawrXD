#pragma once
#include "ReapLocalRequest.hpp"
#include <thread>
#include <vector>
#include <chrono>
namespace Deep2 { namespace ReapQuant {
struct AgentReport {
    LocalResult result=LocalResult::BackendFailed;
    uint64_t tokens=0;
    double seconds=0;
};
template<class Model,class Factory,class Consumer>
bool RunAgentGroup(std::shared_ptr<const Model> model,StrataBudget& budget,
 const std::vector<StrataBudget::Amount>& amounts,size_t maxTokens,size_t maxAgents,
 const std::vector<std::shared_ptr<std::atomic<bool>>>& cancellation,
 Factory factory,Consumer consumer,std::vector<AgentReport>& out){
    const size_t n=amounts.size();
    if(!model||!n||n>maxAgents||!maxTokens||cancellation.size()!=n)return false;
    for(size_t i=0;i<n;++i){
        if(!cancellation[i])return false;
        for(size_t j=0;j<i;++j)if(cancellation[i]==cancellation[j])return false;
    }
    std::vector<AgentReport> reports(n);
    std::vector<std::thread> workers;
    try {
        workers.reserve(n);
        for(size_t i=0;i<n;++i)workers.emplace_back([&,i,factory,consumer]() mutable {
            auto start=std::chrono::steady_clock::now();
            auto& report=reports[i];
            try {
                report.result=RunLocalRequest(budget,amounts[i],maxTokens,*cancellation[i],
                    [&]{return factory(model,i);},
                    [&](uint32_t token){++report.tokens;return consumer(i,token);});
            }catch(...){report.result=LocalResult::BackendFailed;}
            report.seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-start).count();
        });
    }catch(...){
        for(size_t i=0;i<workers.size();++i)cancellation[i]->store(true);
        for(auto& worker:workers)worker.join();
        return false;
    }
    for(auto& worker:workers)worker.join();
    out.swap(reports);return true;
}
} }
