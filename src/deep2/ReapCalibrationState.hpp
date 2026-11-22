#pragma once
// Versioned calibration state; caller selects a distinct schema for each metric.
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <locale>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace Deep2 { namespace ReapState {
struct Identity {
    std::string model, config;
    uint32_t layers=0, experts=0, topK=0;
    std::vector<std::string> prompts;
    std::string schema="RAWRXD_REAP_ROUTING_STATE_002";
};
struct Metric { uint32_t layer=0, expert=0; uint64_t count=0; double activation=0, weight=0; };
struct State { uint64_t observations=0; std::vector<uint64_t> completed; std::vector<Metric> metrics; };
inline bool valid(const Identity& id,const State& s) {
    if(id.model.empty()||id.config.empty()||!id.layers||!id.experts||!id.topK||id.topK>id.experts||id.prompts.empty()||s.completed.size()!=id.prompts.size())return false;
    uint64_t total=0;bool gap=false;
    for(auto n:s.completed){if(!n)gap=true;else if(gap||n>UINT64_MAX-total)return false;total+=n;}
    if(!total||total!=s.observations||s.observations>UINT64_MAX/id.topK)return false;
    uint64_t routes=0;std::set<std::pair<uint32_t,uint32_t>> seen;
    for(const auto& m:s.metrics){
        if(m.layer>=id.layers||m.expert>=id.experts||!m.count||m.count>total||m.count>UINT64_MAX-routes||!seen.emplace(m.layer,m.expert).second||!std::isfinite(m.activation)||!std::isfinite(m.weight)||m.activation<0||std::abs(m.weight)>m.activation)return false;
        routes+=m.count;
    }
    return routes==total*id.topK;
}
inline bool Write(std::ostream& o,const Identity& id,const State& s){
    if(!valid(id,s))return false;
    o.imbue(std::locale::classic());o<<std::setprecision(std::numeric_limits<double>::max_digits10);
    o<<id.schema<<'\n'<<std::quoted(id.model)<<'\n'<<std::quoted(id.config)<<'\n'<<id.layers<<' '<<id.experts<<' '<<id.topK<<' '<<id.prompts.size()<<'\n';
    for(size_t i=0;i<id.prompts.size();++i)o<<std::quoted(id.prompts[i])<<' '<<s.completed[i]<<'\n';
    o<<s.observations<<' '<<s.metrics.size()<<'\n';
    for(const auto& m:s.metrics)o<<m.layer<<' '<<m.expert<<' '<<m.count<<' '<<m.activation<<' '<<m.weight<<'\n';
    return bool(o);
}
inline bool Read(std::istream& in,const Identity& id,State& result){
    in.imbue(std::locale::classic());std::string schema,model,config,prompt;uint32_t layers=0,experts=0,top=0;size_t n=0;
    if(!(in>>schema>>std::quoted(model)>>std::quoted(config)>>layers>>experts>>top>>n)||schema!=id.schema||model!=id.model||config!=id.config||layers!=id.layers||experts!=id.experts||top!=id.topK||n!=id.prompts.size())return false;
    State s;s.completed.resize(n);
    for(size_t i=0;i<n;++i)if(!(in>>std::quoted(prompt)>>s.completed[i])||prompt!=id.prompts[i])return false;
    uint64_t rows=0;if(!(in>>s.observations>>rows)||rows>uint64_t(layers)*experts||rows>10000000)return false;
    s.metrics.reserve(static_cast<size_t>(rows));
    for(uint64_t i=0;i<rows;++i){Metric m;if(!(in>>m.layer>>m.expert>>m.count>>m.activation>>m.weight))return false;s.metrics.push_back(m);}
    in>>std::ws;if(in.bad()||!in.eof()||!valid(id,s))return false;
    result=std::move(s);return true;
}
inline bool Save(const std::filesystem::path& path,const Identity& id,const State& s){
    auto tmp=path;tmp+=".tmp";
    std::ofstream out(tmp,std::ios::binary|std::ios::trunc);if(!out)return false;
    const bool written=Write(out,id,s);out.close();if(!written||!out)return false;
    std::error_code ec;std::filesystem::rename(tmp,path,ec);return !ec;
}
inline bool Load(const std::filesystem::path& path,const Identity& id,State& s){
    std::ifstream in(path,std::ios::binary);return in&&Read(in,id,s);
}
} } // namespace Deep2::ReapState
