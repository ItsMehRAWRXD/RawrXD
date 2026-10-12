#include "ExpertAuthority.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
#include <charconv>
int main(int argc,char**argv){try{if(argc!=4){std::cerr<<"usage: expert_authority manifest.tsv declared_payload_bytes expert_count\n";return 2;}auto parse=[](const char*s){uint64_t n=0;std::string v=s;auto r=std::from_chars(v.data(),v.data()+v.size(),n);if(r.ec!=std::errc{}||r.ptr!=v.data()+v.size())throw std::runtime_error("invalid numeric argument");return n;};auto r=deep2::analyze(deep2::load_tsv(argv[1]),parse(argv[2]),parse(argv[3]));std::cout<<deep2::to_json(r);return r.complete?0:3;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 2;}}
