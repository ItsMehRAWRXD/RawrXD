#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_set>
#include <cmath>

struct Row { uint32_t layer{}, expert{}; uint64_t bytes{}; double score{}; uint64_t routes{}; };
static std::string sha256(const std::string& s){ BCRYPT_ALG_HANDLE a{}; BCRYPT_HASH_HANDLE h{}; DWORD n=0,z=0; if(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)||BCryptGetProperty(a,BCRYPT_OBJECT_LENGTH,(PUCHAR)&n,sizeof n,&z,0)||BCryptGetProperty(a,BCRYPT_HASH_LENGTH,(PUCHAR)&z,sizeof z,&n,0)) return {}; std::vector<UCHAR> ob(n),out(z); if(BCryptCreateHash(a,&h,ob.data(),n,nullptr,0,0)||BCryptHashData(h,(PUCHAR)s.data(),(ULONG)s.size(),0)||BCryptFinishHash(h,out.data(),z,0)){BCryptDestroyHash(h);BCryptCloseAlgorithmProvider(a,0);return {};} BCryptDestroyHash(h);BCryptCloseAlgorithmProvider(a,0); std::ostringstream o; for(auto c:out){char b[3];sprintf_s(b,"%02x",c);o<<b;} return o.str(); }
int main(int argc,char**argv){
 if(argc!=5){std::cerr<<"usage: rawr-reap-mask <scores.csv> <target_bytes> <dense_bytes> <output.json>\n";return 2;}
 uint64_t target=0,dense=0; try{target=std::stoull(argv[2]);dense=std::stoull(argv[3]);}catch(...){return 2;} if(target<=dense){std::cerr<<"INFEASIBLE_DENSE_BYTES\n";return 4;}
 std::ifstream f(argv[1]); if(!f){std::cerr<<"SCORES_OPEN_FAILED\n";return 4;} std::vector<Row> rows; std::unordered_set<std::string> seen; std::string line; while(std::getline(f,line)){if(line.empty()||line[0]=='#')continue; std::replace(line.begin(),line.end(),',',' '); std::istringstream s(line); Row r; if(!(s>>r.layer>>r.expert>>r.bytes>>r.score>>r.routes)||!r.bytes||r.routes==0||!std::isfinite(r.score)){std::cerr<<"INVALID_SCORE_ROW\n";return 4;} const std::string key=std::to_string(r.layer)+":"+std::to_string(r.expert); if(!seen.insert(key).second){std::cerr<<"DUPLICATE_SCORE_KEY\n";return 4;} rows.push_back(r);} if(rows.empty()){std::cerr<<"NO_SCORES\n";return 4;}
 std::sort(rows.begin(),rows.end(),[](auto&a,auto&b){return a.score>b.score||(a.score==b.score&&(a.layer<b.layer||(a.layer==b.layer&&a.expert<b.expert)));}); uint64_t budget=target-dense,used=0; std::string mask;
 for(auto&r:rows){bool keep = (r.bytes<=budget-used); if(keep)used+=r.bytes; mask+=std::to_string(r.layer)+":"+std::to_string(r.expert)+":"+(keep?"1":"0")+"\n";}
 if(used==0){std::cerr<<"NO_FEASIBLE_SELECTION\n";return 4;} std::ofstream o(std::string(argv[4])+".tmp",std::ios::binary); if(!o)return 4; o<<"{\"target_bytes\":"<<target<<",\"dense_bytes\":"<<dense<<",\"selected_bytes\":"<<used<<",\"mask_sha256\":\""<<sha256(mask)<<"\",\"complete\":true}\n"; o.close(); if(!MoveFileExA((std::string(argv[4])+".tmp").c_str(),argv[4],MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH))return 4; return 0;
}
