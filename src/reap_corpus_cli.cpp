#include "deep2/CanonicalTokenizer.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <set>

namespace fs = std::filesystem;

static std::string sha256(const std::string& s) {
    BCRYPT_ALG_HANDLE a=nullptr; BCRYPT_HASH_HANDLE h=nullptr; DWORD olen=0, hlen=0, got=0;
    if (BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)!=0 ||
        BCryptGetProperty(a,BCRYPT_OBJECT_LENGTH,(PUCHAR)&olen,sizeof(olen),&got,0)!=0 ||
        BCryptGetProperty(a,BCRYPT_HASH_LENGTH,(PUCHAR)&hlen,sizeof(hlen),&got,0)!=0) throw std::runtime_error("CNG init failed");
    std::vector<UCHAR> obj(olen), out(hlen);
    if (BCryptCreateHash(a,&h,obj.data(),olen,nullptr,0,0)!=0 ||
        BCryptHashData(h,(PUCHAR)s.data(),(ULONG)s.size(),0)!=0 ||
        BCryptFinishHash(h,out.data(),hlen,0)!=0) throw std::runtime_error("CNG hash failed");
    BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(a,0);
    std::ostringstream o; for(auto b:out) o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b; return o.str();
}
static std::string esc(const std::string& s) {
    std::ostringstream o; for(unsigned char c:s) { if(c=='"')o<<"\\\""; else if(c=='\\')o<<"\\\\";
      else if(c=='\n')o<<"\\n"; else if(c=='\r')o<<"\\r"; else if(c=='\t')o<<"\\t";
      else if(c<0x20){o<<"\\u"<<std::hex<<std::setw(4)<<std::setfill('0')<<(int)c;} else o<<c; } return o.str();
}
static bool utf8(const std::string& s) {
    size_t i=0; while(i<s.size()){ unsigned c=(unsigned char)s[i]; size_t n=0;
      if(c<=0x7f)n=1; else if(c>=0xc2&&c<=0xdf)n=2; else if(c==0xe0)n=3; else if(c>=0xe1&&c<=0xec||c>=0xee&&c<=0xef)n=3; else if(c==0xed)n=3; else if(c>=0xf0&&c<=0xf3)n=4; else if(c==0xf4)n=4; else return false;
      if(i+n>s.size())return false; if(n==3&&c==0xe0&&((unsigned char)s[i+1]<0xa0))return false;
      if(n==3&&c==0xed&&((unsigned char)s[i+1]>=0xa0))return false; if(n==4&&c==0xf0&&((unsigned char)s[i+1]<0x90))return false;
      if(n==4&&c==0xf4&&((unsigned char)s[i+1]>0x8f))return false;
      for(size_t j=1;j<n;++j)if(((unsigned char)s[i+j]&0xc0)!=0x80)return false; i+=n; } return true;
}
int main(int argc,char**argv){
    if(argc!=4){std::cerr<<"usage: rawr-reap-corpus <tokenizer.gguf> <corpus-root> <output.jsonl>\n";return 2;}
    const fs::path root=fs::absolute(argv[2]);
    if(!fs::exists(root)||!fs::is_directory(root)){std::cerr<<"CORPUS_ROOT_INVALID\n";return 2;}
    std::cerr<<"TOKENIZER_LOAD_BEGIN "<<argv[1]<<"\n";
    Deep2::CanonicalTokenizer& tok=Deep2::CanonicalTokenizer::Instance();
    if(!tok.LoadFromGGUF(argv[1])){std::cerr<<"TOKENIZER_LOAD_FAILED: "<<tok.LastError()<<"\n";return 1;}
    std::cerr<<"TOKENIZER_LOAD_OK vocab="<<tok.VocabSize()<<"\n";
    const std::set<std::string> exts={".cpp",".hpp",".h",".ps1",".md",".json",".yaml",".yml",".txt"};
    const std::set<std::string> banned={"build",".git","evidence","logs","models","OllamaModels",".kilo","~dev",".worktrees","worktrees","node_modules","3rdparty","compilers","test_results",".vs","dist","packages",".cache",".archive","bin"};
    std::map<std::string,std::vector<std::pair<std::string,std::string>>> buckets;
    std::cerr<<"CORPUS_SCAN_BEGIN root="<<root.string()<<"\n";
    size_t files_seen=0, bytes_seen=0;
    fs::directory_options opts = fs::directory_options::skip_permission_denied;
    for(auto it=fs::recursive_directory_iterator(root, opts);it!=fs::recursive_directory_iterator();++it){
      // Never recurse through junctions/reparse points or unbounded generated
      // trees.  Windows worktrees can otherwise form cycles and terminate the
      // process with a fail-fast stack-overrun before calibration begins.
      if(it.depth() > 32){ it.disable_recursion_pending(); continue; }
      std::error_code fec;
      const auto attrs = fs::status(it->path(), fec).type();
      (void)attrs;
      const auto st = it->symlink_status(fec);
      if(!fec && fs::is_directory(st)) {
          const DWORD a = GetFileAttributesW(it->path().c_str());
          if(a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_REPARSE_POINT)) {
              it.disable_recursion_pending(); continue;
          }
      }
      const std::string leaf=it->path().filename().string();
      if(it->is_directory()) {
          if(leaf==".git"||leaf==".kilo"||leaf==".worktrees"||leaf==".cache"||leaf==".archive"||leaf==".vs"||leaf=="evidence"||leaf=="logs"||leaf=="models"||leaf=="OllamaModels"||leaf.rfind("build",0)==0||leaf=="node_modules"||leaf=="worktrees"||leaf=="bin") it.disable_recursion_pending();
          continue;
      }
      if(++files_seen > 200000) { std::cerr<<"CORPUS_FILE_LIMIT\n"; return 4; }
      if(!it->is_regular_file())continue; auto p=it->path(); std::string rel=p.lexically_relative(root).string();
        bool skip=false; for(auto& part:p.relative_path()) {
            const std::string partName = part.string();
            if (banned.count(partName) || partName == "CMakeFiles" ||
                partName.rfind("build", 0) == 0 || partName.rfind(".build", 0) == 0) skip=true;
        }
      const auto fn=p.filename().string(); const bool prompt_file=p.extension()==".txt" && fn.find("prompt")!=std::string::npos;
      if(skip||(!exts.count(p.extension().string()))|| (p.extension()==".txt"&&!prompt_file))continue;
      std::error_code sec; const auto fsz=fs::file_size(p,sec); if(sec||fsz>(1ull<<20)) continue;
      std::ifstream f(p,std::ios::binary); std::string raw((std::istreambuf_iterator<char>(f)),{}); if(!utf8(raw)){std::cerr<<"SKIP_INVALID_UTF8 "<<rel<<"\n";continue;}
      bytes_seen += raw.size(); if(bytes_seen > (1ull<<30)) { std::cerr<<"CORPUS_BYTE_LIMIT\n"; return 4; }
      // Keep tokenizer calls bounded.  A source file is a corpus source, not
      // an unbounded single sequence; very large translation units can exhaust
      // the tokenizer's temporary buffers before the 2048-token clip is
      // reached.  Truncate only at a validated UTF-8 boundary.
      constexpr size_t kMaxSourceBytes = 1u << 16;
      if(raw.size() > kMaxSourceBytes) {
        raw.resize(kMaxSourceBytes);
        while(!utf8(raw) && !raw.empty()) raw.pop_back();
      }
      std::string clean; for(size_t i=0;i<raw.size();++i){if(raw[i]=='\r'){clean+='\n';if(i+1<raw.size()&&raw[i+1]=='\n')++i;}else clean+=raw[i];}
      std::string d=prompt_file?"prompts":(p.extension()==".ps1"?"powershell":p.extension()==".md"?"markdown":(p.extension()==".json"||p.extension()==".yaml"||p.extension()==".yml")?"json_yaml":"cpp");
      if(!clean.empty()) {
          // Eight bounded source files per domain are sufficient for the
          // deterministic window pass. Stop discovery once coverage exists;
          // this prevents repository-wide accumulation.
          if(buckets[d].size() < 8) buckets[d].push_back({rel,clean});
          if(buckets["cpp"].size()>=8 && buckets["powershell"].size()>=8 &&
             buckets["markdown"].size()>=8 && buckets["json_yaml"].size()>=8 &&
             buckets["prompts"].size()>=8) break;
      }
    }
    // Directory iteration order is filesystem-dependent.  Sort each domain
    // by relative path so repeated calibration runs select identical files.
    for(auto& kv : buckets) std::sort(kv.second.begin(), kv.second.end(),
        [](const auto& a,const auto& b){ return a.first < b.first; });
    for(auto& kv:buckets) std::sort(kv.second.begin(),kv.second.end(),[](const auto& a,const auto& b){return a.first<b.first;});
    std::vector<std::string> dom={"cpp","powershell","markdown","json_yaml","prompts"}; std::string out; size_t n=0, stride=0;
    while(n<256){std::string d=dom[stride%dom.size()]; auto& b=buckets[d]; if(b.empty()){std::cerr<<"MISSING_DOMAIN "<<d<<"\n";return 4;} auto& src=b[(stride/dom.size())%b.size()];
      std::string sample=src.second; if(sample.size()>16384) sample.resize(16384);
      std::cerr<<"ENCODE domain="<<d<<" source="<<src.first<<" bytes="<<sample.size()<<"\n";
      auto ids=tok.Encode(sample); if(ids.empty()){++stride;continue;} if(ids.size()>2048)ids.resize(2048); auto text=tok.Decode(ids); if(text.empty()){++stride;continue;}
      std::ostringstream line; line<<"{\"id\":\"src_"<<std::setw(6)<<std::setfill('0')<<(n+1)<<"\",\"text\":\""<<esc(text)<<"\",\"domain\":\""<<d<<"\",\"source\":\""<<esc(src.first)<<"\",\"source_sha256\":\""<<sha256(src.second)<<"\",\"sha256\":\""<<sha256(text)<<"\"}\n"; out+=line.str(); ++n; ++stride;
    }
    const std::string output=argv[3];
    const std::string tmp=output+".tmp";
    {std::ofstream f(tmp,std::ios::binary); if(!f){std::cerr<<"CORPUS_OUTPUT_OPEN_FAILED\n";return 1;} f.write(out.data(),out.size()); f.flush(); if(!f){std::remove(tmp.c_str());std::cerr<<"CORPUS_OUTPUT_WRITE_FAILED\n";return 1;}}
    if(!MoveFileExA(tmp.c_str(),output.c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)){std::remove(tmp.c_str());std::cerr<<"CORPUS_ATOMIC_RENAME_FAILED win32="<<GetLastError()<<"\n";return 1;}
    std::cout<<"records=256 tokenizer_vocab="<<tok.VocabSize()<<" dataset_sha256="<<sha256(out)<<"\n"; return 0;
}
