// Deterministic unit test of the H5 authorization + scope predicates in
// src/rawr_core.cpp. Bodies copied verbatim from that file so we exercise the
// same logic the shipped tools call, independent of the 3B model controller.
#include <string>
#include <vector>
#include <filesystem>
#include <cstdio>
#include <cassert>
namespace fs = std::filesystem;
static std::string toLower(std::string s){ std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return (char)::tolower(c);}); return s; }

// ---- verbatim from rawr_core.cpp: isExcludedFromWalk (dir+ext sets) ----
static bool isExcludedFromWalk(const fs::path& p){
    std::string name; try{ name=p.filename().string(); }catch(...){ name=""; }
    if(name.empty()) return false;
    std::string lower=toLower(name);
    static const char* dirs[]={ ".git","3rdparty","build","build_vs","build_fresh",
        "build_cert","build_test","out","__pycache__","node_modules",
        "vs_validation",".cache","dist","~dev","_deps",
        "bench",".swarm_runs","evidence","crash_dumps",
        ".archive","_archive","_pre_merge_backup",".backups","logs",
        "full_source","full source","tmp_build" };
    for(const char* d:dirs) if(lower==d) return true;
    for(const char* ext:{".gguf",".dll",".exe",".pdb",".lib",".obj",
        ".zip",".7z",".iso",".bin",".log",".tmp",".exp",".ilk"})
        if(lower.size()>strlen(ext) && lower.compare(lower.size()-strlen(ext),strlen(ext),ext)==0) return true;
    return false;
}
static bool isSourceLikePath(const fs::path& p){
    std::string e; try{ e=toLower(p.extension().string()); }catch(...){return false;}
    static const char* kExt[]={ ".cpp",".cc",".cxx",".c",".h",".hpp",".hh",".inl",".ipp",
        ".asm",".s",".inc",".cu",".cuh",".metal",".glsl",".hlsl",
        ".vert",".frag",".comp",".py",".rs",".go",".java",".cs",
        ".js",".jsx",".ts",".tsx",".m",".mm",".swift",".kt" };
    for(const char* s:kExt) if(e==s) return true;
    return false;
}
static bool isPathAuthorized(const fs::path& p){
    std::vector<std::string> parts;
    try{ for(const auto& part:p) parts.push_back(toLower(part.string())); }catch(...){ return false; }
    for(const auto& s:parts) if(s==".git"||s=="crash_dumps"||s==".backups"||s=="_pre_merge_backup") return false;
    std::string name; try{ name=toLower(p.filename().string()); }catch(...){return false;}
    if(name.empty()) return true;
    static const char* blocked[]={ ".env",".pem",".key",".keystore",".p12",".pfx",".ppk",
        "id_rsa","id_dsa","id_ecdsa","id_ed25519","credentials","secrets" };
    for(const char* b:blocked) if(name.find(b)!=std::string::npos) return false;
    return true;
}
int main(){
    // Authorization: must DENY these even with all=true
    assert(!isPathAuthorized("F:/rawrxd/.env"));
    assert(!isPathAuthorized("F:/rawrxd/.git/config"));
    assert(!isPathAuthorized("F:/rawrxd/.archive/Full_Source/x/y.json"));
    assert(!isPathAuthorized("F:/rawrxd/crash_dumps/a.txt"));
    assert(!isPathAuthorized("F:/rawrxd/_pre_merge_backup/t.cpp"));
    assert(!isPathAuthorized("id_rsa"));
    assert(!isPathAuthorized("server.pem"));
    assert(!isPathAuthorized("secrets.yaml"));
    // Authorized
    assert(isPathAuthorized("F:/rawrxd/src/rawr_core.cpp"));
    assert(isPathAuthorized("F:/rawrxd/README_PRODUCTION.md"));
    // Archive/log excluded from DEFAULT walk
    assert(isExcludedFromWalk(".archive")); assert(isExcludedFromWalk("Full_Source"));
    assert(isExcludedFromWalk("_pre_merge_backup")); assert(isExcludedFromWalk("x.log"));
    // Default source-scope: code yes, data/markup no
    assert(isSourceLikePath("a.cpp")); assert(isSourceLikePath("b.h")); assert(isSourceLikePath("s.py"));
    assert(!isSourceLikePath("a.json")); assert(!isSourceLikePath("a.jsonl"));
    assert(!isSourceLikePath("a.md")); assert(!isSourceLikePath("a.txt"));
    assert(!isSourceLikePath("a.yaml")); assert(!isSourceLikePath("a.bat"));
    printf("H5_UNIT_ALL_PASS\n");
    return 0;
}
