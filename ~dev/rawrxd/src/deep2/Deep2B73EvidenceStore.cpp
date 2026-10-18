#include "Deep2B73EvidenceStore.hpp"
#include <fstream>
#include <cstdio>
#include <cerrno>

#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
#include <filesystem>
#endif

namespace Deep2 {

bool B73EvidenceStore::readAll(const std::string& path,std::string& out) noexcept {
    std::ifstream f(path,std::ios::binary);
    if(!f) return false;
    out.assign((std::istreambuf_iterator<char>(f)),
               std::istreambuf_iterator<char>());
    return bool(f) || f.eof();
}

B73StoredReceipt B73EvidenceStore::writeAtomic(
    const std::string& dir,
    const std::string& stem,
    const std::string& text) noexcept {

    B73StoredReceipt r{};
    if(stem.empty()) {r.failure="STEM_EMPTY";return r;}

#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
    try {
        std::filesystem::create_directories(dir);
    } catch (...) {
        r.failure="MKDIR_FAIL";return r;
    }
#endif

    const std::string receipt=dir+"/"+stem+".receipt.txt";
    const std::string hash=dir+"/"+stem+".sha256";
    const std::string tmpR=receipt+".tmp";
    const std::string tmpH=hash+".tmp";

    const std::string sha=NoDepSha256::hash(text);

    {
        std::ofstream f(tmpR,std::ios::binary|std::ios::trunc);
        if(!f){r.failure="RECEIPT_OPEN";return r;}
        f.write(text.data(),static_cast<std::streamsize>(text.size()));
        f.flush();
        if(!f){r.failure="RECEIPT_WRITE";return r;}
    }
    {
        std::ofstream f(tmpH,std::ios::binary|std::ios::trunc);
        if(!f){std::remove(tmpR.c_str());r.failure="HASH_OPEN";return r;}
        f<<sha<<"  "<<stem<<".receipt.txt\n";
        f.flush();
        if(!f){std::remove(tmpR.c_str());std::remove(tmpH.c_str());r.failure="HASH_WRITE";return r;}
    }

    std::remove(receipt.c_str());
    std::remove(hash.c_str());
    if(std::rename(tmpR.c_str(),receipt.c_str())!=0) {
        std::remove(tmpR.c_str());std::remove(tmpH.c_str());
        r.failure="RECEIPT_RENAME";return r;
    }
    if(std::rename(tmpH.c_str(),hash.c_str())!=0) {
        r.failure="HASH_RENAME";return r;
    }

    r.pass=true;r.failure="PASS";
    r.receiptPath=receipt;r.hashPath=hash;r.sha256=sha;
    return r;
}

} // namespace Deep2
