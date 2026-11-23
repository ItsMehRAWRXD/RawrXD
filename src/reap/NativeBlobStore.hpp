#pragma once
// Content-addressed GGUF storage compatible with Ollama's sha256-<hex>
// blob naming. This publishes model bytes only; no manifest/tag creation.
#include "NativeGGUFPublisher.hpp"
#include "NativeSHA256.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>

namespace RawrXD { namespace REAP {
enum class BlobError {
    None, InvalidRoot, StageFailure, RepackFailure, HashFailure,
    Conflict, CommitFailure
};
struct BlobResult {
    BlobError error=BlobError::None;
    RepackError repack_error=RepackError::None;
    std::string digest;
    std::string blob_path;
    uint64_t bytes=0;
    bool already_present=false;
};
inline BlobResult StoreRepackedGGUFBlob(const std::string& source,
                                        const std::string& modelRoot,
                                        uint64_t budget=UINT64_MAX) {
    namespace fs=std::filesystem;
    BlobResult result;
    if(source.empty()||modelRoot.empty()) {
        result.error=BlobError::InvalidRoot;return result;
    }
    std::error_code ec;
    const fs::path blobs=fs::path(modelRoot)/"blobs";
    fs::create_directories(blobs,ec);
    if(ec||!fs::is_directory(blobs,ec)||ec) {
        result.error=BlobError::InvalidRoot;return result;
    }
    static std::atomic<uint64_t> serial{0};
    fs::path stageDir;
    bool reserved=false;
    const auto tick=std::chrono::steady_clock::now().time_since_epoch().count();
    for(int attempt=0;attempt<32;++attempt) {
        stageDir=blobs/(".reap-blob-"+std::to_string(tick)+"-"+
                        std::to_string(serial.fetch_add(1)));
        ec.clear();
        if(fs::create_directory(stageDir,ec)){reserved=true;break;}
        if(ec && ec!=std::errc::file_exists)break;
    }
    if(!reserved){result.error=BlobError::StageFailure;return result;}
    struct Cleanup {
        fs::path path;
        ~Cleanup(){std::error_code ignored;fs::remove_all(path,ignored);}
    } cleanup{stageDir};
    const fs::path stage=stageDir/"model.gguf";
    result.repack_error=RepackGGUF(source,stage.string(),budget);
    if(result.repack_error!=RepackError::None) {
        result.error=BlobError::RepackFailure;return result;
    }
    result.bytes=fs::file_size(stage,ec);
    if(ec||result.bytes>budget||result.bytes<24||
       !HashFileSHA256(stage.string(),result.digest)) {
        result.error=BlobError::HashFailure;return result;
    }
    const fs::path target=blobs/("sha256-"+result.digest);
    result.blob_path=target.string();
    // A preexisting digest must be verified rather than trusted by name.
    if(fs::exists(target,ec)) {
        std::string actual;
        if(!HashFileSHA256(target.string(),actual)||actual!=result.digest) {
            result.error=BlobError::Conflict;return result;
        }
        result.already_present=true;return result;
    }
    if(ec){result.error=BlobError::CommitFailure;return result;}
    fs::create_hard_link(stage,target,ec);
    if(ec) {
        // Another writer may have won the same digest race.
        std::string actual;
        if(fs::exists(target)&&HashFileSHA256(target.string(),actual)&&
           actual==result.digest) {
            result.already_present=true;return result;
        }
        result.error=BlobError::CommitFailure;return result;
    }
    return result;
}
}} // namespace RawrXD::REAP
