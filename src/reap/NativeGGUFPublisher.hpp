#pragma once
// Native staged publisher for GGUF artifacts. Does not overwrite an existing
// destination; the caller must choose a new artifact name.
#include "NativeGGUFRepacker.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <string>
#include <system_error>

namespace RawrXD { namespace REAP {
enum class PublishError {
    None, InvalidPath, DestinationExists, StageCreation,
    RepackFailed, VerificationFailed, CommitFailed
};
struct PublishResult {
    PublishError error = PublishError::None;
    RepackError repack_error = RepackError::None;
    uint64_t published_bytes = 0;
};
inline PublishResult PublishRepackedGGUF(const std::string& source,
                                         const std::string& destination,
                                         uint64_t max_bytes=UINT64_MAX,
                                         bool convert_f32_to_f16=false) {
    namespace fs=std::filesystem;
    PublishResult result;
    std::error_code ec;
    const fs::path target(destination), input(source);
    if(source.empty()||destination.empty()||!target.has_filename()||
       !fs::exists(input,ec)||ec) {
        result.error=PublishError::InvalidPath;return result;
    }
    // Reject aliases of the source, including symlinks and hard links.
    // A source/destination collision must not destroy model input.
    if(fs::equivalent(input,target,ec)) {
        result.error=PublishError::InvalidPath;return result;
    }
    ec.clear();
    if(fs::exists(target,ec)||ec) {
        result.error=PublishError::DestinationExists;return result;
    }
    const auto parent=target.has_parent_path()?target.parent_path():fs::path(".");
    if(!fs::exists(parent,ec)||ec) {
        result.error=PublishError::InvalidPath;return result;
    }
    static std::atomic<uint64_t> serial{0};
    const auto tick=std::chrono::steady_clock::now().time_since_epoch().count();
    fs::path stageDirectory;
    // Reserve the staging namespace atomically. An existence check alone
    // permits two concurrent writers to truncate the same staging file.
    bool reserved=false;
    for(unsigned attempt=0;attempt<32;++attempt) {
        stageDirectory=parent/(target.filename().string()+".reap-part-"+
              std::to_string(tick)+"-"+std::to_string(serial.fetch_add(1)));
        ec.clear();
        if(fs::create_directory(stageDirectory,ec)){reserved=true;break;}
        if(ec && ec!=std::errc::file_exists)break;
    }
    if(!reserved){result.error=PublishError::StageCreation;return result;}
    struct Cleanup {
        fs::path directory;
        ~Cleanup(){std::error_code ignored;std::filesystem::remove_all(directory,ignored);}
    } cleanup{stageDirectory};
    const fs::path stage=stageDirectory/"artifact.gguf";
    result.repack_error=RepackGGUF(source,stage.string(),max_bytes,convert_f32_to_f16);
    if(result.repack_error!=RepackError::None) {
        result.error=PublishError::RepackFailed;return result;
    }
    const uint64_t bytes=fs::file_size(stage,ec);
    if(ec||bytes>max_bytes||bytes<24) {
        result.error=PublishError::VerificationFailed;return result;
    }
    // Hard-link publication is atomic and no-replace: link creation fails
    // when target exists, avoiding rename's platform-specific overwrite.
    // Filesystems without hard links fail closed instead of overwriting.
    fs::create_hard_link(stage,target,ec);
    if(ec){result.error=PublishError::CommitFailed;return result;}
    result.published_bytes=bytes;
    return result;
}
}} // namespace RawrXD::REAP
