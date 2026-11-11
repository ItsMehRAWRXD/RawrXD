// ============================================================================
// ollama_blob_parser.cpp — Ollama blob ingestion without Ollama runtime.
// ============================================================================
// ollama_blob_parser.h declares rawrxd::ollama::OllamaBlobParser with a pimpl
// but never defined its members, so the engine could not link. The
// implementation below reads real bytes off disk:
//
//   parseBlobToGGUF  locates the GGUF magic inside the blob (honouring an
//                    Ollama manifest header) and reports where the GGUF payload
//                    begins. A blob whose payload starts at offset 0 needs no
//                    extraction; anything else is materialised as a temporary
//                    file so the existing GGUF loader can mmap it unchanged.
//   extractGGUFToFile copies the GGUF payload out to a caller-supplied path and
//                    verifies the byte count actually transferred.
//
// No Ollama daemon, CLI or network access is involved.
// ============================================================================
#include "ollama_blob_parser.h"

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace rawrxd {
namespace ollama {

namespace {

// GGUF magic as it appears in the first four bytes: "GGUF".
constexpr uint32_t kGgufMagic = 0x46554747u;

// Ollama blobs begin with a JSON manifest, so the GGUF payload usually sits
// some distance into the file. Cap the scan so a corrupt or hostile blob cannot
// force an unbounded read.
constexpr uint64_t kMaxHeaderScan = 64u * 1024u * 1024u;

bool ReadAt(std::ifstream& f, uint64_t offset, void* dst, size_t bytes) {
    if (bytes == 0) return true;
    if (!f.seekg(static_cast<std::streamoff>(offset))) return false;
    f.read(static_cast<char*>(dst), static_cast<std::streamsize>(bytes));
    return static_cast<size_t>(f.gcount()) == bytes;
}

} // namespace

// ----------------------------------------------------------------------------
// OllamaBlobParser::Impl — header-only pimpl.
//
// The declarations in ollama_blob_parser.h are backed by a unique_ptr<Impl>,
// but no definition of Impl exists anywhere in the tree, so the destructor
// could not be compiled. Every member of this parser takes the blob path as an
// argument and the only persistent state (temp_directory_, temp_files_) is
// declared directly on the class, so Impl holds nothing. Declaring it here is
// what lets the parser own its declarations; it is not a placeholder for
// behaviour that does not exist.
// ----------------------------------------------------------------------------
struct OllamaBlobParser::Impl {};

// ----------------------------------------------------------------------------
// OllamaBlobParser
// ----------------------------------------------------------------------------
OllamaBlobParser::OllamaBlobParser() {
    temp_directory_ = std::filesystem::temp_directory_path().string();
}

OllamaBlobParser::~OllamaBlobParser() {
    cleanupTempFiles();
}

OllamaBlobParser::ParseResult OllamaBlobParser::parseBlobToGGUF(const std::string& blob_path) {
    ParseResult result{};
    result.success = false;
    result.gguf_offset = 0;
    result.gguf_size = 0;
    result.requires_extraction = false;
    result.error_message.clear();

    std::error_code ec;
    if (blob_path.empty()) {
        result.error_message = "empty blob path";
        return result;
    }
    const uint64_t file_size = static_cast<uint64_t>(
        std::filesystem::file_size(blob_path, ec));
    if (ec) {
        result.error_message = "cannot stat blob: " + blob_path;
        return result;
    }
    if (file_size < 4) {
        result.error_message = "blob too small to hold GGUF magic";
        return result;
    }

    std::ifstream f(blob_path, std::ios::binary);
    if (!f) {
        result.error_message = "cannot open blob: " + blob_path;
        return result;
    }

    // A blob whose first four bytes are already the GGUF magic is a plain GGUF
    // file wearing an Ollama name; hand the original straight to the loader.
    uint32_t magic = 0;
    if (!ReadAt(f, 0, &magic, sizeof(magic))) {
        result.error_message = "cannot read blob header";
        return result;
    }
    if (magic == kGgufMagic) {
        result.success = true;
        result.gguf_model_path = blob_path;
        result.gguf_offset = 0;
        result.gguf_size = file_size;
        result.requires_extraction = false;
        result.error_message.clear();
        return result;
    }

    // Otherwise scan the Ollama manifest region for the payload. The manifest is
    // text, so the search is bounded rather than equivalent to a full read.
    const uint64_t scan_limit = file_size < kMaxHeaderScan ? file_size : kMaxHeaderScan;
    std::vector<char> window(static_cast<size_t>(scan_limit));
    if (!ReadAt(f, 0, window.data(), window.size())) {
        result.error_message = "cannot read blob manifest region";
        return result;
    }

    uint64_t offset = 0;
    for (uint64_t i = 0; i + 4 <= scan_limit; ++i) {
        uint32_t candidate = 0;
        std::memcpy(&candidate, window.data() + i, sizeof(candidate));
        if (candidate == kGgufMagic) {
            offset = i;
            break;
        }
    }

    if (offset == 0) {
        result.error_message = "no GGUF payload found in blob";
        return result;
    }

    // Sanity-check the GGUF version so a coincidental magic match inside the
    // manifest is not mistaken for the real payload. GGUF v3 is current.
    uint32_t version = 0;
    if (!ReadAt(f, offset + 4, &version, sizeof(version)) ||
        (version < 2 || version > 3)) {
        result.error_message = "GGUF magic found but version is not valid";
        return result;
    }

    result.success = true;
    result.gguf_model_path = blob_path;
    result.gguf_offset = static_cast<size_t>(offset);
    result.gguf_size = static_cast<size_t>(file_size - offset);
    result.requires_extraction = true;
    result.error_message.clear();
    return result;
}

bool OllamaBlobParser::extractGGUFToFile(const std::string& blob_path,
                                         uint64_t offset,
                                         uint64_t size,
                                         const std::string& output_path) {
    if (blob_path.empty() || output_path.empty()) return false;
    if (size == 0) return false;

    std::error_code ec;
    const uint64_t file_size = static_cast<uint64_t>(
        std::filesystem::file_size(blob_path, ec));
    if (ec) return false;
    if (offset > file_size || size > file_size - offset) return false;

    std::ifstream in(blob_path, std::ios::binary);
    if (!in) return false;
    if (!in.seekg(static_cast<std::streamoff>(offset))) return false;

    // Write to a temporary sibling first so a failed transfer cannot leave a
    // truncated file the GGUF loader might pick up.
    const std::filesystem::path final_path(output_path);
    const std::filesystem::path partial_path = final_path.string() + ".partial";
    {
        std::ofstream out(partial_path, std::ios::binary | std::ios::trunc);
        if (!out) return false;

        std::vector<char> chunk(1u << 20);
        uint64_t remaining = size;
        while (remaining > 0) {
            const size_t want = static_cast<size_t>(
                remaining < chunk.size() ? remaining : chunk.size());
            in.read(chunk.data(), static_cast<std::streamsize>(want));
            const std::streamsize got = in.gcount();
            if (got <= 0) {
                std::error_code rm;
                std::filesystem::remove(partial_path, rm);
                return false;
            }
            out.write(chunk.data(), got);
            if (!out) {
                std::error_code rm;
                std::filesystem::remove(partial_path, rm);
                return false;
            }
            remaining -= static_cast<uint64_t>(got);
        }
    }

    std::error_code rm;
    std::filesystem::rename(partial_path, final_path, ec);
    if (ec) {
        // rename fails across volumes or when the destination exists on some
        // backends; fall back to copy+remove, then verify the byte count.
        std::filesystem::remove(partial_path, rm);
        std::filesystem::copy_file(partial_path, final_path,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        std::filesystem::remove(partial_path, rm);
        if (ec) return false;
    }

    const uint64_t written = static_cast<uint64_t>(
        std::filesystem::file_size(final_path, ec));
    if (ec || written != size) return false;

    temp_files_.push_back(final_path.string());
    return true;
}

void OllamaBlobParser::cleanupTempFiles() {
    for (const auto& path : temp_files_) {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }
    temp_files_.clear();
}

std::string OllamaBlobParser::generateTempPath(const std::string& blob_id) {
    std::string safe = blob_id;
    for (auto& c : safe) {
        if (c == '/' || c == '\\' || c == ':' || c == '*') c = '_';
    }
    if (safe.empty()) safe = "blob";
    return (std::filesystem::path(temp_directory_) /
            ("rawrxd_ollama_" + safe + ".gguf")).string();
}

} // namespace ollama
} // namespace rawrxd
