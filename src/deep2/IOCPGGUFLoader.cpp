// ============================================================================
// IOCPGGUFLoader.cpp
// Overlapped IOCP-based GGUF loader — eliminates OS paging/thrashing
// ============================================================================

#include "IOCPGGUFLoader.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <io.h>
#include <fcntl.h>

namespace Deep2 {

// ============================================================================
// Open / Close
// ============================================================================

bool IOCPGGUFLoader::Open(const std::wstring& path, const Config& config) {
    config_ = config;
    return OpenInternal(path);
}

bool IOCPGGUFLoader::Open(const std::string& path, const Config& config) {
    config_ = config;
    // Convert UTF-8 to UTF-16 for Windows API
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return false;
    std::wstring wpath(wlen, 0);
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);
    return OpenInternal(wpath);
}

bool IOCPGGUFLoader::OpenInternal(const std::wstring& path) {
    DWORD flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED;
    if (config_.noBuffering) {
        flags |= FILE_FLAG_NO_BUFFERING;
    }

    hFile_ = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        flags,
        nullptr
    );

    if (hFile_ == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[IOCPGGUF] CreateFileW failed: %lu\n", GetLastError());
        return false;
    }

    if (config_.useIOCP) {
        hIOCP_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, config_.maxConcurrentReads);
        if (!hIOCP_) {
            fprintf(stderr, "[IOCPGGUF] CreateIoCompletionPort failed: %lu\n", GetLastError());
            CloseHandle(hFile_);
            hFile_ = INVALID_HANDLE_VALUE;
            return false;
        }

        // Associate file with IOCP
        if (!CreateIoCompletionPort(hFile_, hIOCP_, 0, 0)) {
            fprintf(stderr, "[IOCPGGUF] Associate IOCP failed: %lu\n", GetLastError());
            CloseHandle(hIOCP_);
            CloseHandle(hFile_);
            hIOCP_ = nullptr;
            hFile_ = INVALID_HANDLE_VALUE;
            return false;
        }
    }

    if (config_.verbose) {
        printf("[IOCPGGUF] Opened: %ls (IOCP=%s, NoBuffering=%s)\n",
               path.c_str(),
               config_.useIOCP ? "yes" : "no",
               config_.noBuffering ? "yes" : "no");
    }
    return true;
}

void IOCPGGUFLoader::Close() {
    if (hFile_ != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile_);
        hFile_ = INVALID_HANDLE_VALUE;
    }
    if (hIOCP_) {
        CloseHandle(hIOCP_);
        hIOCP_ = nullptr;
    }
}

// ============================================================================
// Header Parsing (small reads, synchronous OK)
// ============================================================================

bool IOCPGGUFLoader::ParseHeader(ModelMetadata& outMetadata,
                                  std::vector<TensorInfo>& outTensors,
                                  uint64_t& outDataOffset) {
    if (hFile_ == INVALID_HANDLE_VALUE) return false;

    // Read first 4KB to get header
    alignas(4096) char headerBuf[4096];
    DWORD read = 0;
    OVERLAPPED ov = {};

    if (!ReadFile(hFile_, headerBuf, sizeof(headerBuf), &read, &ov)) {
        if (GetLastError() != ERROR_IO_PENDING) {
            fprintf(stderr, "[IOCPGGUF] Header read failed: %lu\n", GetLastError());
            return false;
        }
        // Wait for async completion
        if (!GetOverlappedResult(hFile_, &ov, &read, TRUE)) {
            fprintf(stderr, "[IOCPGGUF] Header read completion failed: %lu\n", GetLastError());
            return false;
        }
    }

    // Parse magic, version, counts using GGUFLoader helpers
    // For now, use a simple FILE* wrapper to reuse existing parser
    // TODO: refactor GGUFLoader to work with memory buffers instead of FILE*
    // Duplicate the HANDLE so fclose doesn't close our original
    HANDLE hDup = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), hFile_, GetCurrentProcess(), &hDup,
                         0, FALSE, DUPLICATE_SAME_ACCESS)) {
        fprintf(stderr, "[IOCPGGUF] DuplicateHandle failed: %lu\n", GetLastError());
        return false;
    }
    int fd = _open_osfhandle((intptr_t)hDup, _O_RDONLY);
    if (fd < 0) {
        CloseHandle(hDup);
        fprintf(stderr, "[IOCPGGUF] _open_osfhandle failed\n");
        return false;
    }
    FILE* fp = _fdopen(fd, "rb");
    if (!fp) {
        _close(fd);
        fprintf(stderr, "[IOCPGGUF] _fdopen failed\n");
        return false;
    }

    // Parse using existing GGUFLoader logic
    // This is a transitional approach — eventually all parsing should be buffer-based
    // Use the static Load API; we already have the file open, so parse manually
    // For now, parse header via the FILE* wrapper then close carefully
    uint64_t tensorCount = 0, kvCount = 0;
    bool ok = GGUFLoader::ParseHeader(fp, tensorCount, kvCount);
    if (ok) {
        std::unordered_map<std::string, std::string> rawMeta;
        ok = GGUFLoader::ParseMetadataKV(fp, kvCount, outMetadata, rawMeta);
    }
    if (ok) {
        ok = GGUFLoader::ParseTensors(fp, tensorCount, outTensors, outDataOffset, config_.verbose);
    }

    // fclose will close the duplicated HANDLE (hDup), but not our original hFile_
    fclose(fp);

    return ok;
}

// ============================================================================
// Async Tensor Data Loading
// ============================================================================

bool IOCPGGUFLoader::LoadTensorDataAsync(const std::vector<TensorInfo>& tensors,
                                          uint64_t dataOffset) {
    if (hFile_ == INVALID_HANDLE_VALUE) return false;
    if (!config_.useIOCP || !hIOCP_) {
        return LoadTensorDataSync(tensors, dataOffset);
    }

    // For out-of-core: register tensors with Elastic but don't load yet
    if (elastic_ && config_.registerWithElastic) {
        for (const auto& t : tensors) {
            uint32_t layerIdx = ~0u;
            uint32_t expertIdx = ~0u;

            // Parse layer/expert from name: "blk.N.attn_q.weight" or "blk.N.expert.E.ffn_gate.weight"
            // Simple heuristic
            if (t.name.find("blk.") == 0) {
                size_t dot = t.name.find('.', 4);
                if (dot != std::string::npos) {
                    layerIdx = (uint32_t)atoi(t.name.c_str() + 4);
                }
                size_t exp = t.name.find("expert.");
                if (exp != std::string::npos) {
                    expertIdx = (uint32_t)atoi(t.name.c_str() + exp + 7);
                }
            }

            TensorFormat fmt = TensorFormat::Unknown;
            switch (t.type) {
                case GGMLType::GGML_TYPE_Q4_0: fmt = TensorFormat::Q4_0; break;
                case GGMLType::GGML_TYPE_Q4_1: fmt = TensorFormat::Q4_1; break;
                case GGMLType::GGML_TYPE_Q4_K: fmt = TensorFormat::Q4_K; break;
                case GGMLType::GGML_TYPE_Q5_K: fmt = TensorFormat::Q5_K; break;
                case GGMLType::GGML_TYPE_Q6_K: fmt = TensorFormat::Q6_K; break;
                case GGMLType::GGML_TYPE_Q8_0: fmt = TensorFormat::Q8_0; break;
                case GGMLType::GGML_TYPE_F16:  fmt = TensorFormat::FP16; break;
                case GGMLType::GGML_TYPE_F32:  fmt = TensorFormat::FP32; break;
                default: break;
            }

            elastic_->RegisterTensor(t.name, layerIdx, expertIdx,
                                      dataOffset + t.offset, t.size, fmt, nullptr);
        }

        if (config_.verbose) {
            printf("[IOCPGGUF] Registered %zu tensors with Elastic Residency\n", tensors.size());
        }
        return true;
    }

    // If no Elastic manager, fall back to synchronous load
    return LoadTensorDataSync(tensors, dataOffset);
}

// ============================================================================
// Synchronous Fallback (for small models or testing)
// ============================================================================

bool IOCPGGUFLoader::LoadTensorDataSync(const std::vector<TensorInfo>& tensors,
                                         uint64_t dataOffset) {
    if (hFile_ == INVALID_HANDLE_VALUE) return false;

    for (auto& t : tensors) {
        if (t.size == 0) continue;

        // Allocate aligned buffer
        size_t allocSize = (t.size + 4095) & ~4095;
        void* buffer = VirtualAlloc(nullptr, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            fprintf(stderr, "[IOCPGGUF] VirtualAlloc failed for %s\n", t.name.c_str());
            return false;
        }

        uint64_t fileOffset = dataOffset + t.offset;
        DWORD read = 0;
        OVERLAPPED ov = {};
        ov.Offset = (DWORD)(fileOffset & 0xFFFFFFFF);
        ov.OffsetHigh = (DWORD)(fileOffset >> 32);

        auto t0 = std::chrono::steady_clock::now();

        if (!ReadFile(hFile_, buffer, (DWORD)t.size, &read, &ov)) {
            if (GetLastError() == ERROR_IO_PENDING) {
                if (!GetOverlappedResult(hFile_, &ov, &read, TRUE)) {
                    fprintf(stderr, "[IOCPGGUF] Sync read failed for %s: %lu\n",
                            t.name.c_str(), GetLastError());
                    VirtualFree(buffer, 0, MEM_RELEASE);
                    return false;
                }
            } else {
                fprintf(stderr, "[IOCPGGUF] ReadFile failed for %s: %lu\n",
                        t.name.c_str(), GetLastError());
                VirtualFree(buffer, 0, MEM_RELEASE);
                return false;
            }
        }

        auto t1 = std::chrono::steady_clock::now();
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

        totalBytesRead_ += read;
        totalReads_++;
        totalLatencyUs_ += us;

        // Store in tensor (caller owns memory)
        const_cast<TensorInfo&>(t).data = buffer;

        if (config_.verbose) {
            printf("[IOCPGGUF] Loaded %s: %zu bytes in %lld us\n",
                   t.name.c_str(), (size_t)read, (long long)us);
        }
    }

    return true;
}

// ============================================================================
// Telemetry
// ============================================================================

IOCPGGUFLoader::Telemetry IOCPGGUFLoader::GetTelemetry() const {
    Telemetry t;
    t.totalBytesRead = totalBytesRead_.load();
    t.totalReads = totalReads_.load();
    t.totalErrors = totalErrors_.load();
    uint64_t reads = totalReads_.load();
    t.avgReadLatencyMs = reads > 0 ? (double)totalLatencyUs_.load() / (double)reads / 1000.0 : 0.0;
    return t;
}

} // namespace Deep2
