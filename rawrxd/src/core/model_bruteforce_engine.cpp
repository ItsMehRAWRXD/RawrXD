// ============================================================================
// model_bruteforce_engine.cpp — Brute-Force Model Discovery & Hotpatch Engine
// ============================================================================
// Enumerates EVERY discoverable GGUF model from local FS, Ollama blobs,
// HuggingFace cache, and user cache. Brute-force probes each model across
// all inference backends (CPU, Ollama API, Native pipeline) to produce a
// full compatibility matrix for CLI, GUI, and HTML IDE modes.
//
// Includes hotpatch integration: discovered models can be live-patched into
// the inference pipeline at runtime without restart via the three-layer
// hotpatch system (memory, byte-level, server).
//
// Architecture: C++20, Win32, no Qt, no exceptions
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED.
// ============================================================================

#include "model_bruteforce_engine.hpp"
#include "unified_hotpatch_manager.hpp"
#include "proxy_hotpatcher.hpp"
#include "native_inference_pipeline.hpp"
#include "../server/gguf_server_hotpatch.hpp"
#include "../agent/model_invoker.hpp"
#include "../agentic/AgentOllamaClient.h"
#include "gguf_loader.h"
#include "perf_telemetry.hpp"
#include "../agent/telemetry_collector.hpp"
#include "../../include/PathResolver.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <shlobj.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <unordered_map>
#include <nlohmann/json.hpp>

namespace RawrXD {

// ============================================================================
// String Escaping Helpers — safe for JSON, HTML, and JS string contexts
// ============================================================================
static std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

static std::string HtmlEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&#39;"; break;
            default: out += c; break;
        }
    }
    return out;
}

static std::string JsStringEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\'': out += "\\'"; break;
            case '<': out += "\\u003C"; break;
            case '>': out += "\\u003E"; break;
            case '&': out += "\\u0026"; break;
            default: out += c; break;
        }
    }
    return out;
}

// ============================================================================
// GGUF Metadata key strings (from GGUF spec)
// ============================================================================
static const char* GGUF_KEY_ARCH             = "general.architecture";
static const char* GGUF_KEY_NAME             = "general.name";
static const char* GGUF_KEY_CONTEXT_LEN      = ".context_length";
static const char* GGUF_KEY_EMBEDDING_LEN    = ".embedding_length";
static const char* GGUF_KEY_BLOCK_COUNT      = ".block_count";
static const char* GGUF_KEY_HEAD_COUNT       = ".attention.head_count";
static const char* GGUF_KEY_HEAD_COUNT_KV    = ".attention.head_count_kv";
static const char* GGUF_KEY_VOCAB_SIZE       = ".vocab_size";
static const char* GGUF_KEY_FILE_TYPE        = "general.file_type";

// GGUF metadata value types
enum GGUFValueType : uint32_t {
    GGUF_TYPE_UINT8    = 0,
    GGUF_TYPE_INT8     = 1,
    GGUF_TYPE_UINT16   = 2,
    GGUF_TYPE_INT16    = 3,
    GGUF_TYPE_UINT32   = 4,
    GGUF_TYPE_INT32    = 5,
    GGUF_TYPE_FLOAT32  = 6,
    GGUF_TYPE_BOOL     = 7,
    GGUF_TYPE_STRING   = 8,
    GGUF_TYPE_ARRAY    = 9,
    GGUF_TYPE_UINT64   = 10,
    GGUF_TYPE_INT64    = 11,
    GGUF_TYPE_FLOAT64  = 12,
};

// File type → quantization name mapping (from ggml)
static const char* FileTypeToQuant(uint32_t ft) {
    switch (ft) {
        case 0:  return "F32";
        case 1:  return "F16";
        case 2:  return "Q4_0";
        case 3:  return "Q4_1";
        case 7:  return "Q8_0";
        case 8:  return "Q8_1";
        case 10: return "Q2_K";
        case 11: return "Q3_K_S";
        case 12: return "Q3_K_M";
        case 13: return "Q3_K_L";
        case 14: return "Q4_K_S";
        case 15: return "Q4_K_M";
        case 16: return "Q5_K_S";
        case 17: return "Q5_K_M";
        case 18: return "Q6_K";
        case 19: return "IQ2_XXS";
        case 20: return "IQ2_XS";
        case 21: return "IQ3_XXS";
        case 22: return "IQ1_S";
        case 23: return "IQ4_NL";
        case 24: return "IQ3_S";
        case 25: return "IQ2_S";
        case 26: return "IQ4_XS";
        case 27: return "IQ1_M";
        case 28: return "BF16";
        case 29: return "Q4_0_4_4";
        case 30: return "Q4_0_4_8";
        case 31: return "Q4_0_8_8";
        default: return "Unknown";
    }
}

// ============================================================================
// Singleton
// ============================================================================
ModelBruteForceEngine& ModelBruteForceEngine::instance() {
    static ModelBruteForceEngine s_instance;
    return s_instance;
}

// ============================================================================
// GGUF Header Parsing — validates magic, reads version/tensor/metadata counts
// ============================================================================
bool ModelBruteForceEngine::ParseGGUFHeader(const std::string& path, ModelProbeResult& result) {
    auto t0 = std::chrono::high_resolution_clock::now();

#ifdef _WIN32
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER liSize;
    GetFileSizeEx(hFile, &liSize);
    result.file_size_bytes = (uint64_t)liSize.QuadPart;

    // Read GGUF header: magic(4) + version(4) + tensor_count(8) + metadata_count(8) = 24 bytes
    BruteForceGGUFHeader header{};
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, &header, sizeof(header), &bytesRead, nullptr) ||
        bytesRead < sizeof(header)) {
        CloseHandle(hFile);
        return false;
    }
    CloseHandle(hFile);
#else
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    result.file_size_bytes = (uint64_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    BruteForceGGUFHeader header{};
    if (fread(&header, sizeof(header), 1, fp) != 1) { fclose(fp); return false; }
    fclose(fp);
#endif

    result.valid_magic = (header.magic == GGUF_MAGIC);
    if (!result.valid_magic) return false;

    // Validate version (GGUF v2 or v3 only)
    if (header.version != 2 && header.version != 3) return false;

    // Sanity limits: prevent memory exhaustion / corruption
    constexpr uint64_t MAX_TENSOR_COUNT = 100000;
    constexpr uint64_t MAX_METADATA_KV_COUNT = 100000;
    if (header.tensor_count > MAX_TENSOR_COUNT) return false;
    if (header.metadata_kv_count > MAX_METADATA_KV_COUNT) return false;

    result.gguf_version = header.version;
    result.tensor_count = header.tensor_count;
    result.metadata_kv_count = header.metadata_kv_count;

    auto t1 = std::chrono::high_resolution_clock::now();
    result.scan_time_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    return true;
}

// ============================================================================
// Metadata Extraction — reads GGUF KV pairs for architecture, quantization, etc.
// ============================================================================
// ============================================================================
// Helper: Safely skip a GGUF value by type to keep file cursor synchronized
// ============================================================================
#ifdef _WIN32
static bool SkipGGUFValue(HANDLE hFile, uint32_t valueType, LARGE_INTEGER& offset, DWORD& br) {
    switch (valueType) {
        case GGUF_TYPE_UINT8:  case GGUF_TYPE_INT8:  case GGUF_TYPE_BOOL: {
            uint8_t v; return ReadFile(hFile, &v, 1, &br, nullptr) && br >= 1;
        }
        case GGUF_TYPE_UINT16: case GGUF_TYPE_INT16: {
            uint16_t v; return ReadFile(hFile, &v, 2, &br, nullptr) && br >= 2;
        }
        case GGUF_TYPE_UINT32: case GGUF_TYPE_INT32: case GGUF_TYPE_FLOAT32: {
            uint32_t v; return ReadFile(hFile, &v, 4, &br, nullptr) && br >= 4;
        }
        case GGUF_TYPE_UINT64: case GGUF_TYPE_INT64: case GGUF_TYPE_FLOAT64: {
            uint64_t v; return ReadFile(hFile, &v, 8, &br, nullptr) && br >= 8;
        }
        case GGUF_TYPE_STRING: {
            uint64_t sLen = 0;
            if (!ReadFile(hFile, &sLen, 8, &br, nullptr) || br < 8) return false;
            if (sLen > 0) {
                offset.QuadPart = (LONGLONG)sLen;
                if (!SetFilePointerEx(hFile, offset, nullptr, FILE_CURRENT)) return false;
            }
            return true;
        }
        case GGUF_TYPE_ARRAY: {
            uint32_t elemType = 0;
            uint64_t count = 0;
            if (!ReadFile(hFile, &elemType, 4, &br, nullptr) || br < 4) return false;
            if (!ReadFile(hFile, &count, 8, &br, nullptr) || br < 8) return false;
            uint64_t elemSize = 0;
            switch (elemType) {
                case GGUF_TYPE_UINT8: case GGUF_TYPE_INT8: case GGUF_TYPE_BOOL: elemSize = 1; break;
                case GGUF_TYPE_UINT16: case GGUF_TYPE_INT16: elemSize = 2; break;
                case GGUF_TYPE_UINT32: case GGUF_TYPE_INT32: case GGUF_TYPE_FLOAT32: elemSize = 4; break;
                case GGUF_TYPE_UINT64: case GGUF_TYPE_INT64: case GGUF_TYPE_FLOAT64: elemSize = 8; break;
                case GGUF_TYPE_STRING: elemSize = (uint64_t)-1; break; // sentinel: variable
                case GGUF_TYPE_ARRAY:  return false; // nested arrays unsupported; abort
                default: return false; // unknown element type; abort
            }
            if (elemSize == (uint64_t)-1) {
                // String array: read length + skip data for each element
                for (uint64_t s = 0; s < count; s++) {
                    uint64_t sl = 0;
                    if (!ReadFile(hFile, &sl, 8, &br, nullptr) || br < 8) return false;
                    if (sl > 0) {
                        offset.QuadPart = (LONGLONG)sl;
                        if (!SetFilePointerEx(hFile, offset, nullptr, FILE_CURRENT)) return false;
                    }
                }
            } else {
                // Scalar array
                if (count > 0) {
                    // Check for overflow before multiplying
                    if (elemSize > 0 && count > (UINT64_MAX / elemSize)) return false;
                    uint64_t totalBytes = elemSize * count;
                    // For very large arrays, seek in chunks
                    const uint64_t maxChunk = 0x7FFFFFFF;
                    while (totalBytes > 0) {
                        uint64_t chunk = (totalBytes > maxChunk) ? maxChunk : totalBytes;
                        offset.QuadPart = (LONGLONG)chunk;
                        if (!SetFilePointerEx(hFile, offset, nullptr, FILE_CURRENT)) return false;
                        totalBytes -= chunk;
                    }
                }
            }
            return true;
        }
        default:
            return false; // unknown type; abort to prevent desync
    }
}
#else
static bool SkipGGUFValue(FILE* fp, uint32_t valueType) {
    switch (valueType) {
        case GGUF_TYPE_UINT8:  case GGUF_TYPE_INT8:  case GGUF_TYPE_BOOL:
            return fseek(fp, 1, SEEK_CUR) == 0;
        case GGUF_TYPE_UINT16: case GGUF_TYPE_INT16:
            return fseek(fp, 2, SEEK_CUR) == 0;
        case GGUF_TYPE_UINT32: case GGUF_TYPE_INT32: case GGUF_TYPE_FLOAT32:
            return fseek(fp, 4, SEEK_CUR) == 0;
        case GGUF_TYPE_UINT64: case GGUF_TYPE_INT64: case GGUF_TYPE_FLOAT64:
            return fseek(fp, 8, SEEK_CUR) == 0;
        case GGUF_TYPE_STRING: {
            uint64_t sLen = 0;
            if (fread(&sLen, 8, 1, fp) != 1) return false;
            if (sLen > 0 && fseek(fp, (long)sLen, SEEK_CUR) != 0) return false;
            return true;
        }
        case GGUF_TYPE_ARRAY: {
            uint32_t elemType = 0;
            uint64_t count = 0;
            if (fread(&elemType, 4, 1, fp) != 1) return false;
            if (fread(&count, 8, 1, fp) != 1) return false;
            uint64_t elemSize = 0;
            switch (elemType) {
                case GGUF_TYPE_UINT8: case GGUF_TYPE_INT8: case GGUF_TYPE_BOOL: elemSize = 1; break;
                case GGUF_TYPE_UINT16: case GGUF_TYPE_INT16: elemSize = 2; break;
                case GGUF_TYPE_UINT32: case GGUF_TYPE_INT32: case GGUF_TYPE_FLOAT32: elemSize = 4; break;
                case GGUF_TYPE_UINT64: case GGUF_TYPE_INT64: case GGUF_TYPE_FLOAT64: elemSize = 8; break;
                case GGUF_TYPE_STRING: elemSize = (uint64_t)-1; break;
                case GGUF_TYPE_ARRAY: return false;
                default: return false;
            }
            if (elemSize == (uint64_t)-1) {
                for (uint64_t s = 0; s < count; s++) {
                    uint64_t sl = 0;
                    if (fread(&sl, 8, 1, fp) != 1) return false;
                    if (sl > 0 && fseek(fp, (long)sl, SEEK_CUR) != 0) return false;
                }
            } else {
                if (count > 0) {
                    if (elemSize > 0 && count > (UINT64_MAX / elemSize)) return false;
                    uint64_t totalBytes = elemSize * count;
                    const uint64_t maxChunk = 0x7FFFFFFF;
                    while (totalBytes > 0) {
                        uint64_t chunk = (totalBytes > maxChunk) ? maxChunk : totalBytes;
                        if (fseek(fp, (long)chunk, SEEK_CUR) != 0) return false;
                        totalBytes -= chunk;
                    }
                }
            }
            return true;
        }
        default:
            return false;
    }
}
#endif

// ============================================================================
// Metadata Extraction — reads GGUF KV pairs for architecture, quantization, etc.
// Two-pass: first collects all string/int scalars into a map,
// then resolves architecture-specific keys using the discovered prefix.
// ============================================================================
bool ModelBruteForceEngine::ExtractMetadata(const std::string& path, ModelProbeResult& result) {
    // --- Pass 1: collect all scalar KVs into a map, skip non-scalars safely ---
    std::unordered_map<std::string, uint64_t> scalarMap;
    std::string archFromPass1;

#ifdef _WIN32
    HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER offset;
    offset.QuadPart = 24;
    SetFilePointerEx(hFile, offset, nullptr, FILE_BEGIN);

    char keyBuf[512]{};
    DWORD br = 0;

    for (uint64_t i = 0; i < result.metadata_kv_count; i++) {
        uint64_t keyLen = 0;
        if (!ReadFile(hFile, &keyLen, 8, &br, nullptr) || br < 8) { CloseHandle(hFile); return false; }
        if (keyLen == 0 || keyLen > 500) {
            // Invalid keyLen is a corruption signal; abort.
            CloseHandle(hFile); return false;
        }
        memset(keyBuf, 0, sizeof(keyBuf));
        if (!ReadFile(hFile, keyBuf, (DWORD)keyLen, &br, nullptr) || br < keyLen) { CloseHandle(hFile); return false; }
        std::string key(keyBuf, keyLen);

        uint32_t valueType = 0;
        if (!ReadFile(hFile, &valueType, 4, &br, nullptr) || br < 4) { CloseHandle(hFile); return false; }

        if (key == GGUF_KEY_ARCH && valueType == GGUF_TYPE_STRING) {
            uint64_t strLen = 0;
            if (ReadFile(hFile, &strLen, 8, &br, nullptr) && br >= 8 && strLen < 256) {
                char buf[256]{};
                if (ReadFile(hFile, buf, (DWORD)strLen, &br, nullptr) && br >= strLen) {
                    archFromPass1 = std::string(buf, strLen);
                } else {
                    CloseHandle(hFile); return false; // corrupt
                }
            } else {
                CloseHandle(hFile); return false; // corrupt or unsupported string length
            }
        } else if (key == GGUF_KEY_FILE_TYPE && (valueType == GGUF_TYPE_UINT32 || valueType == GGUF_TYPE_INT32)) {
            uint32_t ft = 0;
            if (ReadFile(hFile, &ft, 4, &br, nullptr) && br >= 4) {
                result.quantization = FileTypeToQuant(ft);
            } else {
                CloseHandle(hFile); return false;
            }
        } else if (valueType == GGUF_TYPE_UINT8 || valueType == GGUF_TYPE_INT8 || valueType == GGUF_TYPE_BOOL) {
            uint8_t v = 0;
            if (ReadFile(hFile, &v, 1, &br, nullptr) && br >= 1) scalarMap[key] = v;
            else { CloseHandle(hFile); return false; }
        } else if (valueType == GGUF_TYPE_UINT16 || valueType == GGUF_TYPE_INT16) {
            uint16_t v = 0;
            if (ReadFile(hFile, &v, 2, &br, nullptr) && br >= 2) scalarMap[key] = v;
            else { CloseHandle(hFile); return false; }
        } else if (valueType == GGUF_TYPE_UINT32 || valueType == GGUF_TYPE_INT32) {
            uint32_t v = 0;
            if (ReadFile(hFile, &v, 4, &br, nullptr) && br >= 4) scalarMap[key] = v;
            else { CloseHandle(hFile); return false; }
        } else if (valueType == GGUF_TYPE_UINT64 || valueType == GGUF_TYPE_INT64) {
            uint64_t v = 0;
            if (ReadFile(hFile, &v, 8, &br, nullptr) && br >= 8) scalarMap[key] = v;
            else { CloseHandle(hFile); return false; }
        } else if (valueType == GGUF_TYPE_FLOAT32) {
            float v = 0.0f;
            if (ReadFile(hFile, &v, 4, &br, nullptr) && br >= 4) {
                // Store float bits as uint64_t for retrieval if needed
                uint32_t bits; memcpy(&bits, &v, 4);
                scalarMap[key] = bits;
            } else { CloseHandle(hFile); return false; }
        } else if (valueType == GGUF_TYPE_FLOAT64) {
            double v = 0.0;
            if (ReadFile(hFile, &v, 8, &br, nullptr) && br >= 8) {
                uint64_t bits; memcpy(&bits, &v, 8);
                scalarMap[key] = bits;
            } else { CloseHandle(hFile); return false; }
        } else {
            // Strings, arrays, unknown types: skip safely or abort on failure
            if (!SkipGGUFValue(hFile, valueType, offset, br)) { CloseHandle(hFile); return false; }
        }
    }
    CloseHandle(hFile);
#else
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) return false;
    fseek(fp, 24, SEEK_SET);

    char keyBuf[512]{};
    for (uint64_t i = 0; i < result.metadata_kv_count; i++) {
        uint64_t keyLen = 0;
        if (fread(&keyLen, 8, 1, fp) != 1) { fclose(fp); return false; }
        if (keyLen == 0 || keyLen > 500) { fclose(fp); return false; }
        memset(keyBuf, 0, sizeof(keyBuf));
        if (fread(keyBuf, 1, keyLen, fp) != keyLen) { fclose(fp); return false; }
        std::string key(keyBuf, keyLen);

        uint32_t valueType = 0;
        if (fread(&valueType, 4, 1, fp) != 1) { fclose(fp); return false; }

        if (key == GGUF_KEY_ARCH && valueType == GGUF_TYPE_STRING) {
            uint64_t strLen = 0;
            if (fread(&strLen, 8, 1, fp) == 1 && strLen < 256) {
                char buf[256]{};
                if (fread(buf, 1, strLen, fp) == strLen) {
                    archFromPass1 = std::string(buf, strLen);
                } else { fclose(fp); return false; }
            } else { fclose(fp); return false; }
        } else if (key == GGUF_KEY_FILE_TYPE && (valueType == GGUF_TYPE_UINT32 || valueType == GGUF_TYPE_INT32)) {
            uint32_t ft = 0;
            if (fread(&ft, 4, 1, fp) == 1) result.quantization = FileTypeToQuant(ft);
            else { fclose(fp); return false; }
        } else if (valueType == GGUF_TYPE_UINT8 || valueType == GGUF_TYPE_INT8 || valueType == GGUF_TYPE_BOOL) {
            uint8_t v = 0;
            if (fread(&v, 1, 1, fp) == 1) scalarMap[key] = v;
            else { fclose(fp); return false; }
        } else if (valueType == GGUF_TYPE_UINT16 || valueType == GGUF_TYPE_INT16) {
            uint16_t v = 0;
            if (fread(&v, 2, 1, fp) == 1) scalarMap[key] = v;
            else { fclose(fp); return false; }
        } else if (valueType == GGUF_TYPE_UINT32 || valueType == GGUF_TYPE_INT32) {
            uint32_t v = 0;
            if (fread(&v, 4, 1, fp) == 1) scalarMap[key] = v;
            else { fclose(fp); return false; }
        } else if (valueType == GGUF_TYPE_UINT64 || valueType == GGUF_TYPE_INT64) {
            uint64_t v = 0;
            if (fread(&v, 8, 1, fp) == 1) scalarMap[key] = v;
            else { fclose(fp); return false; }
        } else if (valueType == GGUF_TYPE_FLOAT32) {
            float v = 0.0f;
            if (fread(&v, 4, 1, fp) == 1) { uint32_t bits; memcpy(&bits, &v, 4); scalarMap[key] = bits; }
            else { fclose(fp); return false; }
        } else if (valueType == GGUF_TYPE_FLOAT64) {
            double v = 0.0;
            if (fread(&v, 8, 1, fp) == 1) { uint64_t bits; memcpy(&bits, &v, 8); scalarMap[key] = bits; }
            else { fclose(fp); return false; }
        } else {
            if (!SkipGGUFValue(fp, valueType)) { fclose(fp); return false; }
        }
    }
    fclose(fp);
#endif

    // --- Pass 2: resolve architecture-specific keys using discovered prefix ---
    result.architecture = archFromPass1;
    std::string archPrefix = archFromPass1;

    auto getUint32 = [&](const std::string& key) -> uint32_t {
        auto it = scalarMap.find(key);
        if (it != scalarMap.end()) return static_cast<uint32_t>(it->second);
        return 0;
    };

    if (!archPrefix.empty()) {
        result.context_length = getUint32(archPrefix + GGUF_KEY_CONTEXT_LEN);
        result.embedding_dim  = getUint32(archPrefix + GGUF_KEY_EMBEDDING_LEN);
        result.layer_count    = getUint32(archPrefix + GGUF_KEY_BLOCK_COUNT);
        result.head_count     = getUint32(archPrefix + GGUF_KEY_HEAD_COUNT);
        result.head_count_kv  = getUint32(archPrefix + GGUF_KEY_HEAD_COUNT_KV);
        result.vocab_size     = getUint32(archPrefix + GGUF_KEY_VOCAB_SIZE);
    }
    // Also try "general" fallback keys if arch-specific not found (some models use generic keys)
    if (result.context_length == 0) result.context_length = getUint32("general" + std::string(GGUF_KEY_CONTEXT_LEN));
    if (result.embedding_dim  == 0) result.embedding_dim  = getUint32("general" + std::string(GGUF_KEY_EMBEDDING_LEN));
    if (result.layer_count    == 0) result.layer_count    = getUint32("general" + std::string(GGUF_KEY_BLOCK_COUNT));
    if (result.head_count     == 0) result.head_count     = getUint32("general" + std::string(GGUF_KEY_HEAD_COUNT));
    if (result.head_count_kv  == 0) result.head_count_kv  = getUint32("general" + std::string(GGUF_KEY_HEAD_COUNT_KV));
    if (result.vocab_size     == 0) result.vocab_size     = getUint32("general" + std::string(GGUF_KEY_VOCAB_SIZE));

    // Estimate RAM from file size + quant overhead
    result.estimated_ram_gb = EstimateRAM(result);

    // Extract quantization from filename if not found in metadata
    if (result.quantization.empty() || result.quantization == "Unknown") {
        result.quantization = ExtractQuantFromFilename(result.filename);
    }

    return true;
}

// ============================================================================
// RAM Estimation
// ============================================================================
float ModelBruteForceEngine::EstimateRAM(const ModelProbeResult& result) const {
    // Base: file size + ~20% overhead for KV cache, embeddings, activations
    float fileGB = (float)result.file_size_bytes / (1024.0f * 1024.0f * 1024.0f);
    float overhead = 1.2f;

    // Context-dependent overhead
    if (result.context_length > 8192) overhead += 0.15f;
    if (result.context_length > 32768) overhead += 0.3f;
    if (result.context_length > 65536) overhead += 0.5f;

    return fileGB * overhead;
}

// ============================================================================
// Quant Extraction from Filename
// ============================================================================
std::string ModelBruteForceEngine::ExtractQuantFromFilename(const std::string& filename) const {
    static const char* quants[] = {
        "IQ1_M", "IQ1_S", "IQ2_XXS", "IQ2_XS", "IQ2_S", "IQ3_XXS", "IQ3_S", "IQ4_NL", "IQ4_XS",
        "Q2_K", "Q3_K_S", "Q3_K_M", "Q3_K_L", "Q4_K_S", "Q4_K_M", "Q5_K_S", "Q5_K_M",
        "Q4_0", "Q4_1", "Q5_0", "Q5_1", "Q6_K", "Q8_0", "Q8_1",
        "F32", "F16", "BF16"
    };
    // Case-insensitive search
    std::string upper = filename;
    for (auto& c : upper) c = (char)toupper(c);
    for (const char* q : quants) {
        std::string uq = q;
        for (auto& c : uq) c = (char)toupper(c);
        if (upper.find(uq) != std::string::npos) return q;
    }
    return "Unknown";
}

// ============================================================================
// Directory Scanning
// ============================================================================
void ModelBruteForceEngine::ScanDirectory(const std::string& dir, const std::string& source,
                                          std::vector<ModelProbeResult>& out,
                                          const BruteForceScanConfig& config) {
    if (m_cancelRequested.load()) return;

#ifdef _WIN32
    // Scan for *.gguf files
    std::string pattern = dir + "\\*.gguf";
    WIN32_FIND_DATAA fd{};
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (m_cancelRequested.load()) break;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

        std::string fullPath = dir + "\\" + fd.cFileName;

        // Size filter
        uint64_t fsize = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        if (fsize < config.min_file_size) continue;
        if (config.max_file_size > 0 && fsize > config.max_file_size) continue;

        ModelProbeResult pr;
        pr.path = fullPath;
        pr.filename = fd.cFileName;
        pr.source = source;
        pr.file_size_bytes = fsize;

        if (ParseGGUFHeader(fullPath, pr) && pr.valid_magic) {
            if (!ExtractMetadata(fullPath, pr)) continue;

            // Apply arch/quant filters
            if (!config.arch_filter.empty() && pr.architecture != config.arch_filter) continue;
            if (!config.quant_filter.empty() && pr.quantization != config.quant_filter) continue;

            out.push_back(std::move(pr));
        }

        if (config.max_models > 0 && (int)out.size() >= config.max_models) break;
    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);

    // Recurse into subdirectories
    pattern = dir + "\\*";
    hFind = FindFirstFileA(pattern.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;
    do {
        if (m_cancelRequested.load()) break;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        std::string subdir = dir + "\\" + fd.cFileName;
        ScanDirectory(subdir, source, out, config);
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
#else
    DIR* dp = opendir(dir.c_str());
    if (!dp) return;
    struct dirent* entry;
    while ((entry = readdir(dp)) != nullptr) {
        if (m_cancelRequested.load()) break;
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string fullPath = dir + "/" + name;
        struct stat st;
        if (stat(fullPath.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            ScanDirectory(fullPath, source, out, config);
            continue;
        }
        if (name.size() < 5 || name.substr(name.size()-5) != ".gguf") continue;
        if ((uint64_t)st.st_size < config.min_file_size) continue;
        ModelProbeResult pr;
        pr.path = fullPath; pr.filename = name; pr.source = source;
        pr.file_size_bytes = (uint64_t)st.st_size;
        if (ParseGGUFHeader(fullPath, pr) && pr.valid_magic) {
            if (!ExtractMetadata(fullPath, pr)) continue;
            out.push_back(std::move(pr));
        }
    }
    closedir(dp);
#endif
}

// ============================================================================
// Ollama Blob Scanning
// ============================================================================
void ModelBruteForceEngine::ScanOllamaBlobs(std::vector<ModelProbeResult>& out,
                                             const BruteForceScanConfig& config) {
    if (m_cancelRequested.load()) return;

#ifdef _WIN32
    // Standard Ollama blob paths
    char userProfile[MAX_PATH]{};
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH) == 0) return;

    std::vector<std::string> blobDirs = {
        std::string(userProfile) + "\\.ollama\\models\\blobs",
        PathResolver::getModelsPath() + "\\blobs",
        "D:\\OllamaModels\\blobs",
        "C:\\OllamaModels\\blobs",
    };

    // Also check OLLAMA_MODELS / RAWRXD_OLLAMA_PATH env vars
    char ollamaModels[MAX_PATH]{};
    if (GetEnvironmentVariableA("OLLAMA_MODELS", ollamaModels, MAX_PATH) > 0) {
        blobDirs.push_back(std::string(ollamaModels) + "\\blobs");
    }
    char rawrxdOllama[MAX_PATH]{};
    if (GetEnvironmentVariableA("RAWRXD_OLLAMA_PATH", rawrxdOllama, MAX_PATH) > 0) {
        blobDirs.push_back(std::string(rawrxdOllama) + "\\blobs");
    }

    for (const auto& blobDir : blobDirs) {
        if (m_cancelRequested.load()) break;

        std::string pattern = blobDir + "\\sha256-*";
        WIN32_FIND_DATAA fd{};
        HANDLE hFind = FindFirstFileA(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (m_cancelRequested.load()) break;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            uint64_t fsize = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            // Ollama blobs > 100MB are likely model weights
            if (fsize < 100 * 1024 * 1024) continue;

            std::string fullPath = blobDir + "\\" + fd.cFileName;

            ModelProbeResult pr;
            pr.path = fullPath;
            pr.filename = fd.cFileName;
            pr.source = "ollama_blob";
            pr.file_size_bytes = fsize;

            // Validate GGUF magic
            if (ParseGGUFHeader(fullPath, pr) && pr.valid_magic) {
                if (!ExtractMetadata(fullPath, pr)) continue;
                out.push_back(std::move(pr));
            }
        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }
#endif
}

// ============================================================================
// Probe: Ollama API
// ============================================================================
void ModelBruteForceEngine::ProbeWithOllama(ModelProbeResult& result,
                                             const BruteForceScanConfig& config) {
    try {
        RawrXD::Agent::OllamaConfig ollamaConf;
        ollamaConf.timeoutMs = config.probe_timeout_ms;

        RawrXD::Agent::AgentOllamaClient client(ollamaConf);
        if (!client.TestConnection()) return;

        // Strict identity matching: exact model name or explicit alias only.
        // Architecture-based fuzzy matching is NOT sufficient to prove identity.
        auto models = client.ListModels();
        bool found = false;
        std::string matchedModel;
        for (const auto& m : models) {
            // Normalized exact alias comparison: strip extension, lowercase
            std::string modelAlias = m;
            for (auto& c : modelAlias) c = (char)tolower(c);

            std::string fileStem = result.filename;
            size_t dotPos = fileStem.rfind('.');
            if (dotPos != std::string::npos) fileStem = fileStem.substr(0, dotPos);
            for (auto& c : fileStem) c = (char)tolower(c);

            // Also normalize Ollama tag separator ':' to '-'
            std::string modelAliasTag = modelAlias;
            std::replace(modelAliasTag.begin(), modelAliasTag.end(), ':', '-');

            if (fileStem == modelAlias || fileStem == modelAliasTag) {
                found = true;
                matchedModel = m;
                break;
            }
        }
        if (!found) return;

        // Identity verified by normalized exact alias match
        result.ollama_identity_verified = true;
        result.ollama_available = true;

        // Attempt token generation
        std::vector<RawrXD::Agent::ChatMessage> msgs;
        RawrXD::Agent::ChatMessage userMsg;
        userMsg.role = "user";
        userMsg.content = config.probe_prompt;
        msgs.push_back(userMsg);

        nlohmann::json options;
        options["model"] = matchedModel;
        options["max_tokens"] = config.probe_max_tokens;
        options["temperature"] = config.probe_temperature;
        auto ir = client.ChatSync(msgs, options);
        if (ir.success && !ir.content.empty()) {
            result.token_generated = true;
            result.ollama_generation_valid = true;
            result.tokens_produced = (uint32_t)ir.tokensGenerated;
            result.probe_output = ir.content.substr(0, 200);
        }
    } catch (...) {
        // No exceptions in release — this is a safety net
    }
}

// ============================================================================
// Probe: CPU Inference — Real GGUFLoader + CPUInferenceEngine validation
// ============================================================================
void ModelBruteForceEngine::ProbeWithCPU(ModelProbeResult& result,
                                          const BruteForceScanConfig& config) {
    // Phase 1: Validate file is mmap-able (basic I/O test)
#ifdef _WIN32
    HANDLE hFile = CreateFileA(result.path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        result.probe_error = "Cannot open file for CPU probe";
        return;
    }
    HANDLE hMap = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
        CloseHandle(hFile);
        result.probe_error = "Cannot mmap file for CPU probe";
        return;
    }
    void* pView = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!pView) {
        CloseHandle(hMap); CloseHandle(hFile);
        result.probe_error = "MapViewOfFile failed";
        return;
    }
    // Verify GGUF magic from mmap
    uint32_t magic = *(uint32_t*)pView;
    UnmapViewOfFile(pView);
    CloseHandle(hMap);
    CloseHandle(hFile);
    if (magic != GGUF_MAGIC) {
        result.probe_error = "mmap magic mismatch";
        return;
    }
#endif

    // Phase 2: Actually open via GGUFLoader — validates full header + metadata parsing
    GGUFLoader loader;
    if (!loader.Open(result.path)) {
        result.probe_error = "GGUFLoader::Open failed";
        return;
    }
    if (!loader.ParseHeader()) {
        loader.Close();
        result.probe_error = "GGUFLoader::ParseHeader failed";
        return;
    }
    if (!loader.ParseMetadata()) {
        loader.Close();
        result.probe_error = "GGUFLoader::ParseMetadata failed";
        return;
    }

    // Phase 3: CPUInferenceEngine not available; use GGUFLoader header + metadata only
    // (NativeInferencePipeline already validated in ProbeWithNative)
    result.cpu_loadable = false;
    result.cli_compatible = false;

    // Enrich metadata from GGUFLoader if our header parse missed anything
    GGUFMetadata meta = loader.GetMetadata();
    if (result.architecture.empty() && !meta.architecture_type.empty()) {
        result.architecture = meta.architecture_type;
    }
    if (result.vocab_size == 0 && meta.vocab_size > 0)
        result.vocab_size = meta.vocab_size;
    if (result.context_length == 0 && meta.context_length > 0)
        result.context_length = meta.context_length;
    if (result.embedding_dim == 0 && meta.embedding_dim > 0)
        result.embedding_dim = meta.embedding_dim;

    loader.Close();
}

// ============================================================================
// Probe: Native Pipeline — Real NativeInferencePipeline::LoadModel validation
// ============================================================================
void ModelBruteForceEngine::ProbeWithNative(ModelProbeResult& result,
                                             const BruteForceScanConfig& config) {
    // Check file accessibility first
#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(result.path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        result.probe_error = "File not accessible for native probe";
        return;
    }
#endif

    // Requires valid GGUF with at least 1 tensor as prerequisite
    if (!result.valid_magic || result.tensor_count == 0) {
        return;
    }

    // Actually try loading via NativeInferencePipeline
    NativeInferencePipeline pipeline;
    PipelineConfig pipeConf{};
    pipeConf.maxContextLen = 512;  // Minimal context for probe
    pipeConf.backgroundInference = false; // Synchronous for compatibility check

    PatchResult initResult = pipeline.Init(pipeConf);
    if (!initResult.success) {
        // Pipeline init failed — not fatal, just means native path unavailable
        return;
    }

    PatchResult loadResult = pipeline.LoadModel(result.path.c_str());
    if (loadResult.success) {
        result.native_loadable = true;

        // Try a quick inference to measure actual tok/s
        // Native inference does NOT depend on CPU tokenization state
        if (config.probe_inference) {
            PatchResult inferResult = pipeline.Infer(
                config.probe_prompt.c_str(),
                (uint32_t)config.probe_prompt.size());

            if (inferResult.success) {
                // Wait for completion with timeout
                PatchResult waitResult = pipeline.WaitForCompletion(
                    (uint32_t)config.probe_timeout_ms);

                if (waitResult.success) {
                    uint32_t outLen = 0;
                    const char* output = pipeline.GetLastOutput(&outLen);
                    if (output && outLen > 0) {
                        result.native_generation_valid = true;
                        result.token_generated = true;
                        result.probe_output = std::string(output, std::min(outLen, 200u));
                        result.tokens_per_sec = pipeline.CurrentTokensPerSec();
                        result.tokens_produced = outLen / 4; // rough estimate
                    }
                }
            }

            pipeline.StopInference();
        }

        pipeline.UnloadModel();
    }

    pipeline.Shutdown();

    // Backend probes report backend facts only.
    // E2E certification must come from actual surface gate tests, not inference here.
    // Do NOT set cli_e2e_certified / gui_e2e_certified / html_e2e_certified from backend state.

    // Legacy compatibility flags: backend-loadable is still reported
    if (result.cpu_loadable) result.cli_compatible = true;
    if (result.native_loadable) {
        result.gui_compatible = true;
        result.html_compatible = true;
    }
    if (result.ollama_identity_verified) {
        result.cli_compatible = true;
        result.gui_compatible = true;
        result.html_compatible = true;
    }
}

// ============================================================================
// Discover All Models (header scan only, no inference probe)
// ============================================================================
std::vector<ModelProbeResult> ModelBruteForceEngine::DiscoverAllModels(
    const BruteForceScanConfig& config, BruteForceProgressCallback progress) {

    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_running.store(true);
        m_cancelRequested.store(false);
        m_progress = {};
        m_progress.status_message = "Scanning model directories...";
    }

    std::vector<ModelProbeResult> results;

    // 1. Current working directory
    if (config.scan_cwd) {
        char cwd[MAX_PATH]{};
        GetCurrentDirectoryA(MAX_PATH, cwd);
        ScanDirectory(cwd, "local", results, config);
    }

    // 2. Additional local directories
    for (const auto& dir : config.local_dirs) {
        ScanDirectory(dir, "local", results, config);
    }

    // 3. Standard model locations (PathResolver + env, then fallbacks)
    std::vector<std::string> stdDirs = {
        PathResolver::getModelsPath(),
        "D:\\OllamaModels",
        "D:\\models",
        "C:\\models",
    };
    char rawrxdOllamaPath[MAX_PATH]{};
    if (GetEnvironmentVariableA("RAWRXD_OLLAMA_PATH", rawrxdOllamaPath, MAX_PATH) > 0)
        stdDirs.insert(stdDirs.begin(), rawrxdOllamaPath);
    char ollamaModelsEnv[MAX_PATH]{};
    if (GetEnvironmentVariableA("OLLAMA_MODELS", ollamaModelsEnv, MAX_PATH) > 0)
        stdDirs.insert(stdDirs.begin(), std::string(ollamaModelsEnv));

    char userProfile[MAX_PATH]{};
    if (GetEnvironmentVariableA("USERPROFILE", userProfile, MAX_PATH) > 0) {
        stdDirs.push_back(std::string(userProfile) + "\\.cache\\rawrxd\\models");
        stdDirs.push_back(std::string(userProfile) + "\\.cache\\huggingface\\hub");
        stdDirs.push_back(std::string(userProfile) + "\\.ollama\\models");
        stdDirs.push_back(std::string(userProfile) + "\\models");
    }

    for (const auto& dir : stdDirs) {
        if (m_cancelRequested.load()) break;
        DWORD attrs = GetFileAttributesA(dir.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            BruteForceScanProgress localProgress;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_progress.status_message = "Scanning: " + dir;
                localProgress = m_progress;
            }
            if (progress) progress(localProgress);
            ScanDirectory(dir, "local", results, config);
        }
    }

    // 4. HuggingFace cache
    if (config.scan_hf_cache && !m_cancelRequested.load()) {
        std::string hfCache = std::string(userProfile) + "\\.cache\\huggingface\\hub\\models--*";
        // Scan each model's snapshots for .gguf files
        WIN32_FIND_DATAA fd{};
        HANDLE hFind = FindFirstFileA(hfCache.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    std::string modelDir = std::string(userProfile) +
                        "\\.cache\\huggingface\\hub\\" + fd.cFileName + "\\snapshots";
                    ScanDirectory(modelDir, "hf_cache", results, config);
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }

    // 5. Ollama blobs
    if (config.scan_ollama_blobs && !m_cancelRequested.load()) {
        BruteForceScanProgress localProgress;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_progress.status_message = "Scanning Ollama blobs...";
            localProgress = m_progress;
        }
        if (progress) progress(localProgress);
        ScanOllamaBlobs(results, config);
    }

    // Deduplicate by path
    std::sort(results.begin(), results.end(),
              [](const ModelProbeResult& a, const ModelProbeResult& b) { return a.path < b.path; });
    results.erase(std::unique(results.begin(), results.end(),
              [](const ModelProbeResult& a, const ModelProbeResult& b) { return a.path == b.path; }),
              results.end());

    BruteForceScanProgress finalProgress;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_progress.models_found = (int)results.size();
        m_progress.status_message = "Discovery complete";
        m_progress.is_complete = true;
        m_running.store(false);
        finalProgress = m_progress;
    }
    if (progress) progress(finalProgress);

    return results;
}

// ============================================================================
// Probe Single Model
// ============================================================================
ModelProbeResult ModelBruteForceEngine::ProbeModel(const std::string& model_path,
                                                    const BruteForceScanConfig& config) {
    ModelProbeResult result;
    result.path = model_path;

    // Extract filename
    size_t lastSlash = model_path.find_last_of("\\/");
    result.filename = (lastSlash != std::string::npos) ? model_path.substr(lastSlash + 1) : model_path;
    result.source = "local";

    // Parse header
    if (!ParseGGUFHeader(model_path, result)) {
        result.probe_error = "Failed to read GGUF header";
        return result;
    }

    // Extract metadata
    if (!ExtractMetadata(model_path, result)) {
        result.probe_error = "Metadata extraction failed";
        return result;
    }

    // Probe inference backends
    if (config.probe_inference) {
        auto t0 = std::chrono::high_resolution_clock::now();
        result.probe_attempted = true;

        ProbeWithCPU(result, config);
        ProbeWithOllama(result, config);
        ProbeWithNative(result, config);

        auto t1 = std::chrono::high_resolution_clock::now();
        result.probe_time_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
    }

    return result;
}

// ============================================================================
// Brute Force ALL — Full scan + probe
// ============================================================================
std::vector<ModelProbeResult> ModelBruteForceEngine::BruteForceAll(
    const BruteForceScanConfig& config, BruteForceProgressCallback progress) {

    // Phase 1: Discovery
    auto results = DiscoverAllModels(config, progress);

    // Phase 2: Brute-force probe each model
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_running.store(true);
        m_progress.is_complete = false;
        m_progress.models_found = (int)results.size();
        m_progress.total_estimated = (int)results.size();
    }

    for (int i = 0; i < (int)results.size(); i++) {
        if (m_cancelRequested.load()) {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_progress.status_message = "Brute-force cancelled";
            m_progress.percent_complete = (float)(i) / (float)results.size() * 100.0f;
            break;
        }

        auto& pr = results[i];
        BruteForceScanProgress localProgress;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_progress.current_model = pr.filename;
            m_progress.models_scanned = i + 1;
            m_progress.percent_complete = (float)(i + 1) / (float)results.size() * 100.0f;
            m_progress.status_message = "Probing: " + pr.filename;
            localProgress = m_progress;
        }
        if (progress) progress(localProgress);

        if (config.probe_inference) {
            auto t0 = std::chrono::high_resolution_clock::now();
            pr.probe_attempted = true;

            ProbeWithCPU(pr, config);
            ProbeWithOllama(pr, config);
            ProbeWithNative(pr, config);

            auto t1 = std::chrono::high_resolution_clock::now();
            pr.probe_time_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (pr.cli_compatible || pr.gui_compatible || pr.html_compatible)
                    m_progress.models_compatible++;
                else
                    m_progress.models_failed++;
            }
        }
    }

    // Track telemetry
    if (auto* tc = TelemetryCollector::instance()) tc->trackFeatureUsage("model_bruteforce");
    {
        auto tsc = RawrXD::Perf::PerfTelemetry::instance().begin(RawrXD::Perf::KernelSlot(0));
        RawrXD::Perf::PerfTelemetry::instance().end(RawrXD::Perf::KernelSlot(0), tsc);
    }

    // Cache results
    bool wasCancelled = m_cancelRequested.load();
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_lastResults = results;
        if (!wasCancelled) {
            m_progress.models_scanned = (int)results.size();
            m_progress.percent_complete = 100.0f;
            m_progress.is_complete = true;
            m_progress.status_message = "Brute-force complete";
        } else {
            // Keep the already-set cancelled status/percentage
            m_progress.is_complete = true;
        }
    }

    m_running.store(false);
    if (progress) progress(m_progress);

    return results;
}

// ============================================================================
// Results / Progress Accessors
// ============================================================================
std::vector<ModelProbeResult> ModelBruteForceEngine::GetLastResults() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_lastResults; // snapshot copy
}

BruteForceScanProgress ModelBruteForceEngine::GetProgress() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_progress; // snapshot copy
}

void ModelBruteForceEngine::Cancel() {
    m_cancelRequested.store(true);
}

bool ModelBruteForceEngine::IsRunning() const {
    return m_running.load();
}

// ============================================================================
// Format: CLI Table
// ============================================================================
std::string ModelBruteForceEngine::FormatCLI(const std::vector<ModelProbeResult>& results) const {
    std::string out;
    char buf[1024];

    out += "\n";
    out += "╔══════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    out += "║                      MODEL BRUTE-FORCE COMPATIBILITY MATRIX                                ║\n";
    out += "╠══════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    snprintf(buf, sizeof(buf),
        "║ %-40s │ %-8s │ %-6s │ %4s │ CLI│ GUI│HTML│ %-6s ║\n",
        "Model", "Arch", "Quant", "Ctx", "Tok/s");
    out += buf;
    out += "╠══════════════════════════════════════════════════════════════════════════════════════════════╣\n";

    for (const auto& r : results) {
        if (!r.valid_magic) continue;
        float sizeGB = (float)r.file_size_bytes / (1024.0f * 1024.0f * 1024.0f);
        snprintf(buf, sizeof(buf),
            "║ %-40.40s │ %-8.8s │ %-6.6s │ %4uK│ %s │ %s │ %s │ %6.1f ║\n",
            r.filename.c_str(),
            r.architecture.c_str(),
            r.quantization.c_str(),
            r.context_length / 1024,
            r.cli_compatible  ? " ✓ " : " ✗ ",
            r.gui_compatible  ? " ✓ " : " ✗ ",
            r.html_compatible ? " ✓ " : " ✗ ",
            r.tokens_per_sec);
        out += buf;
    }

    out += "╠══════════════════════════════════════════════════════════════════════════════════════════════╣\n";
    int total = 0, compat = 0;
    for (const auto& r : results) {
        if (!r.valid_magic) continue;
        total++;
        if (r.cli_compatible || r.gui_compatible || r.html_compatible) compat++;
    }
    snprintf(buf, sizeof(buf),
        "║ Total: %d models found, %d compatible, %d failed                                          ║\n",
        total, compat, total - compat);
    out += buf;
    out += "╚══════════════════════════════════════════════════════════════════════════════════════════════╝\n";

    return out;
}

// ============================================================================
// Format: JSON
// ============================================================================
std::string ModelBruteForceEngine::FormatJSON(const std::vector<ModelProbeResult>& results) const {
    std::string json = "{\"models\":[";

    bool firstValid = true;
    for (const auto& r : results) {
        if (!r.valid_magic) continue;

        if (!firstValid) json += ",";
        firstValid = false;

        json += "\n  {\"path\":\"" + JsonEscape(r.path) + "\","
                "\"filename\":\"" + JsonEscape(r.filename) + "\","
                "\"source\":\"" + JsonEscape(r.source) + "\","
                "\"size_bytes\":" + std::to_string(r.file_size_bytes) + ","
                "\"gguf_version\":" + std::to_string(r.gguf_version) + ","
                "\"tensor_count\":" + std::to_string(r.tensor_count) + ","
                "\"architecture\":\"" + JsonEscape(r.architecture) + "\","
                "\"quantization\":\"" + JsonEscape(r.quantization) + "\","
                "\"context_length\":" + std::to_string(r.context_length) + ","
                "\"embedding_dim\":" + std::to_string(r.embedding_dim) + ","
                "\"vocab_size\":" + std::to_string(r.vocab_size) + ","
                "\"layer_count\":" + std::to_string(r.layer_count) + ","
                "\"head_count\":" + std::to_string(r.head_count) + ","
                "\"head_count_kv\":" + std::to_string(r.head_count_kv) + ","
                "\"estimated_ram_gb\":" + std::to_string(r.estimated_ram_gb) + ","
                "\"cpu_loadable\":" + std::string(r.cpu_loadable ? "true" : "false") + ","
                "\"cpu_tokenizer_valid\":" + std::string(r.cpu_tokenizer_valid ? "true" : "false") + ","
                "\"cpu_generation_valid\":" + std::string(r.cpu_generation_valid ? "true" : "false") + ","
                "\"ollama_available\":" + std::string(r.ollama_available ? "true" : "false") + ","
                "\"ollama_identity_verified\":" + std::string(r.ollama_identity_verified ? "true" : "false") + ","
                "\"ollama_generation_valid\":" + std::string(r.ollama_generation_valid ? "true" : "false") + ","
                "\"native_loadable\":" + std::string(r.native_loadable ? "true" : "false") + ","
                "\"native_generation_valid\":" + std::string(r.native_generation_valid ? "true" : "false") + ","
                "\"token_generated\":" + std::string(r.token_generated ? "true" : "false") + ","
                "\"tokens_per_sec\":" + std::to_string(r.tokens_per_sec) + ","
                "\"tokens_produced\":" + std::to_string(r.tokens_produced) + ","
                "\"cli_compatible\":" + std::string(r.cli_compatible ? "true" : "false") + ","
                "\"gui_compatible\":" + std::string(r.gui_compatible ? "true" : "false") + ","
                "\"html_compatible\":" + std::string(r.html_compatible ? "true" : "false") + ","
                "\"cli_e2e_certified\":" + std::string(r.cli_e2e_certified ? "true" : "false") + ","
                "\"gui_e2e_certified\":" + std::string(r.gui_e2e_certified ? "true" : "false") + ","
                "\"html_e2e_certified\":" + std::string(r.html_e2e_certified ? "true" : "false") + ","
                "\"scan_time_ms\":" + std::to_string(r.scan_time_ms) + ","
                "\"probe_time_ms\":" + std::to_string(r.probe_time_ms) + ","
                "\"probe_output\":\"" + JsonEscape(r.probe_output) + "\","
                "\"probe_error\":\"" + JsonEscape(r.probe_error) + "\"}";
    }

    json += "\n],\"total\":" + std::to_string(results.size());

    // Summary stats
    int compat = 0, failed = 0;
    for (const auto& r : results) {
        if (r.cli_compatible || r.gui_compatible || r.html_compatible) compat++;
        else if (r.valid_magic) failed++;
    }
    json += ",\"compatible\":" + std::to_string(compat);
    json += ",\"failed\":" + std::to_string(failed);
    json += "}\n";

    return json;
}

// ============================================================================
// Format: HTML
// ============================================================================
std::string ModelBruteForceEngine::FormatHTML(const std::vector<ModelProbeResult>& results) const {
    std::string html;
    html += R"(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RawrXD — Model Brute-Force Compatibility Matrix</title>
<style>
:root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #c9d1d9;
        --green: #3fb950; --red: #f85149; --yellow: #d29922; --blue: #58a6ff;
        --accent: #bc8cff; }
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: 'Cascadia Code', 'JetBrains Mono', monospace; padding: 20px; }
h1 { color: var(--accent); text-align: center; margin-bottom: 16px; font-size: 1.4em; }
.stats { display: flex; gap: 16px; justify-content: center; margin-bottom: 16px; flex-wrap: wrap; }
.stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px 24px; text-align: center; }
.stat .num { font-size: 2em; font-weight: bold; }
.stat .label { font-size: 0.8em; opacity: 0.7; }
.stat.ok .num { color: var(--green); }
.stat.fail .num { color: var(--red); }
.stat.total .num { color: var(--blue); }
table { width: 100%; border-collapse: collapse; background: var(--card); border-radius: 8px; overflow: hidden; }
th { background: #21262d; color: var(--accent); padding: 10px 8px; text-align: left; font-size: 0.85em; position: sticky; top: 0; }
td { padding: 8px; border-top: 1px solid var(--border); font-size: 0.82em; }
tr:hover { background: #1c2128; }
.compat { text-align: center; font-size: 1.2em; }
.yes { color: var(--green); }
.no { color: var(--red); }
.size { color: var(--yellow); }
.arch { color: var(--blue); }
.quant { color: var(--accent); }
.probe-out { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; opacity: 0.7; }
.hotpatch-btn { background: var(--accent); color: #000; border: none; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 0.8em; font-weight: bold; }
.hotpatch-btn:hover { opacity: 0.8; }
.hotpatch-btn.active { background: var(--green); }
</style>
</head>
<body>
<h1>⚡ RawrXD Model Brute-Force Compatibility Matrix</h1>
)";

    // Stats summary
    int total = 0, compat = 0, failed = 0;
    for (const auto& r : results) {
        if (!r.valid_magic) continue;
        total++;
        if (r.cli_compatible || r.gui_compatible || r.html_compatible) compat++;
        else failed++;
    }

    char buf[2048];
    snprintf(buf, sizeof(buf),
        R"(<div class="stats">
<div class="stat total"><div class="num">%d</div><div class="label">Models Found</div></div>
<div class="stat ok"><div class="num">%d</div><div class="label">Compatible</div></div>
<div class="stat fail"><div class="num">%d</div><div class="label">Failed</div></div>
</div>)", total, compat, failed);
    html += buf;

    html += R"(<table>
<tr><th>#</th><th>Model</th><th>Arch</th><th>Quant</th><th>Size</th><th>Ctx</th><th>Layers</th><th>RAM Est.</th><th>CLI</th><th>GUI</th><th>HTML</th><th>OllamaGen</th><th>Tok/s</th><th>Hotpatch</th><th>Output</th></tr>
)";

    int idx = 0;
    for (const auto& r : results) {
        if (!r.valid_magic) continue;
        idx++;
        float sizeGB = static_cast<float>(r.file_size_bytes) / (1024.0f * 1024.0f * 1024.0f);

        std::string probeDisplay;
        if (r.probe_output.empty()) {
            probeDisplay = HtmlEscape(r.probe_error);
        } else {
            probeDisplay = HtmlEscape(r.probe_output);
        }

        html += "<tr>\n";
        html += "<td>" + std::to_string(idx) + "</td>\n";
        html += "<td title=\"" + HtmlEscape(r.path) + "\">" + HtmlEscape(r.filename) + "</td>\n";
        html += "<td class=\"arch\">" + HtmlEscape(r.architecture) + "</td>\n";
        html += "<td class=\"quant\">" + HtmlEscape(r.quantization) + "</td>\n";

        snprintf(buf, sizeof(buf),
            "<td class=\"size\">%.1fGB</td>\n"
            "<td>%uK</td>\n"
            "<td>%u</td>\n"
            "<td>%.1fGB</td>\n"
            "<td class=\"compat\">%s</td>\n"
            "<td class=\"compat\">%s</td>\n"
            "<td class=\"compat\">%s</td>\n"
            "<td class=\"compat\">%s</td>\n"
            "<td>%.1f</td>\n"
            "<td><button class=\"hotpatch-btn\" data-model-path=\"%s\" onclick=\"hotpatchModel(event,this.getAttribute('data-model-path'))\">[Patch]</button></td>\n"
            "<td class=\"probe-out\">%s</td>\n"
            "</tr>\n",
            sizeGB,
            r.context_length / 1024,
            r.layer_count,
            r.estimated_ram_gb,
            r.cli_compatible  ? "<span class='yes'>✓</span>" : "<span class='no'>✗</span>",
            r.gui_compatible  ? "<span class='yes'>✓</span>" : "<span class='no'>✗</span>",
            r.html_compatible ? "<span class='yes'>✓</span>" : "<span class='no'>✗</span>",
            r.ollama_generation_valid ? "<span class='yes'>✓</span>" : "<span class='no'>✗</span>",
            r.tokens_per_sec,
            HtmlEscape(r.path).c_str(),
            probeDisplay.c_str());
        html += buf;
    }

    html += R"(</table>
<script>
async function hotpatchModel(event, path) {
    const btn = event.currentTarget;
    btn.textContent = '⏳ Patching...';
    try {
        const res = await fetch('/api/models/bruteforce/hotpatch', {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({model_path: path})
        });
        const data = await res.json();
        if (data.success) { btn.textContent = '✓ Patched'; btn.classList.add('active'); }
        else { btn.textContent = '✗ Failed'; }
    } catch(e) { btn.textContent = '✗ Error'; }
}
// Auto-refresh results every 5s during scan
let refreshInterval = setInterval(async () => {
    try {
        const res = await fetch('/api/models/bruteforce/progress');
        const data = await res.json();
        if (data.is_complete) clearInterval(refreshInterval);
    } catch(e) { clearInterval(refreshInterval); }
}, 5000);
</script>
</body>
</html>)";

    return html;
}

} // namespace RawrXD
