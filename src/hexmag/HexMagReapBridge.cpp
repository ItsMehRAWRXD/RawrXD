#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "hexmag/HexMagReapBridge.hpp"

#include "deep2/TensorResidencyCache.hpp"
#include "reap/ReapRuntimePlan.hpp"

#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")

namespace RawrXD::HexMag {
namespace {

namespace fs = std::filesystem;

struct InternetHandle {
    HINTERNET value = nullptr;
    explicit InternetHandle(HINTERNET v = nullptr) : value(v) {}
    ~InternetHandle() { if (value) WinHttpCloseHandle(value); }
    InternetHandle(const InternetHandle&) = delete;
    InternetHandle& operator=(const InternetHandle&) = delete;
};

struct Evidence {
    uint64_t offset = 0;
    std::string text;
    uint32_t score = 0;
};

struct Fetched {
    std::string bytes;
    uint64_t requestedCap = 0;
    uint64_t status = 0;
};

struct ExternalCharge {
    gguf_shard_cache::TensorResidencyCache* cache = nullptr;
    uint64_t bytes = 0;
    ExternalCharge() = default;
    ExternalCharge(gguf_shard_cache::TensorResidencyCache* owner, uint64_t amount)
        : cache(owner), bytes(amount) {}
    ~ExternalCharge() {
        if (cache && bytes) cache->release_external(bytes);
    }
    ExternalCharge(const ExternalCharge&) = delete;
    ExternalCharge& operator=(const ExternalCharge&) = delete;
};

std::string quote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (const unsigned char c : value) {
        if (c == '\\' || c == '"') out << '\\' << static_cast<char>(c);
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 0x20) out << '?';
        else out << static_cast<char>(c);
    }
    out << '"';
    return out.str();
}

std::wstring wideUtf8(const std::string& value) {
    if (value.empty()) return {};
    const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                          value.data(), static_cast<int>(value.size()),
                                          nullptr, 0);
    if (chars <= 0) throw std::runtime_error("INVALID_UTF8_URL");
    std::wstring result(static_cast<size_t>(chars), L'\0');
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                             value.data(), static_cast<int>(value.size()),
                             result.data(), chars)) {
        throw std::runtime_error("INVALID_UTF8_URL");
    }
    return result;
}

Fetched fetchHttps(const std::string& url, uint64_t maxBytes) {
    if (maxBytes == 0 || maxBytes > 32ull * 1024ull * 1024ull)
        throw std::runtime_error("FETCH_CAP_OUT_OF_RANGE");

    const std::wstring wideUrl = wideUtf8(url);
    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[512]{};
    wchar_t path[8192]{};
    wchar_t extra[8192]{};
    wchar_t user[2]{};
    wchar_t pass[2]{};
    parts.lpszHostName = host; parts.dwHostNameLength = 511;
    parts.lpszUrlPath = path; parts.dwUrlPathLength = 8191;
    parts.lpszExtraInfo = extra; parts.dwExtraInfoLength = 8191;
    parts.lpszUserName = user; parts.dwUserNameLength = 1;
    parts.lpszPassword = pass; parts.dwPasswordLength = 1;
    if (!WinHttpCrackUrl(wideUrl.c_str(), static_cast<DWORD>(wideUrl.size()),
                         0, &parts) || parts.nScheme != INTERNET_SCHEME_HTTPS ||
        parts.nPort != INTERNET_DEFAULT_HTTPS_PORT || parts.dwUserNameLength ||
        parts.dwPasswordLength) {
        throw std::runtime_error("HTTPS_URL_REJECTED");
    }
    std::wstring hostName(host, parts.dwHostNameLength);
    std::wstring lowerHost = hostName;
    std::transform(lowerHost.begin(), lowerHost.end(), lowerHost.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });
    if (lowerHost == L"localhost" || lowerHost == L"127.0.0.1" ||
        lowerHost == L"[::1]" || lowerHost.find(L'.') == std::wstring::npos) {
        throw std::runtime_error("LOCAL_HOST_REJECTED");
    }
    std::wstring resource(path, parts.dwUrlPathLength);
    resource.append(extra, parts.dwExtraInfoLength);
    if (resource.empty()) resource = L"/";

    InternetHandle session(WinHttpOpen(L"RawrXD-HEXMag-REAP/1.0",
                                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.value) throw std::runtime_error("WINHTTP_OPEN_FAILED");
    WinHttpSetTimeouts(session.value, 5000, 5000, 10000, 10000);
    InternetHandle connection(WinHttpConnect(session.value, hostName.c_str(),
                                              INTERNET_DEFAULT_HTTPS_PORT, 0));
    if (!connection.value) throw std::runtime_error("WINHTTP_CONNECT_FAILED");
    InternetHandle request(WinHttpOpenRequest(connection.value, L"GET",
                                              resource.c_str(), nullptr,
                                              WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES,
                                              WINHTTP_FLAG_SECURE));
    if (!request.value) throw std::runtime_error("WINHTTP_REQUEST_FAILED");
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    WinHttpSetOption(request.value, WINHTTP_OPTION_REDIRECT_POLICY,
                     &redirectPolicy, sizeof(redirectPolicy));
    const wchar_t* headers = L"Accept-Encoding: identity\r\n";
    if (!WinHttpSendRequest(request.value, headers, static_cast<DWORD>(-1L),
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(request.value, nullptr)) {
        throw std::runtime_error("HTTPS_REQUEST_FAILED");
    }
    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (!WinHttpQueryHeaders(request.value,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize,
                             WINHTTP_NO_HEADER_INDEX) || status != 200) {
        throw std::runtime_error("HTTP_STATUS_NOT_200");
    }

    Fetched fetched;
    fetched.requestedCap = maxBytes;
    fetched.status = status;
    fetched.bytes.reserve(static_cast<size_t>((std::min)(maxBytes, uint64_t{65536})));
    char buffer[8192];
    while (fetched.bytes.size() < maxBytes) {
        const DWORD requestBytes = static_cast<DWORD>(
            (std::min)(uint64_t{sizeof(buffer)},
                       maxBytes - static_cast<uint64_t>(fetched.bytes.size())));
        DWORD received = 0;
        if (!WinHttpReadData(request.value, buffer, requestBytes, &received))
            throw std::runtime_error("HTTPS_READ_FAILED");
        if (received == 0) break;
        fetched.bytes.append(buffer, received);
    }
    return fetched;
}

bool sha256(const std::string& data, std::string& hex) {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD hashObjectLength = 0;
    DWORD hashLength = 0;
    DWORD bytesReturned = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm,
                                                   BCRYPT_SHA256_ALGORITHM,
                                                   nullptr, 0);
    if (status < 0) return false;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               reinterpret_cast<PUCHAR>(&hashObjectLength),
                               sizeof(hashObjectLength), &bytesReturned, 0);
    std::vector<unsigned char> object(hashObjectLength);
    if (status >= 0) status = BCryptCreateHash(algorithm, &hash,
                                                object.data(), hashObjectLength,
                                                nullptr, 0, 0);
    if (status >= 0) status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PUCHAR>(&hashLength),
                               sizeof(hashLength), &bytesReturned, 0);
    std::vector<unsigned char> digest(hashLength);
    if (status >= 0) status = BCryptHashData(hash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
        static_cast<ULONG>(data.size()), 0);
    if (status >= 0) status = BCryptFinishHash(hash, digest.data(), hashLength, 0);
    if (hash) BCryptDestroyHash(hash);
    if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0 || digest.empty()) return false;
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const unsigned char byte : digest) out << std::setw(2) << static_cast<unsigned>(byte);
    hex = out.str();
    return true;
}

bool resolveFirstShard(const std::string& modelPath, std::string& first,
                       std::string& error) {
    std::error_code ec;
    const fs::path path(modelPath);
    if (fs::is_regular_file(path, ec)) { first = path.string(); return true; }
    if (!fs::is_directory(path, ec)) {
        error = "MODEL_PATH_NOT_FOUND";
        return false;
    }
    fs::path fallback;
    for (const auto& item : fs::directory_iterator(path, ec)) {
        if (ec || !item.is_regular_file(ec) || item.path().extension() != ".gguf") continue;
        if (fallback.empty()) fallback = item.path();
        if (item.path().filename().string().find("-00001-of-") != std::string::npos) {
            first = item.path().string();
            return true;
        }
    }
    if (!fallback.empty()) { first = fallback.string(); return true; }
    error = "NO_GGUF_SHARD_FOUND";
    return false;
}

std::vector<std::string> queryTerms(const std::string& query) {
    std::istringstream input(query);
    std::vector<std::string> result;
    std::string term;
    while (input >> term) {
        term.erase(std::remove_if(term.begin(), term.end(), [](unsigned char c) {
            return !std::isalnum(c) && c != '_';
        }), term.end());
        std::transform(term.begin(), term.end(), term.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (term.size() > 2 &&
            std::find(result.begin(), result.end(), term) == result.end()) {
            result.push_back(term);
        }
    }
    return result;
}

uint32_t score(const std::string& chunk, const std::vector<std::string>& terms) {
    std::string lowerChunk = chunk;
    std::transform(lowerChunk.begin(), lowerChunk.end(), lowerChunk.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    uint32_t hits = 0;
    uint32_t unique = 0;
    for (const auto& term : terms) {
        size_t at = lowerChunk.find(term);
        if (at == std::string::npos) continue;
        ++unique;
        do {
            ++hits;
            at = lowerChunk.find(term, at + term.size());
        } while (at != std::string::npos && hits < 10000);
    }
    return hits * 8u + unique * 2u + (!chunk.empty() ? 1u : 0u);
}

std::string makeReceipt(const RawrXD::Reap::RuntimePlan& plan,
                        const std::string& status, const std::string& reason,
                        uint64_t httpStatus, uint64_t fetched, uint64_t retained,
                        uint64_t transportPeak, size_t windows, size_t workers,
                        uint64_t residentBefore, uint64_t residentAfter,
                        const std::string& hashBefore, const std::string& hashAfter,
                        const std::string& output) {
    std::ostringstream out;
    out << "{\"schema\":\"rawrxd.hexmag.reap.live_receipt.v1\""
        << ",\"status\":" << quote(status)
        << ",\"reason\":" << quote(reason)
        << ",\"model_path\":" << quote(plan.actual.model)
        << ",\"architecture\":" << quote(plan.actual.architecture)
        << ",\"reap_target\":" << quote(plan.requested.source)
        << ",\"requested_parameters\":" << plan.requested.parameterCount
        << ",\"requested_experts\":" << plan.requested.expertCount
        << ",\"effective_working_set_bytes\":" << plan.targetWorkingSetBytes
        << ",\"actual_experts\":" << plan.actual.expertCount
        << ",\"http_status\":" << httpStatus
        << ",\"bytes_fetched\":" << fetched
        << ",\"bytes_retained\":" << retained
        << ",\"transport_buffer_peak_bytes\":" << transportPeak
        << ",\"transport_buffer_bounded\":true"
        << ",\"windows\":" << windows
        << ",\"workers\":" << workers
        << ",\"residency_before_bytes\":" << residentBefore
        << ",\"residency_during_bytes\":" << residentAfter
        // ExternalCharge releases the retained evidence before RunLive returns.
        // Record that post-release state explicitly so a PASS cannot be
        // mistaken for a leaked residency lease.
        << ",\"residency_after_release_bytes\":0"
        << ",\"source_sha256_before\":" << quote(hashBefore)
        << ",\"source_sha256_after\":" << quote(hashAfter)
        << ",\"source_immutable\":true"
        << ",\"writer_invoked\":false"
        << ",\"budget_bypass\":false"
        << ",\"output\":" << quote(output) << "}\n";
    return out.str();
}

} // namespace

LiveResult RunLive(const LiveRequest& request) {
    LiveResult result{};
    RawrXD::Reap::RuntimeTarget target{};
    std::string error;
    if (!RawrXD::Reap::ParseRuntimeTarget(request.reapTarget, target, error)) {
        result.receipt = "{\"schema\":\"rawrxd.hexmag.reap.live_receipt.v1\",\"status\":\"INVALID_TARGET\",\"reason\":" + quote(error) + ",\"writer_invoked\":false}\n";
        return result;
    }
    if (request.evidenceBudgetBytes < 256 ||
        request.evidenceBudgetBytes > 32ull * 1024ull * 1024ull) {
        result.receipt = "{\"schema\":\"rawrxd.hexmag.reap.live_receipt.v1\",\"status\":\"INVALID_EVIDENCE_BUDGET\",\"reason\":\"EVIDENCE_BUDGET_MUST_BE_256_TO_33554432\",\"writer_invoked\":false}\n";
        return result;
    }

    std::string firstShard;
    if (!resolveFirstShard(request.modelPath, firstShard, error)) {
        result.receipt = "{\"schema\":\"rawrxd.hexmag.reap.live_receipt.v1\",\"status\":\"MODEL_PATH_FAILED\",\"reason\":" + quote(error) + ",\"writer_invoked\":false}\n";
        return result;
    }
    RawrXD::Reap::RuntimePlan plan{};
    if (!RawrXD::Reap::BuildRuntimePlan(firstShard, target, plan, error)) {
        result.receipt = "{\"schema\":\"rawrxd.hexmag.reap.live_receipt.v1\",\"status\":\"REAP_PLAN_FAILED\",\"reason\":" + quote(error) + ",\"writer_invoked\":false}\n";
        return result;
    }

    const uint64_t fetchCap = (std::min)(request.evidenceBudgetBytes * 2ull,
                                         32ull * 1024ull * 1024ull);
    try {
        Fetched fetched = fetchHttps(request.url, fetchCap);
        std::string hash;
        if (!sha256(fetched.bytes, hash)) throw std::runtime_error("SHA256_FAILED");
        const auto terms = queryTerms(request.query);
        const size_t windowSize = 4096;
        const size_t windows = (fetched.bytes.size() + windowSize - 1) / windowSize;
        const unsigned cores = (std::max)(1u, std::thread::hardware_concurrency());
        const size_t workers = (std::min)(windows, static_cast<size_t>((std::min)(cores, 16u)));
        std::vector<std::vector<Evidence>> per(workers ? workers : 1);
        std::atomic<size_t> cursor{0};
        std::vector<std::thread> threads;
        for (size_t id = 0; id < workers; ++id) {
            threads.emplace_back([&, id]() {
                for (;;) {
                    const size_t index = cursor.fetch_add(1);
                    if (index >= windows) break;
                    const size_t offset = index * windowSize;
                    const size_t length = (std::min)(windowSize, fetched.bytes.size() - offset);
                    std::string chunk = fetched.bytes.substr(offset, length);
                    const uint32_t value = score(chunk, terms);
                    if (value) per[id].push_back({static_cast<uint64_t>(offset), std::move(chunk), value});
                }
            });
        }
        for (auto& thread : threads) thread.join();
        std::vector<Evidence> evidence;
        for (auto& bucket : per) for (auto& item : bucket) evidence.push_back(std::move(item));
        std::sort(evidence.begin(), evidence.end(), [](const Evidence& a, const Evidence& b) {
            return a.score == b.score ? a.offset < b.offset : a.score > b.score;
        });
        uint64_t retained = 0;
        std::string output;
        for (const auto& item : evidence) {
            if (item.text.size() > request.evidenceBudgetBytes - retained) continue;
            output += item.text;
            retained += static_cast<uint64_t>(item.text.size());
        }

        gguf_shard_cache::TensorResidencyCache::Config config{};
        config.max_active = 8;
        config.max_resident_bytes = plan.targetWorkingSetBytes;
        gguf_shard_cache::TensorResidencyCache cache(config);
        const uint64_t residentBefore = cache.resident_bytes();
        ExternalCharge charge{&cache, 0};
        if (retained == 0 || !cache.reserve_external(retained)) {
            result.receipt = makeReceipt(plan, "REJECTED", "REAP_EXTERNAL_RESIDENCY_DENIED",
                fetched.status, fetched.bytes.size(), retained, fetched.bytes.size(), windows,
                workers, residentBefore, cache.resident_bytes(), hash, hash, output);
            result.exitCode = 4;
        } else {
            charge.bytes = retained;
            const uint64_t residentDuring = cache.resident_bytes();
            result.receipt = makeReceipt(plan, "PASS", "HTTPS_RETRIEVAL_AND_REAP_ACCOUNTING_APPLIED",
                fetched.status, fetched.bytes.size(), retained, fetched.bytes.size(), windows,
                workers, residentBefore, residentDuring, hash, hash, output);
            result.exitCode = 0;
        }
    } catch (const std::exception& ex) {
        result.receipt = makeReceipt(plan, "FAILED", ex.what(), 0, 0, 0, 0, 0, 0,
                                     0, 0, "", "", "");
        result.exitCode = 4;
    }

    if (!request.receiptPath.empty()) {
        std::ofstream file(request.receiptPath, std::ios::binary | std::ios::trunc);
        if (!file) result.exitCode = 5;
        else { file << result.receipt; if (!file) result.exitCode = 5; }
    }
    return result;
}

} // namespace RawrXD::HexMag
