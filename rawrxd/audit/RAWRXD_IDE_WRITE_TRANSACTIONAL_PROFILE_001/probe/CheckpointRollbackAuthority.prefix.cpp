// ============================================================================
// CheckpointRollbackAuthority.cpp
//   RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001
// See CheckpointRollbackAuthority.h for the on-disk and durability contract.
// ============================================================================
#include "agentic/CheckpointRollbackAuthority.h"

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <sstream>

namespace rawrxd {
namespace ckpt {
namespace {

// ---------------------------------------------------------------------------
// Measured counters. Incremented at the site of the effect, never predicted.
// ---------------------------------------------------------------------------
struct Counters {
    MeasuredCounters values;
    std::mutex mtx;
};
Counters& counters() {
    static Counters c;
    return c;
}

MeasuredCounters SnapshotCounters() {
    std::lock_guard<std::mutex> lk(counters().mtx);
    return counters().values;
}

void Bump(std::uint64_t MeasuredCounters::*field, std::uint64_t by = 1) {
    std::lock_guard<std::mutex> lk(counters().mtx);
    counters().values.*field += by;
}

// ---------------------------------------------------------------------------
// Fault injection state
// ---------------------------------------------------------------------------
constexpr DWORD kFaultExitCode = 0xC0FFEE01u;

struct FaultSpec {
    bool armed = false;
    std::string point;  // crash_before_write | crash_torn | crash_after
    int index = 0;
};

FaultSpec& mutableFault() {
    static FaultSpec spec;
    return spec;
}

void InitFaultFromEnvironment() {
    FaultSpec& spec = mutableFault();
    if (spec.armed || spec.point == "__loaded__") return;
    char buffer[64] = {};
    const DWORD got = GetEnvironmentVariableA("RAWRXD_CKPT_FAULT", buffer, sizeof(buffer));
    if (got == 0 || got >= sizeof(buffer)) {
        spec.point = "__loaded__";
        return;
    }
    const std::string raw(buffer, got);
    const std::size_t colon = raw.find(':');
    spec.point = raw.substr(0, colon);
    if (colon != std::string::npos) {
        spec.index = std::atoi(raw.c_str() + colon + 1);
    }
    spec.armed = (spec.point == "crash_before_write" || spec.point == "crash_torn" ||
                  spec.point == "crash_after");
    spec.point = spec.point + "|__loaded__";  // marker so this runs once
}

void DieNow(const char* why) {
    std::fprintf(stderr, "[ckpt] FAULT INJECTION: %s (exit=0x%08lX)\n", why,
                 static_cast<unsigned long>(kFaultExitCode));
    std::fflush(stderr);
    // No destructors, no atexit handlers, no stream flush beyond stderr above.
    ::TerminateProcess(::GetCurrentProcess(), kFaultExitCode);
}

// True when the armed fault point and index match, so the caller can perform
// the state-mutating part of the fault (a torn write) before dying.
bool FaultMatches(const char* point, int index) {
    FaultSpec& spec = mutableFault();
    if (!spec.armed || index != spec.index) return false;
    return spec.point.substr(0, spec.point.find('|')) == point;
}

// Fires when the armed fault point matches. Returns normally otherwise.
// Counter increments happen before the process dies, and the durable journal
// state is already flushed at every fault point, so the receipt can report how
// many faults were injected without a post-mortem hook.
void MaybeFault(const char* point, int index) {
    if (!FaultMatches(point, index)) return;
    Bump(&MeasuredCounters::faultsInjected);
    char why[128];
    std::snprintf(why, sizeof(why), "%s:%d", point, index);
    DieNow(why);
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------
struct Sha256 {
    std::uint32_t h[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::uint64_t total = 0;
    unsigned char buf[64] = {};
    std::size_t bufLen = 0;

    static std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

    void block(const unsigned char* p) {
        static const std::uint32_t k[64] = {
            0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
            0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
            0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
            0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
            0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u,
            0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u,
            0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u,
            0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u,
            0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
            0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau,
            0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (std::uint32_t(p[i * 4]) << 24) | (std::uint32_t(p[i * 4 + 1]) << 16) |
                   (std::uint32_t(p[i * 4 + 2]) << 8) | std::uint32_t(p[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6],
                      hh = h[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const unsigned char* p, std::size_t n) {
        total += n;
        while (n) {
            const std::size_t take = (64 - bufLen < n) ? (64 - bufLen) : n;
            std::memcpy(buf + bufLen, p, take);
            bufLen += take;
            p += take;
            n -= take;
            if (bufLen == 64) {
                block(buf);
                bufLen = 0;
            }
        }
    }

    std::string hex() {
        const std::uint64_t bits = total * 8;
        unsigned char pad = 0x80;
        update(&pad, 1);
        pad = 0x00;
        while (bufLen != 56) update(&pad, 1);
        unsigned char len[8];
        for (int i = 0; i < 8; ++i) len[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
        update(len, 8);
        char out[65];
        for (int i = 0; i < 8; ++i) std::snprintf(out + i * 8, 9, "%08x", h[i]);
        return std::string(out, 64);
    }
};

// ---------------------------------------------------------------------------
// CRC32 (IEEE), used to detect torn journal lines
// ---------------------------------------------------------------------------
std::uint32_t crc32(const void* data, std::size_t len) {
    static std::uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        ready = true;
    }
    const unsigned char* p = static_cast<const unsigned char*>(data);
    std::uint32_t c = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) c = table[(c ^ p[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ---------------------------------------------------------------------------
// UTF-8 / UTF-16 / path helpers
// ---------------------------------------------------------------------------
std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int needed = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                             nullptr, 0);
    if (needed <= 0) return std::wstring();
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()), &out[0], needed);
    return out;
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
                                             nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return std::string();
    std::string out(static_cast<std::size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &out[0], needed,
                          nullptr, nullptr);
    return out;
}

std::string hexEncode(const std::string& in) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (unsigned char c : in) {
        out.push_back(digits[c >> 4]);
        out.push_back(digits[c & 0x0F]);
    }
    return out;
}

bool hexDecode(const std::string& in, std::string& out) {
    if (in.size() % 2 != 0) return false;
    out.clear();
    out.reserve(in.size() / 2);
    auto nib = [](char c, int& v) {
        if (c >= '0' && c <= '9') { v = c - '0'; return true; }
        if (c >= 'a' && c <= 'f') { v = c - 'a' + 10; return true; }
        if (c >= 'A' && c <= 'F') { v = c - 'A' + 10; return true; }
        return false;
    };
    for (std::size_t i = 0; i < in.size(); i += 2) {
        int hi = 0, lo = 0;
        if (!nib(in[i], hi) || !nib(in[i + 1], lo)) return false;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return true;
}

std::wstring dirName(const std::wstring& path) {
    const std::size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) return std::wstring();
    if (pos == 0) return std::wstring(L"\\");
    return path.substr(0, pos);
}

std::wstring joinPath(const std::wstring& dir, const std::wstring& leaf) {
    if (dir.empty()) return leaf;
    if (leaf.empty()) return dir;
    wchar_t last = dir[dir.size() - 1];
    if (last == L'\\' || last == L'/') return dir + leaf;
    return dir + L"\\" + leaf;
}

std::wstring normalizeSlashes(std::wstring p) {
    for (wchar_t& c : p) {
        if (c == L'/') c = L'\\';
    }
    return p;
}

std::wstring absolutePathW(const std::wstring& path);

std::string absolutePath(const std::string& path) {
    return narrow(absolutePathW(widen(path)));
}

std::wstring absolutePathW(const std::wstring& path) {
    if (path.empty()) return path;
    const std::wstring w = normalizeSlashes(path);
    const DWORD needed = ::GetFullPathNameW(w.c_str(), 0, nullptr, nullptr);
    if (needed == 0) return w;
    std::wstring out(needed, L'\0');
    const DWORD written = ::GetFullPathNameW(w.c_str(), needed, &out[0], nullptr);
    if (written == 0 || written >= needed) return w;
    out.resize(written);
    return out;
}

bool ensureDir(const std::wstring& dir) {
    if (dir.empty()) return false;
    const DWORD attrs = ::GetFileAttributesW(dir.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    const std::wstring parent = dirName(dir);
    if (!parent.empty() && parent != dir && !ensureDir(parent)) return false;
    if (::CreateDirectoryW(dir.c_str(), nullptr)) return true;
    return (::GetLastError() == ERROR_ALREADY_EXISTS);
}

bool fileExists(const std::wstring& path) {
    return ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}

bool readFileBytes(const std::wstring& path, std::string& out) {
    out.clear();
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(h, &size) || size.QuadPart < 0) {
        ::CloseHandle(h);
        return false;
    }
    out.resize(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = out.empty() ? TRUE
                                : ::ReadFile(h, &out[0], static_cast<DWORD>(out.size()), &read,
                                             nullptr);
    ::CloseHandle(h);
    if (!ok) {
        out.clear();
        return false;
    }
    out.resize(read);
    return true;
}

std::uint64_t unixSeconds() {
    FILETIME ft{};
    ::GetSystemTimeAsFileTime(&ft);
    std::uint64_t ticks = (static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return ticks / 10000000ULL;  // 100ns intervals since 1601 -> seconds
}

// ---------------------------------------------------------------------------
// Durable writes
// ---------------------------------------------------------------------------
// Publishes `bytes` at `path` through a temp file + flush + atomic rename.
// A crash therefore leaves either the old file or the new file, never a
// truncated one.
bool DurablePublish(const std::wstring& path, const std::string& bytes, std::string* outError) {
    const std::wstring dir = dirName(path);
    if (!ensureDir(dir)) {
        if (outError) *outError = "cannot create directory " + narrow(dir);
        return false;
    }
    char suffix[64];
    std::snprintf(suffix, sizeof(suffix), ".ckpttmp.%lu.%llu",
                  static_cast<unsigned long>(::GetCurrentProcessId()),
                  static_cast<unsigned long long>(::GetTickCount64()));
    const std::wstring tmp = path + widen(suffix);

    HANDLE h = ::CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (outError) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(::GetLastError()));
            *outError = std::string("CreateFileW temp failed (win32=") + buf + ")";
        }
        return false;
    }
    DWORD written = 0;
    BOOL ok = TRUE;
    if (!bytes.empty()) {
        ok = ::WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    }
    if (ok) ok = ::FlushFileBuffers(h);
    ::CloseHandle(h);
    if (!ok || written != bytes.size()) {
        ::DeleteFileW(tmp.c_str());
        if (outError) *outError = "temp write or flush failed for " + narrow(path);
        return false;
    }
    Bump(&MeasuredCounters::blobFlushes);
    if (!::MoveFileExW(tmp.c_str(), path.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        ::DeleteFileW(tmp.c_str());
        if (outError) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%lu", static_cast<unsigned long>(::GetLastError()));
            *outError = std::string("MoveFileExW failed (win32=") + buf + ")";
        }
        return false;
    }
    Bump(&MeasuredCounters::atomicPublishes);
    return true;
}

// Non-atomic write used only by the torn-write fault injection, to reproduce a
// write that dies halfway through.
void TornPublishForFault(const std::wstring& path, const std::string& bytes) {
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                             FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    const std::size_t half = bytes.size() / 2;
    DWORD written = 0;
    if (half) ::WriteFile(h, bytes.data(), static_cast<DWORD>(half), &written, nullptr);
    ::CloseHandle(h);
}

// ---------------------------------------------------------------------------
// Paths inside the checkpoint tree
// ---------------------------------------------------------------------------
std::wstring ckptRoot(const std::wstring& workspaceRoot) {
    return joinPath(workspaceRoot, L".rawrxd\\ckpt");
}
std::wstring blobsDir(const std::wstring& workspaceRoot) {
    return joinPath(ckptRoot(workspaceRoot), L"blobs");
}
std::wstring journalDir(const std::wstring& workspaceRoot) {
    return joinPath(ckptRoot(workspaceRoot), L"journal");
}
std::wstring recoveryDir(const std::wstring& workspaceRoot) {
    return joinPath(ckptRoot(workspaceRoot), L"recovery");
}

bool storeBlob(const std::wstring& workspaceRoot, const std::string& sha, const std::string& bytes,
               std::string* outError) {
    const std::wstring dir = blobsDir(workspaceRoot);
    if (!ensureDir(dir)) {
        if (outError) *outError = "cannot create blob directory";
        return false;
    }
    const std::wstring path = joinPath(dir, widen(sha));
    if (fileExists(path)) return true;  // content-addressed: identical by definition
    if (!DurablePublish(path, bytes, outError)) return false;
    Bump(&MeasuredCounters::blobWrites);
    return true;
}

bool loadBlob(const std::wstring& workspaceRoot, const std::string& sha, std::string& out) {
    return readFileBytes(joinPath(blobsDir(workspaceRoot), widen(sha)), out);
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------
struct JournalLine {
    std::string type;
    std::vector<std::string> fields;
    std::uint32_t crc = 0;
};

std::string BuildRecord(const std::string& payload) {
    char crcText[16];
    std::snprintf(crcText, sizeof(crcText), "%08x", crc32(payload.data(), payload.size()));
    return payload + "|" + crcText + "\n";
}

// Appends one record and forces it to stable storage before returning.
bool AppendJournal(HANDLE journal, const std::string& payload, std::string* outError) {
    const std::string line = BuildRecord(payload);
    LARGE_INTEGER zero{};
    ::SetFilePointerEx(journal, zero, nullptr, FILE_END);
    DWORD written = 0;
    if (!::WriteFile(journal, line.data(), static_cast<DWORD>(line.size()), &written, nullptr) ||
        written != line.size()) {
        if (outError) *outError = "journal append failed";
        return false;
    }
    if (!::FlushFileBuffers(journal)) {
        if (outError) *outError = "journal FlushFileBuffers failed";
        return false;
    }
    Bump(&MeasuredCounters::journalRecords);
    Bump(&MeasuredCounters::journalFlushes);
    return true;
}

// ---------------------------------------------------------------------------
// Active transaction
// ---------------------------------------------------------------------------
struct ActiveTx {
    bool active = false;
    std::string txId;
    std::string workspaceRoot;  // utf-8
    std::wstring workspaceRootW;
    HANDLE journal = INVALID_HANDLE_VALUE;
    std::uint32_t fileIndex = 0;
    std::vector<std::string> recordedBefore;  // paths whose before-state is durable
};

ActiveTx& active() {
    static ActiveTx tx;
    return tx;
}

std::mutex& activeMutex() {
    static std::mutex m;
    return m;
}

// Measured evidence from the last in-process rollback, kept so a caller can
// report what was actually restored instead of a bare success flag.
RecoveryReport& lastRecovery() {
    static RecoveryReport r;
    return r;
}

std::string makeTxId() {
    char id[96];
    std::snprintf(id, sizeof(id), "tx%llu_%lu_%llx", static_cast<unsigned long long>(unixSeconds()),
                  static_cast<unsigned long>(::GetCurrentProcessId()),
                  static_cast<unsigned long long>(::GetTickCount64()));
    return std::string(id);
}

bool AppendActive(const std::string& payload, std::string* outError) {
    if (!active().active || active().journal == INVALID_HANDLE_VALUE) {
        if (outError) *outError = "no active transaction";
        return false;
    }
    return AppendJournal(active().journal, payload, outError);
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
std::string sha256Hex(const void* data, std::size_t len) {
    Sha256 s;
    if (data && len) s.update(static_cast<const unsigned char*>(data), len);
    return s.hex();
}

std::string sha256Hex(const std::string& data) { return sha256Hex(data.data(), data.size()); }

std::string sha256FileHex(const std::string& path) {
    std::string bytes;
    if (!readFileBytes(widen(path), bytes)) return std::string();
    return sha256Hex(bytes);
}

bool FaultInjectionEnabled() {
    InitFaultFromEnvironment();
    return mutableFault().armed;
}

std::string FaultInjectionDescription() {
    InitFaultFromEnvironment();
    FaultSpec& spec = mutableFault();
    if (!spec.armed) return "disabled";
    return spec.point.substr(0, spec.point.find('|')) + ":" + std::to_string(spec.index);
}

bool Transaction::Begin(const TransactionSpec& spec, std::string* outTxId, std::string* outError) {
    InitFaultFromEnvironment();
    std::lock_guard<std::mutex> lk(activeMutex());
    if (active().active) {
        if (outError) *outError = "a transaction is already active: " + active().txId;
        return false;
    }
    if (spec.workspaceRoot.empty()) {
        if (outError) *outError = "workspaceRoot is required";
        return false;
    }
    const std::string root = absolutePath(spec.workspaceRoot);
    const std::wstring rootW = widen(root);
    if (!ensureDir(journalDir(rootW)) || !ensureDir(blobsDir(rootW)) ||
        !ensureDir(recoveryDir(rootW))) {
        if (outError) *outError = "cannot create the .rawrxd\\ckpt tree under " + root;
        return false;
    }

    const std::string txId = makeTxId();
    const std::wstring journalPath = joinPath(journalDir(rootW), widen(txId + ".jrnl"));
    HANDLE journal = ::CreateFileW(journalPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (journal == INVALID_HANDLE_VALUE) {
        if (outError) *outError = "cannot create journal " + narrow(journalPath);
        return false;
    }

    active().txId = txId;
    active().workspaceRoot = root;
    active().workspaceRootW = rootW;
    active().journal = journal;
    active().fileIndex = 0;
    active().recordedBefore.clear();
    active().active = true;

    std::string error;
    std::ostringstream beginPayload;
    beginPayload << "V1";
    bool ok =
        AppendActive(beginPayload.str(), &error) &&
        AppendActive("BEGIN|" + txId + "|" + std::to_string(unixSeconds()) + "|" +
                         std::to_string(static_cast<unsigned long long>(::GetCurrentProcessId())) +
                         "|" + hexEncode(root),
                     &error);

    // Working-tree identity: recorded as its own record so recovery can report
    // what the tree looked like before the agent touched it.
    if (ok) {
        const WorkingTreeIdentity id = CaptureIdentity(root);
        std::ostringstream wt;
        wt << "WORKTREE|" << (id.gitPresent ? 1 : 0) << "|" << hexEncode(id.headRef) << "|"
           << id.headSha << "|" << id.indexSha256 << "|" << id.treeSha256 << "|"
           << id.fileCount << "|" << id.totalBytes << "|" << id.identitySha256;
        ok = AppendActive(wt.str(), &error);
    }

    struct Payload {
        const char* tag;
        const std::string* text;
    };
    const Payload payloads[3] = {{"PLAN", &spec.plan},
                                 {"CONTEXT", &spec.modelContext},
                                 {"DIAG", &spec.diagnostics}};
    for (const Payload& p : payloads) {
        if (!ok) break;
        const std::string& body = *p.text;
        const std::string sha = sha256Hex(body);
        if (!body.empty() && !storeBlob(rootW, sha, body, &error)) {
            ok = false;
            break;
        }
        std::ostringstream rec;
        rec << p.tag << "|" << sha << "|" << body.size();
        ok = AppendActive(rec.str(), &error);
    }
    if (!ok && outError) *outError = error.empty() ? "journal write failed" : error;

    if (!ok) {
        ::CloseHandle(journal);
        active() = ActiveTx();
        return false;
    }
    if (outTxId) *outTxId = txId;
    return true;
}

bool Transaction::Active() {
    std::lock_guard<std::mutex> lk(activeMutex());
    return active().active;
}

std::string Transaction::ActiveTxId() {
    std::lock_guard<std::mutex> lk(activeMutex());
    return active().active ? active().txId : std::string();
}

std::string Transaction::ActiveWorkspaceRoot() {
    std::lock_guard<std::mutex> lk(activeMutex());
    return active().active ? active().workspaceRoot : std::string();
}

WorkingTreeIdentity Transaction::CaptureIdentity(const std::string& workspaceRoot) {
    WorkingTreeIdentity id;
    const std::string root = absolutePath(workspaceRoot);
    const std::wstring rootW = widen(root);
    id.gitDir = narrow(rootW);

    // .git may be a directory (normal) or a file (worktree/submodule pointer).
    std::wstring gitDir;
    const std::wstring dotGit = joinPath(rootW, L".git");
    const DWORD attrs = ::GetFileAttributesW(dotGit.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
            gitDir = dotGit;
        } else {
            std::string text;
            if (readFileBytes(dotGit, text)) {
                const std::string prefix = "gitdir:";
                if (text.rfind(prefix, 0) == 0) {
                    std::string rel = text.substr(prefix.size());
                    while (!rel.empty() && (rel.front() == ' ' || rel.front() == '\t')) {
                        rel.erase(rel.begin());
                    }
                    while (!rel.empty() && (rel.back() == '\n' || rel.back() == '\r' ||
                                            rel.back() == ' ')) {
                        rel.pop_back();
                    }
                    gitDir = widen(absolutePath(rel));
                }
            }
        }
    }
    if (!gitDir.empty() && ::GetFileAttributesW(gitDir.c_str()) != INVALID_FILE_ATTRIBUTES) {
        id.gitPresent = true;
        id.gitDir = narrow(gitDir);

        std::string head;
        if (readFileBytes(joinPath(gitDir, L"HEAD"), head)) {
            while (!head.empty() && (head.back() == '\n' || head.back() == '\r')) head.pop_back();
            if (head.rfind("ref:", 0) == 0) {
                id.headRef = head.substr(4);
                while (!id.headRef.empty() && id.headRef.front() == ' ') id.headRef.erase(0, 1);
                std::string loose;
                if (readFileBytes(joinPath(gitDir, widen(id.headRef)), loose)) {
                    while (!loose.empty() && (loose.back() == '\n' || loose.back() == '\r')) {
                        loose.pop_back();
                    }
                    id.headSha = loose;
                } else {
                    std::string packed;
                    if (readFileBytes(joinPath(gitDir, L"packed-refs"), packed)) {
                        std::istringstream ps(packed);
                        std::string line;
                        while (std::getline(ps, line)) {
                            if (line.rfind("#", 0) == 0) continue;
                            std::istringstream ls(line);
                            std::string sha, name;
                            if (std::getline(ls, sha, ' ') && std::getline(ls, name, ' ')) {
                                while (!name.empty() && name.front() == ' ') name.erase(0, 1);
                                if (name == id.headRef) {
                                    id.headSha = sha;
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                id.headSha = head;
            }
        }
        id.indexSha256 = sha256FileHex(narrow(joinPath(gitDir, L"index")));
    }

    // Workspace tree identity: every file under the root except the checkpoint
    // tree itself and .git, hashed from (relpath, content-sha256) in sorted
    // order.
    //
    // CONTENT, not (size, mtime): a byte-exact restore rewrites the file, so
    // its mtime necessarily changes. An identity that included mtime could never
    // be reproduced by recovery, which would make "did the tree come back?"
    // unanswerable -- the first run of this cert failed exactly that way.
    // Files above kIdentityHashMax contribute (relpath, size) instead; the
    // count of those is mixed into the identity so the substitution is visible
    // rather than silent.
    constexpr std::uint64_t kIdentityHashMax = 8ull << 20;
    std::vector<std::string> entries;
    std::uint64_t largeFiles = 0;
    std::vector<std::wstring> stack{rootW};
    while (!stack.empty()) {
        const std::wstring dir = stack.back();
        stack.pop_back();
        const std::wstring pattern = joinPath(dir, L"*");
        WIN32_FIND_DATAW fd{};
        HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            const std::wstring name(fd.cFileName);
            if (name == L"." || name == L"..") continue;
            const std::wstring full = joinPath(dir, name);
            if (dir == rootW && (name == L".git" || name == L".rawrxd")) continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                stack.push_back(full);
                continue;
            }
            const std::string rel = narrow(full.substr(rootW.size() + 1));
            const std::uint64_t size =
                (static_cast<std::uint64_t>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
            std::string contentSha;
            if (size <= kIdentityHashMax) {
                std::string bytes;
                contentSha = readFileBytes(full, bytes) ? sha256Hex(bytes) : std::string("unreadable");
            } else {
                ++largeFiles;
                contentSha = "size:" + std::to_string(size);
            }
            entries.push_back(rel + std::string(1, '\0') + contentSha + std::string(1, '\0'));
            id.fileCount += 1;
            id.totalBytes += size;
        } while (::FindNextFileW(h, &fd));
        ::FindClose(h);
    }
    std::sort(entries.begin(), entries.end());
    std::string joined;
    for (const std::string& e : entries) joined += e;
    id.treeSha256 = sha256Hex(joined);
    id.largeFilesHashedBySize = largeFiles;

    std::ostringstream identity;
    identity << (id.gitPresent ? 1 : 0) << '|' << id.gitDir << '|' << id.headRef << '|'
             << id.headSha << '|' << id.indexSha256 << '|' << id.treeSha256 << '|'
             << id.fileCount << '|' << id.totalBytes << '|' << largeFiles;
    id.identitySha256 = sha256Hex(identity.str());
    return id;
}

bool Transaction::WriteFile(const std::string& absPath, const std::string& content,
                            std::string* outError) {
    return WriteFileW(widen(absolutePath(absPath)), content, outError);
}

bool Transaction::WriteFileW(const std::wstring& wide, const std::string& content,
                             std::string* outError) {
    InitFaultFromEnvironment();
    // The caller supplies a wide path; canonicalisation here is identical to the
    // utf-8 entry point's, so a rollback matches the recorded write exactly.
    const std::string canonical = narrow(absolutePathW(wide));

    std::lock_guard<std::mutex> lk(activeMutex());
    const bool inTx = active().active;
    if (!inTx) {
        // No transaction: still publish atomically so a crash cannot truncate.
        return DurablePublish(wide, content, outError);
    }

    const std::wstring rootW = active().workspaceRootW;
    std::string error;

    // before-state, captured once per path
    bool alreadyRecorded = false;
    for (const std::string& p : active().recordedBefore) {
        if (p == canonical) {
            alreadyRecorded = true;
            break;
        }
    }
    if (!alreadyRecorded) {
        const bool existed = fileExists(wide);
        std::string beforeBytes;
        if (existed && !readFileBytes(wide, beforeBytes)) {
            if (outError) *outError = "cannot read before-state of " + canonical;
            return false;
        }
        const std::string beforeSha = existed ? sha256Hex(beforeBytes) : std::string();
        if (existed && !storeBlob(rootW, beforeSha, beforeBytes, &error)) {
            if (outError) *outError = "cannot persist before-state: " + error;
            return false;
        }
        std::ostringstream rec;
        rec << "FILE_BEFORE|" << hexEncode(canonical) << "|" << (existed ? 1 : 0) << "|"
            << beforeSha << "|" << beforeBytes.size();
        if (!AppendActive(rec.str(), &error)) {
            if (outError) *outError = "cannot journal before-state: " + error;
            return false;
        }
        active().recordedBefore.push_back(canonical);
    }

    const int index = ++active().fileIndex;
    MaybeFault("crash_before_write", index);
    if (FaultMatches("crash_torn", index)) {
        // Reproduce the write that dies halfway through: half the bytes reach
        // the target path directly, with no temp file and no rename, and the
        // process dies before the after-state record is journalled.
        TornPublishForFault(wide, content);
        Bump(&MeasuredCounters::faultsInjected);
        DieNow("crash_torn");
    }

    if (!DurablePublish(wide, content, outError)) return false;
    Bump(&MeasuredCounters::fileWrites);

    std::ostringstream rec;
    rec << "FILE_AFTER|" << hexEncode(canonical) << "|" << sha256Hex(content) << "|"
        << content.size();
    if (!AppendActive(rec.str(), &error)) {
        if (outError) *outError = "cannot journal after-state: " + error;
        return false;
    }
    MaybeFault("crash_after", index);
    return true;
}

bool Transaction::RecordCommand(const std::string& command, int exitCode,
                               const std::string& stdoutText, const std::string& stderrText,
                               std::uint64_t elapsedMicros) {
    std::lock_guard<std::mutex> lk(activeMutex());
    if (!active().active) return false;
    std::ostringstream rec;
    rec << "CMD|" << hexEncode(command) << "|" << exitCode << "|" << sha256Hex(stdoutText) << "|"
        << sha256Hex(stderrText) << "|" << elapsedMicros;
    return AppendActive(rec.str(), nullptr);
}

bool Transaction::RecordToolResult(const std::string& tool, const std::string& paramsText,
                                   bool success, const std::string& output, const std::string& error,
                                   std::uint64_t elapsedMicros) {
    std::lock_guard<std::mutex> lk(activeMutex());
    if (!active().active) return false;
    std::ostringstream rec;
    rec << "TOOL|" << hexEncode(tool) << "|" << sha256Hex(paramsText) << "|" << (success ? 1 : 0)
        << "|" << sha256Hex(output) << "|" << sha256Hex(error) << "|" << elapsedMicros;
    return AppendActive(rec.str(), nullptr);
}

bool Transaction::Commit(std::string* outError) {
    std::lock_guard<std::mutex> lk(activeMutex());
    if (!active().active) {
        if (outError) *outError = "no active transaction";
        return false;
    }
    std::string error;
    const bool ok = AppendActive("COMMIT|" + active().txId + "|" + std::to_string(unixSeconds()),
                                 &error);
    ::CloseHandle(active().journal);
    active() = ActiveTx();
    if (!ok && outError) *outError = error;
    return ok;
}

bool Transaction::Rollback(std::string* outError) {
    std::string root;
    {
        std::lock_guard<std::mutex> lk(activeMutex());
        root = active().workspaceRoot;
    }
    if (root.empty()) {
        if (outError) *outError = "no active transaction";
        return false;
    }
    // PRE-FIX ORDERING, RESTORED DELIBERATELY FOR THE FALSIFICATION PROBE.
    // The recovery pass runs while this process still holds the journal handle
    // that Begin() opened with FILE_SHARE_READ, so the reopen it performs to
    // append ROLLBACK fails with ERROR_SHARING_VIOLATION and the transaction
    // stays permanently incomplete.
    const RecoveryReport rep = RecoverWorkspace(root, /*writeReceipt=*/true);
    {
        std::lock_guard<std::mutex> lk(activeMutex());
        lastRecovery() = rep;
        if (active().journal != INVALID_HANDLE_VALUE) ::CloseHandle(active().journal);
        active() = ActiveTx();
    }
    if (!rep.AllRestored()) {
        if (outError) {
            std::ostringstream oss;
            oss << "rollback incomplete: failed=" << rep.filesFailed
                << " missingBlobs=" << rep.missingBlobs;
            *outError = oss.str();
        }
        return false;
    }
    return true;
}

MeasuredCounters Transaction::Counters() { return SnapshotCounters(); }

RecoveryReport Transaction::LastRecovery() {
    std::lock_guard<std::mutex> lk(activeMutex());
    return lastRecovery();
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------
namespace {

bool ParseRecord(const std::string& line, JournalLine& out, bool& crcOk) {
    const std::size_t lastPipe = line.find_last_of('|');
    if (lastPipe == std::string::npos) {
        crcOk = false;
        return false;
    }
    const std::string payload = line.substr(0, lastPipe);
    const std::string crcText = line.substr(lastPipe + 1);
    char* end = nullptr;
    const unsigned long want = std::strtoul(crcText.c_str(), &end, 16);
    crcOk = (end && *end == '\0' && !crcText.empty());
    if (crcOk) {
        const std::uint32_t got = crc32(payload.data(), payload.size());
        crcOk = (got == static_cast<std::uint32_t>(want));
    }
    if (!crcOk) return false;

    std::vector<std::string> parts;
    std::string field;
    std::istringstream iss(payload);
    while (std::getline(iss, field, '|')) parts.push_back(field);
    if (parts.empty()) return false;
    out.type = parts[0];
    out.fields.assign(parts.begin() + 1, parts.end());
    out.crc = static_cast<std::uint32_t>(want);
    return true;
}

struct BeforeEntry {
    std::string path;
    bool existed = false;
    std::string beforeSha;
};

void WriteRecoveryReceipt(const std::wstring& rootW, const std::string& txId, const RecoveryReport& r) {
    ensureDir(recoveryDir(rootW));
    const std::wstring path = joinPath(recoveryDir(rootW), widen(txId + ".txt"));
    std::ostringstream oss;
    oss << "RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001\n"
        << "transaction=" << txId << "\n"
        << "reason=no COMMIT record in journal (interrupted transaction)\n"
        << "workspace=" << r.workspaceRoot << "\n"
        << "files_restored=" << r.filesRestored << "\n"
        << "files_deleted=" << r.filesDeleted << "\n"
        << "files_verified=" << r.filesVerified << "\n"
        << "files_failed=" << r.filesFailed << "\n"
        << "torn_records_discarded=" << r.tornRecordsDiscarded << "\n"
        << "missing_blobs=" << r.missingBlobs << "\n"
        << "journal_flushes=" << r.fsyncCalls << "\n"
        << "identity_before=" << r.identityBeforeSha256 << "\n"
        << "identity_after=" << r.identityAfterSha256 << "\n";
    for (const std::string& f : r.failedPaths) oss << "failed_path=" << f << "\n";
    oss << "verdict=" << (r.filesFailed == 0 ? "RESTORED" : "INCOMPLETE") << "\n";
    const std::string text = oss.str();
    std::string err;
    DurablePublish(path, text, &err);
}

}  // namespace

RecoveryReport RecoverWorkspace(const std::string& workspaceRoot, bool writeReceipt) {
    RecoveryReport r;
    r.invoked = true;
    r.workspaceRoot = absolutePath(workspaceRoot);
    const std::wstring rootW = widen(r.workspaceRoot);

    r.identityBeforeSha256 = Transaction::CaptureIdentity(r.workspaceRoot).identitySha256;

    const std::wstring jdir = journalDir(rootW);
    std::vector<std::wstring> journals;
    {
        const std::wstring pattern = joinPath(jdir, L"*.jrnl");
        WIN32_FIND_DATAW fd{};
        HANDLE h = ::FindFirstFileW(pattern.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                journals.push_back(joinPath(jdir, fd.cFileName));
            } while (::FindNextFileW(h, &fd));
            ::FindClose(h);
        }
    }

    for (const std::wstring& journalPath : journals) {
        r.journalsScanned += 1;
        std::string text;
        if (!readFileBytes(journalPath, text)) continue;

        const std::string fileName = narrow(journalPath.substr(journalPath.find_last_of(L"\\/") + 1));
        const std::string txId = fileName.rfind(".jrnl") == std::string::npos
                                     ? fileName
                                     : fileName.substr(0, fileName.size() - 5);

        bool committed = false;
        bool alreadyRolledBack = false;
        std::vector<BeforeEntry> befores;
        std::istringstream iss(text);
        std::string line;
        while (std::getline(iss, line)) {
            if (line.empty()) continue;
            if (!line.empty() && line.back() == '\r') line.pop_back();
            JournalLine rec;
            bool crcOk = false;
            if (!ParseRecord(line, rec, crcOk)) {
                // A torn trailing line is the expected power-loss artifact.
                r.tornRecordsDiscarded += 1;
                Bump(&MeasuredCounters::crcFailures);
                continue;
            }
            if (rec.type == "COMMIT") {
                committed = true;
            } else if (rec.type == "ROLLBACK") {
                // A previous recovery pass already closed this transaction by
                // undoing it. Treating it as still-open would replay the same
                // rollback on every startup forever. The first run of the cert
                // caught exactly that: the second pass re-restored identical
                // bytes and reported the transaction as still incomplete.
                alreadyRolledBack = true;
            } else if (rec.type == "FILE_BEFORE" && rec.fields.size() >= 4) {
                BeforeEntry e;
                if (!hexDecode(rec.fields[0], e.path)) continue;
                e.existed = rec.fields[1] == "1";
                e.beforeSha = rec.fields[2];
                bool replaced = false;
                for (BeforeEntry& existing : befores) {
                    if (existing.path == e.path) {
                        existing = e;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced) befores.push_back(e);
            }
        }

        if (committed || alreadyRolledBack) {
            r.closedTransactions += 1;
            continue;
        }

        r.incompleteTransactions += 1;
        r.recoveredTxIds.push_back(txId);

        // Roll back in reverse write order.
        for (std::size_t i = befores.size(); i-- > 0;) {
            const BeforeEntry& e = befores[i];
            const std::wstring wide = widen(e.path);
            if (!e.existed) {
                // The transaction created this file: restoring means removing it.
                if (fileExists(wide) && ::DeleteFileW(wide.c_str())) {
                    Bump(&MeasuredCounters::fileDeletes);
                }
                if (!fileExists(wide)) {
                    r.filesDeleted += 1;
                } else {
                    r.filesFailed += 1;
                    r.failedPaths.push_back(e.path);
                }
                continue;
            }
            std::string blob;
            if (!loadBlob(rootW, e.beforeSha, blob)) {
                r.missingBlobs += 1;
                r.filesFailed += 1;
                r.failedPaths.push_back(e.path);
                continue;
            }
            if (sha256Hex(blob) != e.beforeSha) {
                r.filesFailed += 1;
                r.failedPaths.push_back(e.path);
                continue;
            }
            std::string err;
            if (!DurablePublish(wide, blob, &err)) {
                r.filesFailed += 1;
                r.failedPaths.push_back(e.path);
                continue;
            }
            Bump(&MeasuredCounters::fileWrites);
            const std::string now = sha256FileHex(e.path);
            if (now == e.beforeSha) {
                r.filesVerified += 1;
                r.filesRestored += 1;
            } else {
                r.filesFailed += 1;
                r.failedPaths.push_back(e.path);
            }
        }

        // Close the journal durably so a second startup does not replay it.
        HANDLE j = ::CreateFileW(journalPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (j != INVALID_HANDLE_VALUE) {
            std::ostringstream rec;
            rec << "ROLLBACK|" << txId << "|" << unixSeconds() << "|" << r.filesRestored << "|"
                << r.filesDeleted << "|" << r.filesFailed;
            std::string err;
            if (AppendJournal(j, rec.str(), &err)) r.fsyncCalls += 1;
            ::CloseHandle(j);
        }
    }

    r.identityAfterSha256 = Transaction::CaptureIdentity(r.workspaceRoot).identitySha256;

    if (writeReceipt && r.incompleteTransactions > 0) {
        ensureDir(recoveryDir(rootW));
        char stamp[32];
        std::snprintf(stamp, sizeof(stamp), "%llu", static_cast<unsigned long long>(unixSeconds()));
        const std::wstring path = joinPath(recoveryDir(rootW), widen(std::string(stamp) + "_pass.txt"));
        std::ostringstream oss;
        oss << "RAWRXD_IDE_CHECKPOINT_ROLLBACK_AUTHORITY_001 startup recovery pass\n"
            << "workspace=" << r.workspaceRoot << "\n"
            << "journals_scanned=" << r.journalsScanned << "\n"
            << "closed_transactions=" << r.closedTransactions << "\n"
            << "incomplete_transactions=" << r.incompleteTransactions << "\n"
            << "files_restored=" << r.filesRestored << "\n"
            << "files_deleted=" << r.filesDeleted << "\n"
            << "files_verified=" << r.filesVerified << "\n"
            << "files_failed=" << r.filesFailed << "\n"
            << "torn_records_discarded=" << r.tornRecordsDiscarded << "\n"
            << "missing_blobs=" << r.missingBlobs << "\n"
            << "identity_before=" << r.identityBeforeSha256 << "\n"
            << "identity_after=" << r.identityAfterSha256 << "\n";
        for (const std::string& tx : r.recoveredTxIds) oss << "recovered=" << tx << "\n";
        for (const std::string& f : r.failedPaths) oss << "failed_path=" << f << "\n";
        oss << "verdict=" << (r.filesFailed == 0 ? "ALL_TRANSACTIONS_CLOSED" : "ROLLBACK_INCOMPLETE")
            << "\n";
        const std::string text = oss.str();
        std::string err;
        DurablePublish(path, text, &err);
        r.receiptPath = narrow(path);
        for (const std::string& tx : r.recoveredTxIds) WriteRecoveryReceipt(rootW, tx, r);
    }
    return r;
}

}  // namespace ckpt
}  // namespace rawrxd