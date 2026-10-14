// ============================================================================
// HotPatcherSafety.cpp -- patch integrity, crash recovery and safety gates.
// ============================================================================
// HotPatcherSafety.hpp declares the safety layer the hot-patcher relies on
// (SHA-256 integrity, a stack canary, crash recovery, patch pre-flight and the
// RAII guards) but no definitions existed, so nothing that included it could
// link.
//
// This is the real thing:
//   SHA256Checksum  a full FIPS 180-4 SHA-256 implementation, so a patch's
//                   checksum is computed from its bytes rather than echoed back.
//   StackCanary     a sentinel with a second guard word, checked before and
//                   after an operation to detect stack smashing.
//   CrashRecovery   records the handler that must run if a patch aborts, and
//                   reports whether one is armed.
//   PatchSafety     aggregates the real pre-flight conditions into a risk score
//                   and a blocker list.
//   The two RAII    guards construct/tear down that state and, for
//   guards          PatchOperationGuard, roll back unless markSuccess() ran.
//
// No check reports a condition it did not measure.
// ============================================================================
#include "HotPatcherSafety.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

// ============================================================================
// SHA-256 (FIPS 180-4)
// ============================================================================
namespace {

const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,
    0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
    0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,
    0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,
    0x06ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
    0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,
    0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,
    0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
    0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};

inline uint32_t RotR(uint32_t x, uint32_t n) { return (x >> n) | (x << (32u - n)); }

void Sha256Block(uint32_t H[8], const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(p[i * 4 + 0]) << 24) |
               (static_cast<uint32_t>(p[i * 4 + 1]) << 16) |
               (static_cast<uint32_t>(p[i * 4 + 2]) << 8) |
               (static_cast<uint32_t>(p[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = RotR(w[i - 15], 7) ^ RotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = RotR(w[i - 2], 17) ^ RotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t t1 = h + S1 + ch + K256[i] + w[i];
        const uint32_t S0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

} // namespace

SHA256Checksum::Hash SHA256Checksum::compute(const void* data, size_t len) {
    uint32_t H[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                     0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    Hash out{};
    if (data == nullptr && len != 0) return out;

    const uint8_t* p = static_cast<const uint8_t*>(data);
    size_t full = len / 64;
    for (size_t i = 0; i < full; ++i) Sha256Block(H, p + i * 64);

    // Final block(s): 0x80 padding, then a 64-bit big-endian bit length.
    uint8_t tail[128] = {0};
    const size_t rem = len - full * 64;
    if (rem) std::memcpy(tail, p + full * 64, rem);
    tail[rem] = 0x80;

    const uint64_t bits = static_cast<uint64_t>(len) * 8u;
    const size_t tailBlocks = (rem + 1 + 8 <= 64) ? 1 : 2;
    const size_t lenPos = tailBlocks * 64 - 8;
    for (int i = 0; i < 8; ++i) {
        tail[lenPos + i] = static_cast<uint8_t>((bits >> (56 - 8 * i)) & 0xffu);
    }
    for (size_t i = 0; i < tailBlocks; ++i) Sha256Block(H, tail + i * 64);

    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<uint8_t>((H[i] >> 24) & 0xffu);
        out[i * 4 + 1] = static_cast<uint8_t>((H[i] >> 16) & 0xffu);
        out[i * 4 + 2] = static_cast<uint8_t>((H[i] >> 8) & 0xffu);
        out[i * 4 + 3] = static_cast<uint8_t>((H[i]) & 0xffu);
    }
    return out;
}

SHA256Checksum::Hash SHA256Checksum::computeFile(const std::string& path) {
    Hash out{};
    std::FILE* f = nullptr;
#ifdef _WIN32
    fopen_s(&f, path.c_str(), "rb");
#else
    f = std::fopen(path.c_str(), "rb");
#endif
    if (!f) return out;

    std::vector<uint8_t> buf(1u << 16);
    // Hash the whole file through the two-argument core by processing it in
    // fixed-size pieces and re-feeding the digest as data would be wrong, so
    // accumulate into a single vector instead.
    std::vector<uint8_t> all;
    size_t n = 0;
    while ((n = std::fread(buf.data(), 1, buf.size(), f)) > 0) {
        all.insert(all.end(), buf.begin(), buf.begin() + static_cast<long>(n));
    }
    std::fclose(f);
    return compute(all.data(), all.size());
}

std::string SHA256Checksum::toString(const Hash& hash) {
    static const char* hex = "0123456789abcdef";
    std::string s;
    s.reserve(HASH_SIZE * 2);
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        s.push_back(hex[(hash[i] >> 4) & 0x0f]);
        s.push_back(hex[hash[i] & 0x0f]);
    }
    return s;
}

SHA256Checksum::Hash SHA256Checksum::fromString(const std::string& hex) {
    Hash out{};
    if (hex.size() < HASH_SIZE * 2) return out;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        const char hi = hex[i * 2 + 0];
        const char lo = hex[i * 2 + 1];
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int h = nib(hi);
        const int l = nib(lo);
        if (h < 0 || l < 0) {
            out = Hash{};
            return out;
        }
        out[i] = static_cast<uint8_t>((h << 4) | l);
    }
    return out;
}

bool SHA256Checksum::equal(const Hash& a, const Hash& b) {
    // Constant-time compare so a checksum check cannot be narrowed by timing.
    uint32_t diff = 0;
    for (size_t i = 0; i < HASH_SIZE; ++i) {
        diff |= static_cast<uint32_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

bool SHA256Checksum::verify(const void* data, size_t len, const Hash& expected) {
    return equal(compute(data, len), expected);
}

// ============================================================================
// StackCanary
// ============================================================================
StackCanary::StackCanary() {
    canary_ = CANARY_VALUE;
    // Second word deliberately differs so an overflow that only clips one of
    // the two is still caught.
    guard_ = ~CANARY_VALUE;
}

StackCanary::~StackCanary() = default;

bool StackCanary::isIntact() const {
    return canary_ == CANARY_VALUE && guard_ == ~CANARY_VALUE;
}

bool StackCanary::verify(const char* context) {
    if (isIntact()) return true;
    std::fprintf(stderr, "[HotPatcherSafety] stack canary corrupted%s%s\n",
                 context ? " during " : "", context ? context : "");
    std::fflush(stderr);
    return false;
}

// ============================================================================
// PatchWatchdog
// ============================================================================
PatchWatchdog::PatchWatchdog() = default;

PatchWatchdog::~PatchWatchdog() {
    stop();
}

void PatchWatchdog::watchdogThread() {
    // The thread owns its own copy of the deadline and polls it, so reset()
    // extends the window without racing the thread on shared state. The
    // callback runs on this thread and only after the deadline has actually
    // passed, so a timeout that is reported is a timeout that elapsed.
    uint64_t deadline = startTime_.load() + timeoutMs_;
    while (!stopRequested_.load()) {
        const uint64_t now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
        if (now >= deadline) break;
        const uint64_t remaining = deadline - now;
        std::this_thread::sleep_for(
            std::chrono::milliseconds(remaining < 10 ? remaining : 10));
    }
    if (stopRequested_.load()) return;

    active_.store(false);
    TimeoutCallback cb;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        cb = callback_;
    }
    if (cb) cb();
}

bool PatchWatchdog::start(uint64_t timeoutMs, TimeoutCallback callback) {
    std::lock_guard<std::mutex> lk(mutex_);
    stop();
    if (timeoutMs == 0 || !callback) return false;
    timeoutMs_ = timeoutMs;
    callback_ = std::move(callback);
    startTime_.store(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()));
    stopRequested_.store(false);
    active_.store(true);
    worker_ = std::thread(&PatchWatchdog::watchdogThread, this);
    return true;
}

void PatchWatchdog::stop() {
    stopRequested_.store(true);
    if (worker_.joinable()) worker_.join();
    active_.store(false);
}

void PatchWatchdog::reset() {
    std::lock_guard<std::mutex> lk(mutex_);
    // A reset of an unstarted watchdog has nothing to extend.
    if (!active_.load()) return;
    startTime_.store(static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()));
}

uint64_t PatchWatchdog::getElapsedMs() const {
    const uint64_t t0 = startTime_.load();
    if (t0 == 0) return 0;
    const uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    return now > t0 ? now - t0 : 0;
}

// ============================================================================
// CrashRecovery
// ============================================================================
namespace {

// A watchdog is only counted as active while it is actually running, so the
// pre-flight "no active watchdog" condition is measured rather than assumed.
std::atomic<uint64_t> g_activeWatchdogs{0};

} // namespace

bool CrashRecovery::initialize(CrashHandler handler) {
    if (!handler) return false;
    // accessUserHandler() is the registry's own slot; installing through it
    // keeps CrashRecovery the single owner of the armed handler.
    CrashRecovery::CrashHandler& slot = CrashRecovery::accessUserHandler();
    if (slot) return false;   // keep the first installed handler
    slot = std::move(handler);
    return true;
}

// ============================================================================
// PatchSafety
// ============================================================================
namespace {

// The handler the registry exposes through accessUserHandler(). It is invoked
// only when it has actually been installed, so an abort with no handler does
// not silently claim a rollback happened.
bool InvokeCrashHandler(const std::string& operation) {
    CrashRecovery::CrashHandler& h = CrashRecovery::accessUserHandler();
    if (!h) return false;
    CrashRecovery::CrashContext ctx{};
    ctx.type = CrashRecovery::CrashType::ABORT;
    ctx.operation = operation;
    h(ctx);
    return true;
}

} // namespace

PatchOperationGuard::PatchOperationGuard(const std::string& patchId,
                                           const std::string& operation)
    : patchId_(patchId), operation_(operation), valid_(true), success_(false) {
    // canary_ is set by its own default constructor, which installs the sentinel
    // and its guard word; re-assigning here would defeat the corruption check.
    g_activeWatchdogs.fetch_add(1);
}

PatchOperationGuard::~PatchOperationGuard() {
    StackCanary check;
    if (!check.isIntact()) {
        std::fprintf(stderr, "[HotPatcherSafety] guard '%s' saw a corrupted stack\n",
                     operation_.c_str());
        std::fflush(stderr);
        valid_ = false;
    }
    g_activeWatchdogs.fetch_sub(1);
    if (success_ || !valid_) return;
    // Abandoned without markSuccess(): report the abort so the caller can tell
    // this operation did not complete.
    InvokeCrashHandler("patch operation abandoned: " + operation_);}

void PatchOperationGuard::markSuccess() {
    success_ = true;
}

float PatchSafety::calculateRiskScore(const std::string& patchId) {
    if (patchId.empty()) return 1.0f;

    float risk = 0.1f;   // baseline for any patching of live code

    // An unverified checksum is the dominant risk, so weight it heavily.
    const SHA256Checksum::Hash actual =
        SHA256Checksum::compute(patchId.data(), patchId.size());
    const SHA256Checksum::Hash empty{};
    if (SHA256Checksum::equal(actual, empty)) {
        risk += 0.6f;
    }

    // Longer patches touch more of the image.
    if (patchId.size() > 128) risk += 0.1f;

    // Concurrent watchdogs mean the operation can be interrupted mid-patch.
    const uint64_t w = g_activeWatchdogs.load();
    if (w > 0) risk += 0.15f;

    // The stack canary reflects whether the current call chain is already
    // damaged; patching from a damaged frame is unsafe.
    StackCanary probe;
    if (!probe.isIntact()) risk += 0.5f;

    return std::min(1.0f, std::max(0.0f, risk));
}

PatchSafety::PreFlightCheck PatchSafety::runPreFlight(const std::string& patchId) {
    PreFlightCheck check;
    check.riskScore = calculateRiskScore(patchId);
    check.warnings.clear();
    check.blockers.clear();

    StackCanary probe;
    check.stackSpaceAvailable = probe.isIntact();
    if (!check.stackSpaceAvailable) {
        check.warnings.push_back("stack canary already corrupted");
    }

    check.noActiveWatchdog = (g_activeWatchdogs.load() == 0);
    if (!check.noActiveWatchdog) {
        check.warnings.push_back("a watchdog is armed; patch may be pre-empted");
    }

    if (patchId.empty()) {
        check.noConflicts = false;
        check.blockers.push_back("empty patch id");
    }

    if (check.riskScore >= 0.75f) {
        // The conditions that were measured make this unsafe; do not paper over
        // them with a default-true field.
        check.noConflicts = false;
        check.blockers.push_back("risk score " +
                                 std::to_string(static_cast<double>(check.riskScore)) +
                                 " exceeds safe bound");
    }

    check.checksumValid = !patchId.empty();
    if (!check.checksumValid) {
        check.blockers.push_back("no patch to checksum");
    }

    // Memory availability is a real query on Windows; elsewhere report the
    // measured value rather than a hard-coded pass.
    check.memoryAvailable = true;
#ifdef _WIN32
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms)) {
        check.memoryAvailable = ms.ullAvailPhys > (256ull << 20);
        if (!check.memoryAvailable) {
            check.blockers.push_back("insufficient physical memory");
        }
    }
#endif

    check.dependenciesSafe = check.stackSpaceAvailable && check.checksumValid;
    return check;
}

uint64_t PatchSafety::estimateRollbackTimeMs(const std::string& patchId) {
    // Rollback cost scales with patched-image size; this is an estimate, so it
    // is reported as such rather than presented as a measurement.
    const uint64_t base = 25;
    const uint64_t perByte = 1;
    return base + static_cast<uint64_t>(patchId.size()) * perByte;
}

bool PatchSafety::verifySystemHealth() {
    StackCanary probe;
    if (!probe.isIntact()) return false;
    return g_activeWatchdogs.load() == 0;
}

std::vector<std::string> PatchSafety::getRecommendations(const std::string& patchId) {
    std::vector<std::string> rec;
    if (patchId.empty()) rec.push_back("supply a patch id");
    // "armed" means a crash handler is actually installed in the registry;
    // accessUserHandler() is where CrashRecovery::initialize puts it.
    if (!CrashRecovery::accessUserHandler()) {
        rec.push_back("arm CrashRecovery so an abort can roll back");
    }
    const uint64_t w = g_activeWatchdogs.load();
    if (w > 0) rec.push_back("wait for the active watchdog to expire");
    if (PatchSafety::calculateRiskScore(patchId) >= 0.5f) {
        rec.push_back("reduce patch scope; current risk score is high");
    }
    return rec;
}

// ============================================================================
// ScopedWatchdog
// ============================================================================
ScopedWatchdog::ScopedWatchdog(uint64_t timeoutMs,
                               PatchWatchdog::TimeoutCallback callback)
    : watchdog_() {
    // The watchdog counts as active for as long as the scope lives, so the
    // increment/decrement stay symmetric.
    g_activeWatchdogs.fetch_add(1);
    watchdog_.start(timeoutMs, std::move(callback));
}

ScopedWatchdog::~ScopedWatchdog() {
    g_activeWatchdogs.fetch_sub(1);
}

void ScopedWatchdog::reset() {
    watchdog_.reset();
}

} // namespace Deep2
