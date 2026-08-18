// ============================================================================
// K2TimeLimitedServing.cpp — K2-TLS: Time-Limited Serving Implementation
// ============================================================================

#include "K2TimeLimitedServing.hpp"
#include <algorithm>

namespace rawrxd::deep2 {

const char* K2TLSStatusName(K2TLSStatus status)
{
    switch (status) {
    case K2TLSStatus::OK:           return "OK";
    case K2TLSStatus::TIME_LIMIT:   return "TIME_LIMIT";
    case K2TLSStatus::TOKEN_LIMIT:  return "TOKEN_LIMIT";
    case K2TLSStatus::CANCELLED:    return "CANCELLED";
    case K2TLSStatus::MEMORY_LIMIT: return "MEMORY_LIMIT";
    case K2TLSStatus::ERROR:        return "ERROR";
    default:                        return "UNKNOWN";
    }
}

K2TimeLimit::K2TimeLimit(const K2TLSConfig& config)
    : config_(config)
{
    reset();
}

void K2TimeLimit::reset()
{
    start_ = Clock::now();
    cancelled_ = false;
}

bool K2TimeLimit::expired() const
{
    if (config_.maxMilliseconds == 0)
        return false;

    return elapsedMilliseconds() >= config_.maxMilliseconds;
}

bool K2TimeLimit::tokenLimitReached(uint32_t generatedTokens) const
{
    if (config_.maxNewTokens == 0)
        return false;

    return generatedTokens >= config_.maxNewTokens;
}

bool K2TimeLimit::memoryLimitReached(uint64_t residentBytes) const
{
    if (config_.maxResidentBytes == 0)
        return false;

    return residentBytes > config_.maxResidentBytes;
}

K2TLSStatus K2TimeLimit::check(uint32_t generatedTokens,
                                uint64_t residentBytes) const
{
    // Cancellation has highest priority.
    if (cancelled_)
        return K2TLSStatus::CANCELLED;

    if (memoryLimitReached(residentBytes))
        return K2TLSStatus::MEMORY_LIMIT;

    if (tokenLimitReached(generatedTokens))
        return K2TLSStatus::TOKEN_LIMIT;

    if (expired())
        return K2TLSStatus::TIME_LIMIT;

    return K2TLSStatus::OK;
}

void K2TimeLimit::cancel()
{
    cancelled_ = true;
}

bool K2TimeLimit::cancelled() const
{
    return cancelled_;
}

uint64_t K2TimeLimit::elapsedMilliseconds() const
{
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - start_);

    return static_cast<uint64_t>(std::max(0LL, elapsed.count()));
}

uint64_t K2TimeLimit::remainingMilliseconds() const
{
    if (config_.maxMilliseconds == 0)
        return UINT64_MAX;

    const uint64_t elapsed = elapsedMilliseconds();

    if (elapsed >= config_.maxMilliseconds)
        return 0;

    return config_.maxMilliseconds - elapsed;
}

K2TLSRequestScope::K2TLSRequestScope(CleanupFn cleanup)
    : cleanup_(std::move(cleanup))
{
}

K2TLSRequestScope::~K2TLSRequestScope()
{
    cleanupNow();
}

void K2TLSRequestScope::cleanupNow()
{
    if (cleaned_)
        return;

    cleaned_ = true;

    if (cleanup_)
        cleanup_();
}

bool K2TLSRequestScope::cleaned() const
{
    return cleaned_;
}

} // namespace rawrxd::deep2
