#pragma once
#ifndef RAWRXD_PLAN_HASH_H
#define RAWRXD_PLAN_HASH_H

#include "execution_plan.h"
#include <string>
#include <array>

namespace RawrXD {

// ============================================================================
// PLAN HASHING - Deterministic execution binding
// 
// ExecutionPlanHash + CapabilityToken -> ExecutionPermit
// Prevents plan mutation after authorization and replay attacks.
// ============================================================================

using PlanHash = std::array<uint8_t, 32>;
using ExecutionPermit = std::array<uint8_t, 64>;

// ============================================================================
// PlanHasher - Cryptographic binding of plan to execution
// ============================================================================
class PlanHasher {
public:
    // Hash a plan deterministically
    static PlanHash hash(const ExecutionPlan& plan);
    
    // Bind plan hash + capability + context -> execution permit
    static ExecutionPermit bind(const PlanHash& planHash,
                                  const ExecutionCapability& cap,
                                  const std::string& context);
    
    // Verify permit is valid for plan + capability
    static bool verify(const ExecutionPermit& permit,
                      const PlanHash& planHash,
                      const ExecutionCapability& cap,
                      const std::string& context);
    
    // String representations
    static std::string toHex(const PlanHash& hash);
    static std::string toHex(const ExecutionPermit& permit);
    static PlanHash fromHex(const std::string& hex);

private:
    // HMAC-SHA256 for binding
    static void hmacSha256(const uint8_t* key, size_t keyLen,
                          const uint8_t* data, size_t dataLen,
                          uint8_t* out);
};

// ============================================================================
// Execution Permit - One-time authorization token
// ============================================================================
class ExecutionPermitToken {
public:
    ExecutionPermitToken() = default;
    ExecutionPermitToken(const PlanHash& planHash,
                         const ExecutionCapability& cap,
                         const std::string& context);
    
    // Non-copyable (one-time use)
    ExecutionPermitToken(const ExecutionPermitToken&) = delete;
    ExecutionPermitToken& operator=(const ExecutionPermitToken&) = delete;
    
    // Movable
    ExecutionPermitToken(ExecutionPermitToken&&) noexcept;
    ExecutionPermitToken& operator=(ExecutionPermitToken&&) noexcept;
    
    bool isValid() const { return m_valid && !m_consumed; }
    void consume() { m_consumed = true; }
    
    const PlanHash& planHash() const { return m_planHash; }
    const ExecutionPermit& permit() const { return m_permit; }

private:
    PlanHash m_planHash;
    ExecutionPermit m_permit;
    bool m_valid = false;
    bool m_consumed = false;
};

} // namespace RawrXD

#endif // RAWRXD_PLAN_HASH_H
