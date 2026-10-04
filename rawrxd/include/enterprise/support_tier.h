// ============================================================================
// enterprise/support_tier.h -- Enterprise Support Tier System
// ============================================================================
// Declares SupportTierManager singleton and supporting types. Full definitions
// live in src/core/support_tier.cpp (single compilation unit).
//
// PATTERN:   No exceptions. No std::function. Raw function pointers only.
// THREADING: Singleton with std::mutex. Thread-safe.
// RULE:      NO SOURCE FILE IS TO BE SIMPLIFIED
//
// ----------------------------------------------------------------------------
// WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
// ----------------------------------------------------------------------------
// src/core/support_tier.cpp was written and has been sitting in the tree for the
// whole life of the project, fully implemented -- 340 lines, every method
// defined -- against a header that was never written. The build graph census
// (RAWRXD_BUILD_GRAPH_CENSUS_001) does not catch this class of absence, because
// it scans CMakeLists.txt for declared SOURCES and this defect is an #include,
// not a source-list entry. The compiler caught it instead, on the RawrXD_Gold
// target:
//
//     src\core\support_tier.cpp(12,10): error C1083: Cannot open include file:
//         'enterprise/support_tier.h': No such file or directory
//
// The header was reconstructed from the implementation, not from a specification.
// Every declaration below is justified by a use site in support_tier.cpp, and the
// justifying use site is named in the comment beside it. That constraint is
// what makes this a reconstruction rather than a guess: if a declaration here
// disagrees with the .cpp, the .cpp fails to compile. Nothing here is invented
// API -- the only two items with no use site are called out as such.
//
// LOCATION. include/enterprise/ is the established home: include/enterprise/
// multi_gpu.h already sits there and is included as "enterprise/multi_gpu.h"
// from src/core/*.cpp by the same pattern, and ${CMAKE_CURRENT_SOURCE_DIR}/
// include is already on this target's include path. src/core/enterprise/
// does not exist and was not created, because the .cpp's own sibling include
// (enterprise_license.h) lives at include/ while a second copy lives in
// src/core/, and guessing a third arrangement is how this absence happened.
//
// TYPE CHOICES THAT WERE FORCED, NOT CHOSEN:
//   SupportLevel    -- ordered Community=0..OEM=3. support_tier.cpp:74 does
//                       `uint32_t idx = static_cast<uint32_t>(level); if (idx >
//                       3) idx = 2;` and then indexes s_slaConfigs with it, so
//                       the numeric values are part of the contract.
//   TicketPriority  -- 5 ordered values. support_tier.cpp:307 indexes
//                       priorityNames[] with the raw value and clamps at >4.
//   TicketStatus    -- 5 ordered values, Open/InProgress/Escalated ordered
//                       FIRST. support_tier.cpp:278 computes the open-ticket
//                       count as `t.status <= TicketStatus::Escalated`, so
//                       Resolved and Closed must sort above Escalated.
//   SLAConfig       -- 7 aggregate members in exactly the order the four
//                       s_slaConfigs initialisers use, because those are
//                       aggregate initialisation and cannot be reordered.
// ============================================================================

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace RawrXD::Enterprise {

// ============================================================================
// Support Tiers
// ============================================================================
// Numeric values are load-bearing -- see the header note. Community is index 0
// because support_tier.cpp falls back to s_slaConfigs[0] when no Enterprise
// licence is present, and to index 2 (Enterprise) for an out-of-range request.
enum class SupportLevel : uint32_t {
    Community  = 0,
    Pro        = 1,
    Enterprise = 2,
    OEM        = 3
};

// ============================================================================
// Ticket Priority
// ============================================================================
// support_tier.cpp:133 gates on `priority >= TicketPriority::High`, so High and
// above are exactly what a Community licence must refuse.
enum class TicketPriority : uint32_t {
    Low      = 0,
    Normal   = 1,
    High     = 2,
    Critical = 3,
    Blocker  = 4
};

// ============================================================================
// Ticket Status
// ============================================================================
// Ordering is load-bearing: support_tier.cpp:278 counts a ticket as open when
// `status <= TicketStatus::Escalated`.
enum class TicketStatus : uint32_t {
    Open       = 0,
    InProgress = 1,
    Escalated  = 2,
    Resolved   = 3,
    Closed     = 4
};

// ============================================================================
// Service Level Agreement
// ============================================================================
// Member order is fixed by the aggregate initialisers in support_tier.cpp:34-50.
// No member is const, because support_tier.cpp:46 copies one element out of the
// table into the manager's own m_slaConfig.
struct SLAConfig {
    SupportLevel level;                 // tier this SLA describes
    uint32_t     responseTimeMinutes;   // 0 == best-effort, no deadline
    uint32_t     resolutionTimeHours;
    bool         phoneSupport;
    bool         dedicatedEngineer;
    bool         priorityRouting;       // see note below
    const char*  description;           // streamed verbatim into the status report
    // priorityRouting has NO read site in support_tier.cpp today. It is the
    // third boolean in the initialiser list and is set only for Enterprise and
    // OEM. It is declared because dropping it would shift description out of
    // position 6 and break every initialiser; it is named for the observed
    // pattern (the two tiers that get "priority" in their description string)
    // and NOT claimed to do anything. Wiring it to the escalation path is
    // outstanding work, not a defect in this header.
};

// ============================================================================
// Support Operation Result
// ============================================================================
// Mirrors MultiGPUResult in include/enterprise/multi_gpu.h:74 so the two
// Enterprise subsystems report failure the same way. Codes used by
// support_tier.cpp: 1 not-initialised, 2 licence-gated, 3 ticket-not-found
// (and illegal-state), 4 ticket-not-found (resolve/close).
struct SupportResult {
    bool        success;
    int         code;
    std::string message;

    static SupportResult ok(const char* msg);
    static SupportResult error(const char* msg, int code);
};

// ============================================================================
// Support Ticket
// ============================================================================
// Aggregate-initialised as `SupportTicket ticket{}` and then field-assigned, so
// every member must be default-constructible and the type must stay an
// aggregate. subject and description stay const char* because they are copied
// straight out of the CreateTicket arguments and never owned by the ticket.
struct SupportTicket {
    uint64_t       id;
    TicketPriority priority;
    TicketStatus   status;
    SupportLevel   tier;
    const char*    subject;
    const char*    description;
    uint64_t       createdAtMs;
    uint64_t       updatedAtMs;
    uint64_t       slaDeadlineMs;   // UINT64_MAX when the tier has no SLA
    bool           slaBreached;
};

// ============================================================================
// Support Tier Manager Singleton
// ============================================================================
// Every query takes m_mutex, so m_mutex is mutable. Callbacks are raw function
// pointers, matching the file's stated "no std::function" rule and the pattern
// already used by MultiGPUManager (include/enterprise/multi_gpu.h:176).
class SupportTierManager {
public:
    static SupportTierManager& Instance();

    // Lifecycle
    SupportResult Initialize(SupportLevel level);
    void          Shutdown();

    // Tier queries
    SupportLevel        GetCurrentLevel() const;
    const SLAConfig&    GetSLAConfig() const;

    // NOT static. support_tier.cpp:111 defines it as an ordinary const member
    // (`const char* SupportTierManager::GetLevelName(SupportLevel level) const`)
    // and the .cpp is the authority here; declaring it static produced
    //     support_tier.cpp(111,33): error C2511: overloaded member function not
    //                                 found in 'SupportTierManager'
    // The body reads a file-scope table rather than instance state, so static
    // would be the tidier signature, but changing the definition to match a
    // declaration I had authored is the wrong direction of travel.
    const char* GetLevelName(SupportLevel level) const;

    // Ticket management
    SupportResult CreateTicket(TicketPriority priority,
                               const char*    subject,
                               const char*    description);
    SupportResult EscalateTicket(uint64_t ticketId);
    SupportResult ResolveTicket(uint64_t ticketId);
    SupportResult CloseTicket(uint64_t ticketId);

    // SLA monitoring
    void     CheckSLABreaches();
    uint32_t GetOpenTicketCount() const;
    uint32_t GetBreachedTicketCount() const;

    // Status reports
    std::string GenerateStatusReport() const;
    std::string GenerateTicketList() const;

    // Callback registration. These are the only way the three callback members
    // can ever be non-null: support_tier.cpp invokes them but never assigns
    // them, so without an entry point the notification path is unreachable
    // code that can never fire.
    using TicketCallback = void (*)(const SupportTicket&);
    void SetCreatedCallback(TicketCallback cb);
    void SetEscalatedCallback(TicketCallback cb);
    void SetBreachCallback(TicketCallback cb);

private:
    SupportTierManager();
    ~SupportTierManager();
    SupportTierManager(const SupportTierManager&)            = delete;
    SupportTierManager& operator=(const SupportTierManager&) = delete;

    uint64_t nextTicketId();
    uint64_t nowMs() const;

    mutable std::mutex  m_mutex;
    bool                m_initialized;
    SupportLevel        m_level;
    SLAConfig           m_slaConfig;
    std::vector<SupportTicket> m_tickets;
    uint64_t            m_nextId;

    TicketCallback      m_onCreated;
    TicketCallback      m_onEscalated;
    TicketCallback      m_onBreach;
};

} // namespace RawrXD::Enterprise