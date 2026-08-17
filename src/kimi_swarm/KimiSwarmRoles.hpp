// =============================================================================
// KimiSwarmRoles.hpp — Kimi K2.6-Style 300-Agent Swarm Role Definitions
// =============================================================================
// Implements the specialized agent role taxonomy from the Kimi K2.6 architecture:
//   - The Architect (1):       Schema, stack selection, project tree
//   - The Frontend Squad (120): UI/UX components, forms, responsive, animations
//   - The Backend Core (100):   Server logic, APIs, payments, auth
//   - The QA Hive (50):         Unit tests, load testing, real-time validation
//   - The Reviewers (29):       Security, Clean Code, dependency conflicts
//
// Total: 300 specialized autonomous coding agents.
//
// This layer sits on top of the existing SovereignSwarm infrastructure and
// maps Kimi roles to Sovereign ModelRole selections for zero-copy inference.
//
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// =============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <unordered_map>
#include <atomic>
#include <mutex>
#include <memory>

namespace KimiSwarm {

// =============================================================================
// KIMI AGENT ROLE TAXONOMY
// =============================================================================

enum class KimiRole : uint16_t {
    // The Architect (1 agent)
    Architect = 0,

    // The Frontend Squad (120 agents) — indices 1..120
    Frontend_ComponentBuilder,      // React/Vue/Svelte component creation
    Frontend_FormLogic,             // Form validation, state management
    Frontend_ResponsiveStyles,      // CSS Grid, Flexbox, media queries
    Frontend_AnimationEngineer,     // Framer Motion, CSS animations, transitions
    Frontend_DesignSystem,          // Token systems, theme palettes
    Frontend_Accessibility,         // ARIA, keyboard nav, screen readers
    Frontend_RoutingSpecialist,     // Client-side routing, code splitting
    Frontend_StateArchitect,        // Redux/Zustand/Jotai store design
    Frontend_APIClient,             // GraphQL/REST client generation
    Frontend_TestRunner,            // Jest/Vitest component tests

    // The Backend Core (100 agents) — indices 121..220
    Backend_APIEndpoint,            // REST/GraphQL endpoint creation
    Backend_DatabaseLayer,          // ORM, migrations, query optimization
    Backend_AuthService,            // JWT, OAuth2, session management
    Backend_PaymentIntegration,     // Stripe, PayPal, crypto gateways
    Backend_MiddlewareEngineer,     // Express/Fastify middleware chains
    Backend_WebSocketServer,        // Real-time bidirectional communication
    Backend_MessageQueue,           // RabbitMQ, Kafka, Redis Streams
    Backend_CachingLayer,           // Redis, Memcached, CDN strategies
    Backend_FileStorage,            // S3, GCS, local FS abstractions
    Backend_EmailService,           // SMTP, templating, delivery tracking

    // The QA Hive (50 agents) — indices 221..270
    QA_UnitTestWriter,              // Jest, PyTest, Go test generation
    QA_IntegrationTester,           // API-to-DB integration tests
    QA_LoadTester,                  // k6, Artillery, Locust scenarios
    QA_SecurityScanner,             // OWASP, dependency CVE checks
    QA_E2ETester,                   // Playwright, Cypress, Selenium
    QA_PerformanceProfiler,         // Flame graphs, bottleneck analysis
    QA_MutationTester,              // Mutation testing for coverage gaps
    QA_ContractTester,              // Pact, OpenAPI contract validation

    // The Reviewers (29 agents) — indices 271..299
    Reviewer_SecurityAudit,         // Security pattern compliance
    Reviewer_CleanCode,             // SOLID, DRY, KISS enforcement
    Reviewer_DependencyConflict,    // Version conflict resolution
    Reviewer_ArchitectureReview,    // Pattern adherence, coupling analysis
    Reviewer_PerformanceReview,     // Algorithmic complexity, N+1 queries
    Reviewer_DocumentationReview,   // README, API docs, inline comments
    Reviewer_TypeSafety,            // TypeScript strict, runtime guards
    Reviewer_TestCoverage,          // Coverage threshold enforcement

    // Micro-Swarm fallback (50-70 agents for <16GB RAM)
    MicroSwarm_Generalist,          // Fallback generalist for reduced mode

    Unknown = 0xFFFF
};

// Role counts matching Kimi K2.6 specification
struct KimiRoleCounts {
    static constexpr uint32_t Architect    = 1;
    static constexpr uint32_t FrontendSquad = 120;
    static constexpr uint32_t BackendCore  = 100;
    static constexpr uint32_t QAHive       = 50;
    static constexpr uint32_t Reviewers    = 29;
    static constexpr uint32_t TotalFull    = 300;
    static constexpr uint32_t MicroSwarmMin = 50;
    static constexpr uint32_t MicroSwarmMax = 70;
};

// =============================================================================
// AGENT CAPABILITY PROFILE
// =============================================================================

struct AgentCapability {
    KimiRole    role;
    std::string roleName;
    std::string squad;          // "Architect", "Frontend", "Backend", "QA", "Reviewers"
    std::string specialization; // Detailed specialization description
    std::string preferredModel;  // Model best suited for this role
    std::string language;        // Primary language (TS, Python, Go, etc.)
    std::string framework;       // Primary framework (React, Express, etc.)
    uint32_t    maxConcurrency;  // Max parallel tasks this role can handle
    bool        canDelegate;     // Can this agent delegate to sub-agents?
    bool        canReview;       // Can this agent review others' work?
    bool        canExecute;      // Can this agent run code/commands?
};

// =============================================================================
// SQUAD ENUMERATION
// =============================================================================

enum class Squad : uint8_t {
    Architect  = 0,
    Frontend   = 1,
    Backend    = 2,
    QA         = 3,
    Reviewers  = 4,
    MicroSwarm = 5,
    Count
};

inline const char* SquadName(Squad s) {
    switch (s) {
        case Squad::Architect:  return "The Architect";
        case Squad::Frontend:   return "The Frontend Squad";
        case Squad::Backend:    return "The Backend Core";
        case Squad::QA:         return "The QA Hive";
        case Squad::Reviewers:  return "The Reviewers";
        case Squad::MicroSwarm: return "Micro-Swarm";
        default: return "Unknown";
    }
}

inline uint32_t SquadSize(Squad s, bool microSwarm = false) {
    if (microSwarm) return KimiRoleCounts::MicroSwarmMax;
    switch (s) {
        case Squad::Architect:  return KimiRoleCounts::Architect;
        case Squad::Frontend:   return KimiRoleCounts::FrontendSquad;
        case Squad::Backend:    return KimiRoleCounts::BackendCore;
        case Squad::QA:         return KimiRoleCounts::QAHive;
        case Squad::Reviewers:  return KimiRoleCounts::Reviewers;
        case Squad::MicroSwarm: return KimiRoleCounts::MicroSwarmMax;
        default: return 0;
    }
}

// =============================================================================
// ROLE REGISTRY — Maps roles to capability profiles
// =============================================================================

class KimiRoleRegistry {
public:
    static KimiRoleRegistry& instance();

    // Get capability profile for a role
    const AgentCapability& getCapability(KimiRole role) const;

    // Get all roles in a squad
    std::vector<KimiRole> getRolesBySquad(Squad squad) const;

    // Get the preferred model for a role
    std::string getPreferredModel(KimiRole role) const;

    // Get squad for a role
    Squad getSquadForRole(KimiRole role) const;

    // Check if system should use Micro-Swarm mode
    static bool shouldUseMicroSwarm(uint64_t availableRAM_GB);

    // Get agent count based on available memory
    static uint32_t getOptimalAgentCount(uint64_t availableRAM_GB);

    // Get all capabilities for a squad
    std::vector<AgentCapability> getSquadCapabilities(Squad squad) const;

    // Total registered roles
    size_t roleCount() const { return registry_.size(); }

private:
    KimiRoleRegistry();

    std::unordered_map<KimiRole, AgentCapability> registry_;
    std::unordered_map<Squad, std::vector<KimiRole>> squadMap_;

    void registerArchitect();
    void registerFrontendSquad();
    void registerBackendCore();
    void registerQAHive();
    void registerReviewers();
    void registerMicroSwarm();
};

// =============================================================================
// AGENT IDENTITY — Lightweight per-agent context
// =============================================================================

struct KimiAgentIdentity {
    uint32_t    agentId;        // 0..299 (or 0..69 for Micro-Swarm)
    KimiRole    role;
    Squad       squad;
    std::string name;           // Human-readable name e.g. "Frontend-042"
    std::string sessionTag;     // Unique session identifier

    KimiAgentIdentity()
        : agentId(0), role(KimiRole::Unknown), squad(Squad::Architect) {}

    KimiAgentIdentity(uint32_t id, KimiRole r, Squad s, const std::string& n)
        : agentId(id), role(r), squad(s), name(n) {
        sessionTag = "kimi-" + std::to_string(id) + "-" + n;
    }
};

// =============================================================================
// TASK DECOMPOSITION — Architect output structure
// =============================================================================

struct ProjectArtifact {
    std::string path;           // File path in project tree
    std::string content;        // Generated content
    std::string language;       // Language identifier
    Squad       assignedSquad;  // Which squad produces this
    KimiRole    assignedRole;   // Specific role
    uint32_t    priority;       // 0 = highest
    bool        requiresReview; // Must pass through Reviewers
    bool        requiresTests;  // Must pass through QA Hive
};

struct ProjectPlan {
    std::string projectName;
    std::string techStack;          // "React + Express + PostgreSQL"
    std::string databaseSchema;     // SQL DDL or schema definition
    std::string projectTree;        // Directory structure
    std::vector<ProjectArtifact> artifacts;
    std::vector<std::string> dependencies;  // npm/pip/go modules
    std::vector<std::string> environmentVars;
    uint64_t estimatedGenerationMs;
    uint32_t totalAgentCount;
    bool     microSwarmMode;
};

// =============================================================================
// SWARM MESSAGE — Inter-agent communication
// =============================================================================

enum class MessageType : uint8_t {
    TaskAssignment,    // Coordinator → Agent
    TaskComplete,      // Agent → Coordinator
    TaskFailed,        // Agent → Coordinator
    DelegateRequest,   // Agent → Agent (via coordinator)
    ReviewRequest,     // Agent → Reviewer
    ReviewResult,      // Reviewer → Agent
    TestRequest,       // Agent → QA
    TestResult,        // QA → Agent
    ConflictAlert,     // Agent → Coordinator (merge conflict)
    StatusUpdate,      // Agent → Coordinator
    Broadcast,         // Coordinator → All
    Vote,              // Agent → Coordinator (consensus)
    VoteResult         // Coordinator → All (tally)
};

struct SwarmMessage {
    uint64_t      id;
    MessageType   type;
    uint32_t      fromAgent;
    uint32_t      toAgent;       // 0xFFFFFFFF = broadcast
    std::string   payload;       // JSON or structured payload
    std::string   artifactPath;  // Associated file if any
    int64_t       timestamp;     // Unix ms
    uint32_t      priority;      // 0 = highest

    SwarmMessage()
        : id(0), type(MessageType::TaskAssignment), fromAgent(0)
        , toAgent(0), timestamp(0), priority(10) {}
};

// =============================================================================
// CONFLICT RESOLUTION — When agents produce overlapping changes
// =============================================================================

struct FileConflict {
    std::string filePath;
    uint32_t    agentA;
    uint32_t    agentB;
    std::string versionA;
    std::string versionB;
    std::string resolution;      // Final merged content
    uint32_t    resolvedBy;      // Reviewer agent ID
};

// =============================================================================
// SWARM STATISTICS
// =============================================================================

struct SwarmStats {
    std::atomic<uint32_t> activeAgents{0};
    std::atomic<uint32_t> idleAgents{0};
    std::atomic<uint32_t> completedTasks{0};
    std::atomic<uint32_t> failedTasks{0};
    std::atomic<uint32_t> pendingReviews{0};
    std::atomic<uint32_t> pendingTests{0};
    std::atomic<uint32_t> conflictsResolved{0};
    std::atomic<uint64_t> totalTokensGenerated{0};
    std::atomic<uint64_t> totalInferenceTimeMs{0};
    std::atomic<uint32_t> currentSquadLoad{0};  // Active across all squads

    void reset() {
        activeAgents = 0;
        idleAgents = 0;
        completedTasks = 0;
        failedTasks = 0;
        pendingReviews = 0;
        pendingTests = 0;
        conflictsResolved = 0;
        totalTokensGenerated = 0;
        totalInferenceTimeMs = 0;
        currentSquadLoad = 0;
    }
};

} // namespace KimiSwarm