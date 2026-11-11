// ============================================================================
// W0UniversalIR.hpp — Canonical knowledge substrate (packs, not topic folders)
// ============================================================================
// ANY SOURCE → INGEST → PARSE → NORMALIZE → GRAPH → MULTI-INDEX →
// RETRIEVE → REASON → VERIFY → ANSWER/ACT
//
// HexMag sits above as orchestration + FINAL / NEED_INPUT authority.
// TENSOR_WEIGHTS=0  FLOAT_OPS=0  NO_STOCHASTIC_INFERENCE=1
// ============================================================================
#ifndef RAWRXD_DEEP2W0_W0_UNIVERSAL_IR_HPP
#define RAWRXD_DEEP2W0_W0_UNIVERSAL_IR_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace RawrXD {
namespace W0 {

enum class NodeKind : uint16_t {
    Concept = 1,
    Entity,
    Fact,
    Rule,
    Procedure,
    Definition,
    Document,
    Section,
    Symbol,
    Function,
    Class,
    Variable,
    Type,
    Module,
    File,
    Command,
    Tool,
    API,
    Parameter,
    Error,
    Cause,
    Repair,
    Equation,
    Quantity,
    Unit,
    Event,
    Requirement,
    Constraint,
    Test,
    Evidence,
    Example,
    Case,
    Observation,
    Intent,
    Patch,
    Unknown = 0xFFFF,
};

enum class Relation : uint16_t {
    IsA = 1,
    InstanceOf,
    PartOf,
    Contains,
    DefinedIn,
    DeclaredBy,
    Uses,
    Requires,
    DependsOn,
    Produces,
    Consumes,
    Calls,
    Causes,
    Prevents,
    Fixes,
    EquivalentTo,
    Before,
    After,
    HasProperty,
    HasValue,
    InputOf,
    OutputOf,
    Validates,
    Contradicts,
    Supports,
    DerivedFrom,
    VerifiedBy,
};

enum class KnowledgeClass : uint8_t {
    Declarative = 1, // what is true
    Procedural,      // how to do
    Causal,          // what produces what
    Diagnostic,      // if X, likely cause
};

enum class VerificationLevel : uint8_t {
    Unknown = 0,
    UserSupplied,
    Documentation,
    SourceCode,
    Tested,
    Derived,
    Certified,
};

enum class TaskKind : uint8_t {
    Explain = 1,
    Find,
    Compare,
    Calculate,
    Diagnose,
    Modify,
    Build,
    Test,
    Generate,
    Verify,
    Plan,
};

enum class EvidenceType : uint8_t {
    Source = 1,
    Rule,
    Compile,
    Test,
    Structural,
    Selection,
    Provenance,
};

struct Provenance {
    std::string sourceId;
    uint64_t revision = 0;
    VerificationLevel level = VerificationLevel::Unknown;
};

struct KnowledgeNode {
    uint64_t id = 0;
    NodeKind kind = NodeKind::Unknown;
    KnowledgeClass kclass = KnowledgeClass::Declarative;
    std::string name;
    std::string content;
    Provenance provenance;
    uint32_t domain = 0;
};

struct KnowledgeEdge {
    uint64_t from = 0;
    uint64_t to = 0;
    Relation relation = Relation::IsA;
    std::string sourceId;
};

struct EvidenceEntry {
    uint64_t claimId = 0;
    std::string sourceId;
    std::string ruleId;
    EvidenceType type = EvidenceType::Source;
    bool verified = false;
    std::string payload;
};

struct QueryIR {
    TaskKind intent = TaskKind::Explain;
    std::vector<std::string> entities;
    std::vector<std::string> constraints;
    std::string requestedOutput;
    std::string raw;
};

struct RepairCase {
    std::string problemFingerprint;
    std::string contextFingerprint;
    std::string transformOp;
    std::string evidence;
    uint32_t successCount = 0;
    uint32_t failureCount = 0;
    bool forbidden = false; // negative knowledge
};

/// Freeze markers for the 10 subsystems (interfaces may grow; contract holds).
inline constexpr const char* kW0SubsystemFreeze =
    "W0_KnowledgeCompiler\n"
    "W0_UniversalIR\n"
    "W0_GraphStore\n"
    "W0_MultiIndexEngine\n"
    "W0_RuleVM\n"
    "W0_ConstraintSolver\n"
    "W0_Planner\n"
    "W0_EvidenceLedger\n"
    "W0_RepairMemory\n"
    "W0_KnowledgePackManager\n"
    "HexMag=orchestration_and_authority\n";

} // namespace W0
} // namespace RawrXD

#endif
