#pragma once
// UcfGenerationTicket.hpp — generation as authority receipt (scratch ticket).
//
// GENERATION ≠ version counter first.
// GENERATION = proof that a specific semantic truth was observed, leased,
//              executed, and optionally published.
//
// Authority chain (never reverse):
//   Semantic Header → Reverse Manifest → Generation Ticket → Execution Artifact
//
// Backend may realize tickets; backend never defines truth.
#include "rawr_uncoherent_object_fabric.hpp"
#include <atomic>
#include <cstdint>
#include <cstring>

namespace rawr::fabric {

enum class TicketStatus : std::uint32_t {
    Issued = 0,
    Acquired = 1,
    Executed = 2,
    Published = 3,
    Released = 4,
    Failed = 5
};

enum TicketFlag : std::uint32_t {
    TicketFlagNone = 0,
    TicketFlagRead = 1u << 0,
    TicketFlagWrite = 1u << 1,
    TicketFlagConverged = 1u << 2,
    TicketFlagStrict = 1u << 3
};

enum class DriftKind : std::uint32_t {
    None = 0,
    IdentityDrift = 1,
    GenerationDrift = 2,
    SemanticDrift = 3,
    PublicationDrift = 4,
    BackendDrift = 5,
    TopologyDrift = 6,
    FallbackDrift = 7,
    AuthorityDrift = 8
};

// Fingerprint of the semantic law the ticket was issued under.
struct SemanticManifestV1 {
    std::uint32_t abiVersion = 1;

    std::uint64_t identityLawHash = 0;
    std::uint64_t generationLawHash = 0;
    std::uint64_t acquireLawHash = 0;
    std::uint64_t publicationLawHash = 0;
    std::uint64_t topologyLawHash = 0;
    std::uint64_t fallbackLawHash = 0;

    std::uint64_t manifestHash = 0;
};

// Progressive scratch ticket — fields resolve as the transaction advances.
struct GenerationTicketV1 {
    std::uint64_t ticketId = 0;

    ObjectId tensorId = 0;
    DeviceId deviceId = 0;
    std::uintptr_t replicaAddress = 0; // opaque; not identity

    Generation requested = 0;
    Generation acquired = 0;   // UNKNOWN=0 until acquire
    Generation candidate = 0;  // write reserve; 0 for reads
    Generation published = 0;  // 0 until successful publish

    std::uint64_t semanticManifestHash = 0;
    std::uint64_t backendManifestHash = 0;

    std::uint64_t leaseToken = 0;
    std::uint64_t acquireFence = 0;
    std::uint64_t publishFence = 0;

    std::uint32_t flags = TicketFlagNone;
    TicketStatus status = TicketStatus::Issued;
};

struct DriftReport {
    DriftKind kind = DriftKind::None;
    GenerationTicketV1 ticket{};
    std::uint64_t expectedHash = 0;
    std::uint64_t observedHash = 0;
};

namespace detail {
inline std::uint64_t Mix64(std::uint64_t h, std::uint64_t v) noexcept {
    h ^= v + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
    return h;
}

inline std::atomic<std::uint64_t>& TicketSeq() {
    static std::atomic<std::uint64_t> s{1};
    return s;
}
} // namespace detail

// Fixed Semantic ABI v1 fingerprint — bump fields only with intentional ABI break.
inline SemanticManifestV1 MakeSemanticManifestV1() noexcept {
    SemanticManifestV1 m{};
    m.abiVersion = 1;
    // Stable string-derived mixes (not crypto; certification witness only).
    m.identityLawHash = detail::Mix64(0x4944ull, 0x54454e534f52ull);      // ID/TENSOR
    m.generationLawHash = detail::Mix64(0x47454eull, 0x52454345495054ull); // GEN/RECEIPT
    m.acquireLawHash = detail::Mix64(0x414351ull, 0x52456144475257ull);    // ACQ/READ+RW
    m.publicationLawHash = detail::Mix64(0x505542ull, 0x46454e4345ull);    // PUB/FENCE
    m.topologyLawHash = detail::Mix64(0x544f50ull, 0x444556494345ull);     // TOP/DEVICE
    m.fallbackLawHash = detail::Mix64(0x46424bull, 0x484f535452454cull);   // FBK/HOSTREL
    m.manifestHash = 0;
    m.manifestHash = detail::Mix64(m.manifestHash, m.abiVersion);
    m.manifestHash = detail::Mix64(m.manifestHash, m.identityLawHash);
    m.manifestHash = detail::Mix64(m.manifestHash, m.generationLawHash);
    m.manifestHash = detail::Mix64(m.manifestHash, m.acquireLawHash);
    m.manifestHash = detail::Mix64(m.manifestHash, m.publicationLawHash);
    m.manifestHash = detail::Mix64(m.manifestHash, m.topologyLawHash);
    m.manifestHash = detail::Mix64(m.manifestHash, m.fallbackLawHash);
    return m;
}

inline const SemanticManifestV1& ActiveSemanticManifest() noexcept {
    static const SemanticManifestV1 kM = MakeSemanticManifestV1();
    return kM;
}

inline GenerationTicketV1 IssueTicket(
    ObjectId tensorId,
    Generation requested,
    std::uint32_t flags) noexcept
{
    GenerationTicketV1 t{};
    t.ticketId = detail::TicketSeq().fetch_add(1, std::memory_order_relaxed);
    t.tensorId = tensorId;
    t.requested = requested;
    t.acquired = 0;
    t.candidate = 0;
    t.published = 0;
    t.semanticManifestHash = ActiveSemanticManifest().manifestHash;
    t.flags = flags;
    t.status = TicketStatus::Issued;
    return t;
}

// Scratch acquire from fabric lease receipt (does not redefine acquire law).
inline void ScratchAcquire(
    GenerationTicketV1& ticket,
    const FabricLease& lease) noexcept
{
    const AcquireReceipt r = lease.receipt();
    ticket.tensorId = r.tensorId;
    ticket.deviceId = lease.device();
    ticket.replicaAddress = r.physical.opaqueAddress;
    ticket.requested = r.requestedGeneration;
    ticket.acquired = r.acquiredGeneration;
    ticket.leaseToken = r.readerReceipt;
    ticket.acquireFence = 1;
    if (ticket.requested != ticket.acquired)
        ticket.flags |= TicketFlagConverged;
    if (lease.access() == Access::ReadWrite || lease.access() == Access::Write) {
        ticket.flags |= TicketFlagWrite;
        // Writer ticket: acquired = authoritative current; candidate = reserved next.
        ticket.acquired = lease.publishBase() ? lease.publishBase()
                                              : r.acquiredGeneration;
        ticket.candidate = r.acquiredGeneration; // reserved G+1 in lease
        if (!lease.publishBase())
            ticket.candidate = r.acquiredGeneration + 1;
    } else {
        ticket.flags |= TicketFlagRead;
        ticket.candidate = 0;
    }
    ticket.status = TicketStatus::Acquired;
}

inline void ScratchExecute(GenerationTicketV1& ticket, std::uint64_t fence) noexcept {
    ticket.acquireFence = fence ? fence : ticket.acquireFence;
    ticket.status = TicketStatus::Executed;
}

inline void ScratchPublish(
    GenerationTicketV1& ticket,
    Generation published,
    std::uint64_t publishFence) noexcept
{
    ticket.published = published;
    ticket.publishFence = publishFence;
    ticket.status = TicketStatus::Published;
}

inline void ScratchRelease(GenerationTicketV1& ticket) noexcept {
    if (ticket.status != TicketStatus::Published)
        ticket.published = 0;
    ticket.status = TicketStatus::Released;
}

inline void ScratchFail(GenerationTicketV1& ticket) noexcept {
    ticket.published = 0;
    ticket.status = TicketStatus::Failed;
}

inline DriftKind CheckTicketDrift(
    const GenerationTicketV1& ticket,
    const FabricLease* leaseOrNull,
    std::uint64_t runtimeManifestHash) noexcept
{
    if (ticket.semanticManifestHash != runtimeManifestHash &&
        ticket.semanticManifestHash != ActiveSemanticManifest().manifestHash)
        return DriftKind::SemanticDrift;

    if (ticket.semanticManifestHash != ActiveSemanticManifest().manifestHash)
        return DriftKind::SemanticDrift;

    if (leaseOrNull) {
        const auto r = leaseOrNull->receipt();
        if (r.tensorId != ticket.tensorId)
            return DriftKind::IdentityDrift;
        if (ticket.status == TicketStatus::Acquired ||
            ticket.status == TicketStatus::Executed) {
            if (ticket.flags & TicketFlagRead) {
                if (r.acquiredGeneration != ticket.acquired)
                    return DriftKind::GenerationDrift;
                if (leaseOrNull->view().generation != ticket.acquired)
                    return DriftKind::GenerationDrift;
            } else if (ticket.flags & TicketFlagWrite) {
                // Write lease: receipt.acquired = candidate; publishBase = current.
                if (leaseOrNull->publishBase() != ticket.acquired)
                    return DriftKind::GenerationDrift;
                if (r.acquiredGeneration != ticket.candidate)
                    return DriftKind::GenerationDrift;
            }
        }
    }

    if (ticket.status == TicketStatus::Published) {
        if (!(ticket.flags & TicketFlagWrite))
            return DriftKind::PublicationDrift;
        // Publication evidence: published == publishBase+1 == candidate.
        if (ticket.candidate && ticket.published != ticket.candidate)
            return DriftKind::PublicationDrift;
        if (ticket.published == 0)
            return DriftKind::PublicationDrift;
    }

    if (ticket.backendManifestHash &&
        ticket.backendManifestHash != ticket.semanticManifestHash)
        return DriftKind::BackendDrift;

    return DriftKind::None;
}

inline bool TruthEquals(
    const GenerationTicketV1& ticket,
    const SemanticManifestV1& manifest) noexcept
{
    return ticket.semanticManifestHash == manifest.manifestHash &&
           CheckTicketDrift(ticket, nullptr, manifest.manifestHash) ==
               DriftKind::None;
}

} // namespace rawr::fabric
