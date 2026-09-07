#pragma once
// UcfHaloSpark.hpp — Halo / sparkUnified (temporary unified execution memory)
//
// Halo ≠ expert neighborhood cache.
// Halo = the act that binds distributed pieces into one generation-bound Spark.
//
// mem+ory inversion:
//   ordinary:     physical memory → defines object
//   sparkUnified: object → defines required physical pieces for this event
//
// sparkUnified does NOT claim hardware coherence. It exposes one semantic
// execution-memory object spanning split VRAM + immutable backing.
//
// Authority chain (never reverse):
//   rawr_uncoherent_object_fabric.hpp → Ticket → Halo → sparkUnified(G)
//     → BounceChain.obj / zipline (mechanics only)
//
// Invariant: ∀ member M ∈ sparkUnified(G): visibleGeneration(M) = G
#include "rawr_uncoherent_object_fabric.hpp"
#include "UcfGenerationTicket.hpp"
#include <stdexcept>
#include <utility>
#include <vector>

namespace rawr::fabric {

struct SparkMember {
    TensorRef tensor{};
    DeviceId device = 0;
    PhysicalView physical{};
    Generation visibleGeneration = 0;
    bool fromImmutableSource = false;
};

struct SparkUnified {
    Generation generation = 0;
    Generation candidate = 0;   // write reserve; 0 for read-only spark
    Generation published = 0;   // 0 until successful publish
    std::vector<SparkMember> members;
    GenerationTicketV1 ticket{};

    // Mutable members must all show spark.generation.
    // Immutable backing is generation-stable (weight source), not activation G.
    bool generationConsistent(Fabric& fabric) const {
        if (!generation || members.empty()) return false;
        for (const auto& m : members) {
            auto obj = fabric.object(m.tensor);
            if (obj->immutable()) {
                if (m.visibleGeneration != obj->generation()) return false;
                if (m.physical.generation != m.visibleGeneration) return false;
            } else {
                if (m.visibleGeneration != generation) return false;
                if (m.physical.generation != generation) return false;
            }
        }
        return true;
    }
};

// Discovers/binds the execution frontier; does not execute.
struct Halo {
    std::vector<DeviceId> devices;
    std::vector<TensorRef> required;
    DeviceId immutableSource = 0;

    void attach(DeviceId d) { devices.push_back(d); }
    void require(TensorRef t) { required.push_back(t); }
    void setImmutableSource(DeviceId host) { immutableSource = host; }
};

// Materialize member onto device at the generation required for this Spark.
// Mutable → exact spark G. Immutable → object generation (stable weight truth).
inline SparkMember ResolveMember(
    Fabric& fabric,
    TensorRef ref,
    DeviceId device,
    Generation sparkGeneration,
    DeviceId immutableSource)
{
    SparkMember m;
    m.tensor = ref;
    m.device = device;

    auto obj = fabric.object(ref);
    const Generation bindGen =
        obj->immutable() ? obj->generation() : sparkGeneration;

    const bool hadDevice =
        [&] {
            auto r = obj->replica(device, false);
            return r &&
                   r->state.load(std::memory_order_acquire) ==
                       ReplicaState::Present &&
                   r->generation.load(std::memory_order_acquire) == bindGen;
        }();

    {
        FabricLease lease =
            fabric.acquireExpected(ref, device, Access::Read, bindGen);
        m.physical = lease.view();
        m.visibleGeneration = m.physical.generation;
    }

    if (m.visibleGeneration != bindGen)
        throw GenerationMismatch(bindGen, m.visibleGeneration);

    m.fromImmutableSource =
        obj->immutable() && immutableSource != 0 && !hadDevice;
    return m;
}

// Halo → temporary unified execution memory at generation G.
inline SparkUnified sparkUnified(
    Fabric& fabric,
    const Halo& halo,
    Generation generation)
{
    if (halo.devices.empty() || halo.required.empty())
        throw std::invalid_argument("sparkUnified: empty halo frontier");

    SparkUnified spark;
    spark.generation = generation;
    spark.ticket = IssueTicket(
        halo.required.front().id, generation, TicketFlagRead);

    const std::size_t nDev = halo.devices.size();
    for (std::size_t i = 0; i < halo.required.size(); ++i) {
        const DeviceId home = halo.devices[i % nDev];
        spark.members.push_back(ResolveMember(
            fabric, halo.required[i], home, generation, halo.immutableSource));
    }

    if (!spark.generationConsistent(fabric))
        throw std::runtime_error("sparkUnified: generation inconsistency");

    spark.ticket.acquired = generation;
    spark.ticket.status = TicketStatus::Acquired;
    return spark;
}

// RW Spark = unit of acquisition/publication (not per-GPU independently).
struct SparkWriteSession {
    SparkUnified spark;
    FabricLease writeLease;
};

inline SparkWriteSession sparkUnifiedWrite(
    Fabric& fabric,
    const Halo& halo,
    Generation generation,
    TensorRef primaryMutable)
{
    SparkWriteSession session;
    session.spark = sparkUnified(fabric, halo, generation);

    DeviceId home = 0;
    for (const auto& m : session.spark.members) {
        if (m.tensor.id == primaryMutable.id) {
            home = m.device;
            break;
        }
    }
    if (!home)
        throw std::runtime_error("sparkUnifiedWrite: primary not in spark");

    session.writeLease =
        fabric.acquireWrite(primaryMutable, home, generation);
    ScratchAcquire(session.spark.ticket, session.writeLease);
    session.spark.candidate = session.spark.ticket.candidate;
    return session;
}

inline Generation sparkPublish(SparkWriteSession& session) {
    ScratchExecute(session.spark.ticket, 1);
    const Generation pub = session.writeLease.commit();
    session.spark.published = pub;
    ScratchPublish(session.spark.ticket, pub, 1);
    return pub;
}

} // namespace rawr::fabric
