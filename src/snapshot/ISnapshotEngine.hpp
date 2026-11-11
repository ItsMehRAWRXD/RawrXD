// snapshot/ISnapshotEngine.hpp
//
// Dependency-free interface for snapshot transaction management.
// No Qt, no KartGib headers, no external dependencies beyond std.
//
// Implementation is provided by kartgib::SnapshotEngine (in SnapshotEngine.hpp).

#pragma once

#include <string>
#include <vector>

class ISnapshotEngine {
public:
    virtual ~ISnapshotEngine() = default;

    // Initialize the engine with repository root and storage path.
    virtual bool initialize(const std::string& repositoryRoot, const std::string& storagePath) = 0;

    // Begin a new agent-owned transaction.
    virtual bool beginTransaction(const std::string& taskName,
                                   const std::string& agentId,
                                   const std::string& taskId) = 0;

    // Capture a file's pre-write state before modification.
    virtual bool capturePreWrite(const std::string& filePath) = 0;

    // Commit the transaction — all changes accepted.
    virtual bool commitTransaction() = 0;

    // Rollback the transaction — restore all captured files to pre-write state.
    virtual bool rollbackTransaction() = 0;

    // Get the current transaction ID (for logging).
    virtual std::string currentTransactionId() const = 0;

    // Check if currently inside a transaction.
    virtual bool inTransaction() const = 0;
};
