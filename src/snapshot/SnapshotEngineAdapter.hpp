// snapshot/SnapshotEngineAdapter.hpp
//
// Adapter: kartgib::SnapshotEngine -> ISnapshotEngine.
// Dependency-free interface implementation linking to the native snapshot library.

#pragma once

#include "snapshot/ISnapshotEngine.hpp"
#include "snapshot/SnapshotEngine.hpp"

class SnapshotEngineAdapter : public ISnapshotEngine {
public:
    bool initialize(const std::string& repositoryRoot, const std::string& storagePath) override {
        config_.repository_root = repositoryRoot;
        config_.storage_path = storagePath;
        config_.max_storage_gb = 10;
        config_.max_snapshots = 1000;
        config_.retention_days = 30;
        config_.include_untracked = true;
        config_.verify_checksums = true;
        config_.atomic_writes = true;
        config_.journal_enabled = true;
        return engine_.Initialize(config_);
    }

    bool beginTransaction(const std::string& taskName,
                          const std::string& agentId,
                          const std::string& taskId) override {
        bool result = engine_.BeginTransaction(taskName, agentId, taskId);
        if (result) {
            m_inTransaction = true;
            m_transactionId = taskId;
        }
        return result;
    }

    bool capturePreWrite(const std::string& filePath) override {
        return engine_.CaptureFile(std::filesystem::path(filePath));
    }

    bool commitTransaction() override {
        engine_.CommitTransaction();
        m_inTransaction = false;
        m_transactionId.clear();
        return true;
    }

    bool rollbackTransaction() override {
        bool result = engine_.RollbackTransaction();
        m_inTransaction = false;
        m_transactionId.clear();
        return result;
    }

    std::string currentTransactionId() const override {
        return m_transactionId;
    }

    bool inTransaction() const override {
        return m_inTransaction;
    }

private:
    kartgib::SnapshotConfig config_;
    kartgib::SnapshotEngine engine_;
    bool m_inTransaction = false;
    std::string m_transactionId;
};
