// RAWRXD_GRAPH_RESTORED_001 — Checkpoint manager header (Qt-free)
#pragma once
#include <string>
#include <vector>
#include <map>
#include <cstdint>

// Stub types replacing Qt
using QString = std::string;
struct QJsonObject { void insert(const char*, const char*){} };
struct QObject { virtual ~QObject() = default; };
using qint64 = int64_t;
using QByteArray = std::string;

/**
 * @class CheckpointManager
 * @brief Save, manage, and restore training checkpoints
 */
class CheckpointManager : public QObject
{
public:
    explicit CheckpointManager(void* parent = nullptr);
    ~CheckpointManager();

    static CheckpointManager& instance() {
        static CheckpointManager inst;
        return inst;
    }

    bool initialize(const QString& checkpointDir, int maxCheckpoints = 10);
    bool isInitialized() const { return m_initialized; }

    enum class CompressionLevel {
        None,
        Low,
        Medium,
        High,
        Maximum
    };

    struct CheckpointMetadata {
        QString checkpointId;
        int epoch = 0;
        int step = 0;
        qint64 timestamp = 0;
        float validationLoss = 0.0f;
        float trainLoss = 0.0f;
        float accuracy = 0.0f;
        float wallclockTime = 0.0f;
        int modelSize = 0;
        QString modelArchitecture;
        QString hyperparameters;
        QString datasetVersion;
        bool isBestModel = false;
        QString notes;
    };

    struct CheckpointState {
        QByteArray modelWeights;
        QByteArray optimizerState;
        QByteArray schedulerState;
        QByteArray trainingState;
        QJsonObject config;
    };

    struct CheckpointIndex {
        QString checkpointId;
        QString filePath;
        CheckpointMetadata metadata;
        int checkpointNumber = 0;
    };

    // Show callback for UI display
    using ShowCallback = void (*)(void* ctx, const std::vector<CheckpointIndex>& checkpoints);

    QString saveCheckpoint(const CheckpointMetadata& metadata,
                          const CheckpointState& state,
                          CompressionLevel compress = CompressionLevel::Medium);
    QString quickSaveCheckpoint(const CheckpointMetadata& metadata,
                               const CheckpointState& state);
    bool loadCheckpoint(const QString& checkpointId, CheckpointState& state);
    QString loadLatestCheckpoint(CheckpointState& state);
    QString loadBestCheckpoint(CheckpointState& state);
    QString loadCheckpointFromEpoch(int epoch, CheckpointState& state);

    CheckpointMetadata getCheckpointMetadata(const QString& checkpointId) const;
    std::vector<CheckpointIndex> listCheckpoints() const;
    std::vector<CheckpointIndex> getCheckpointHistory(int limit = 10) const;

    bool deleteCheckpoint(const QString& checkpointId);
    int pruneOldCheckpoints(int keepCount);
    CheckpointMetadata getBestCheckpointInfo() const;
    bool updateCheckpointMetadata(const QString& checkpointId,
                                 const CheckpointMetadata& metadata);
    bool setCheckpointNote(const QString& checkpointId, const QString& note);

    bool enableAutoCheckpointing(int intervalSteps, int saveEveryNEpochs = 1);
    void disableAutoCheckpointing();
    bool shouldCheckpoint(int step, int epoch) const;

    bool validateCheckpoint(const QString& checkpointId) const;
    std::map<QString, bool> validateAllCheckpoints() const;
    bool repairCheckpoint(const QString& checkpointId);

    uint64_t getTotalCheckpointSize() const;
    uint64_t getCheckpointSize(const QString& checkpointId) const;
    QJsonObject generateCheckpointReport() const;
    QJsonObject compareCheckpoints(const QString& checkpointId1,
                                  const QString& checkpointId2) const;

    void setDistributedInfo(int rank, int worldSize);
    bool synchronizeDistributedCheckpoints();

    QJsonObject exportConfiguration() const;
    bool importConfiguration(const QJsonObject& config);
    bool saveConfigurationToFile(const QString& filePath) const;
    bool loadConfigurationFromFile(const QString& filePath);

    void setShowCallback(ShowCallback cb, void* ctx);
    void show();

private:
    QString m_checkpointDir;
    int m_maxCheckpoints = 10;
    int m_checkpointCounter = 0;
    bool m_initialized = false;

    bool m_autoCheckpointEnabled = false;
    int m_autoCheckpointInterval = 0;
    int m_autoCheckpointEpochInterval = 0;
    int m_lastAutoCheckpointStep = 0;
    int m_lastAutoCheckpointEpoch = 0;

    int m_rank = 0;
    int m_worldSize = 0;

    std::vector<CheckpointIndex> m_checkpointIndex;
    QString m_bestCheckpointId;

    ShowCallback m_showCb = nullptr;
    void* m_showCtx = nullptr;

    QString generateCheckpointId();
    QByteArray compressState(const QByteArray& data, CompressionLevel level);
    QByteArray decompressState(const QByteArray& data);
    bool writeCheckpointToDisk(const QString& checkpointId,
                              const CheckpointState& state,
                              CompressionLevel compress);
    bool readCheckpointFromDisk(const QString& checkpointId,
                               CheckpointState& state);
};
