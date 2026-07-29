<<<<<<< HEAD
#ifndef SPECULATIVE_DECODER_H
#define SPECULATIVE_DECODER_H

#include <string>
#include <vector>
#include <cstdio>
#include <random>

// Speculative decoding – draft with TinyLlama, verify with Phi-3 → 1.8× tokens/sec boost on RX 7800 XT.
class SpeculativeDecoder
{
public:
    explicit SpeculativeDecoder();
    ~SpeculativeDecoder();

    // Set draft model (e.g., TinyLlama)
    void setDraftModel(const std::string &modelPath);

    // Set target model (e.g., Phi-3)
    void setTargetModel(const std::string &modelPath);

    // Generate tokens using speculative decoding
    std::vector<int> generateTokens(const std::string &prompt, int maxTokens);

    // Callback hooks (replacing Qt signals)
    void (*onTokensGenerated)(const std::vector<int>& tokens) = nullptr;
    void (*onAcceptanceRateChanged)(float rate) = nullptr;

private:
    std::string m_draftModelPath;
    std::string m_targetModelPath;
    bool m_gpuAccelerated;
    bool m_draftModelLoaded;
    bool m_targetModelLoaded;

    // Generate draft tokens
    std::vector<int> generateDraftTokens(const std::string &prompt, int maxTokens);

    // Verify draft tokens with target model
    std::vector<int> verifyTokens(const std::string &prompt, const std::vector<int> &draftTokens);

    // RNG for draft token generation
    std::mt19937 m_rng;
};

=======
#ifndef SPECULATIVE_DECODER_H
#define SPECULATIVE_DECODER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>

// Speculative decoding – draft with TinyLlama, verify with Phi-3 → 1.8× tokens/sec boost on RX 7800 XT.
class SpeculativeDecoder : public QObject
{
    Q_OBJECT

public:
    explicit SpeculativeDecoder(QObject *parent = nullptr);
    ~SpeculativeDecoder();

    // Set draft model (e.g., TinyLlama)
    void setDraftModel(const QString &modelPath);

    // Set target model (e.g., Phi-3)
    void setTargetModel(const QString &modelPath);

    // Generate tokens using speculative decoding
    QList<int> generateTokens(const QString &prompt, int maxTokens);

private:
    QString m_draftModelPath;
    QString m_targetModelPath;

    // Generate draft tokens
    QList<int> generateDraftTokens(const QString &prompt, int maxTokens);

    // Verify draft tokens with target model
    QList<int> verifyTokens(const QString &prompt, const QList<int> &draftTokens);
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#endif // SPECULATIVE_DECODER_H