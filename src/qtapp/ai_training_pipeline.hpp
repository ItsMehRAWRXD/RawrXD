#ifndef AI_TRAINING_PIPELINE_HPP
#define AI_TRAINING_PIPELINE_HPP

#include "ai_digestion_engine.hpp"
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QProcess>
#include <QtCore/QTemporaryDir>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>
#include <memory>

// Forward declarations
class LlamaTrainer;
class ModelQuantizer;
class TrainingValidator;

// Enumeration for training backends
enum class TrainingBackend {
    LlamaCpp,       // llama.cpp based training
    Transformers,   // HuggingFace transformers
    Custom,         // Custom implementation
    OpenAI,         // OpenAI fine-tuning
    Ollama          // Ollama training
};

// Structure for model architecture configuration
struct ModelArchitecture {
    QString baseModel;          // Base model to fine-tune from
    int vocabularySize;
    int hiddenSize;
    int numLayers;
    int numAttentionHeads;
    int intermediateSize;
    int maxPositionEmbeddings;
    QString activationFunction;
    double dropoutRate;
    double attentionDropout;
    QString normalizationType;
    
    ModelArchitecture() 
        : vocabularySize(32000)
        , hiddenSize(4096)
        , numLayers(32)
        , numAttentionHeads(32)
        , intermediateSize(11008)
        , maxPositionEmbeddings(2048)
        , activationFunction("silu")
        , dropoutRate(0.0)
        , attentionDropout(0.0)
        , normalizationType("RMSNorm")
    {}
};

// Structure for training hyperparameters
struct TrainingHyperparameters {
    double learningRate;
    double weightDecay;
    double beta1;
    double beta2;
    double epsilon;
    int batchSize;
    int gradientAccumulationSteps;
    int maxGradientNorm;
    double warmupRatio;
    QString scheduler;
    int saveSteps;
    int evaluationSteps;
    int loggingSteps;
    bool useGradientCheckpointing;
    bool useFp16;
    bool useBf16;
    
    TrainingHyperparameters()
        : learningRate(5e-5)
        , weightDecay(0.0)
        , beta1(0.9)
        , beta2(0.999)
        , epsilon(1e-8)
        , batchSize(4)
        , gradientAccumulationSteps(8)
        , maxGradientNorm(1.0)
        , warmupRatio(0.03)
        , scheduler("cosine")
        , saveSteps(500)
        , evaluationSteps(500)
        , loggingSteps(10)
        , useGradientCheckpointing(true)
        , useFp16(false)
        , useBf16(true)
    {}
};

// Main training pipeline class
class AITrainingPipeline : public QObject {
    Q_OBJECT

public:
    explicit AITrainingPipeline(QObject* parent = nullptr);
    virtual ~AITrainingPipeline();

    // Configuration methods
    void setBackend(TrainingBackend backend);
    TrainingBackend getBackend() const;
    
    void setArchitecture(const ModelArchitecture& arch);
    ModelArchitecture getArchitecture() const;
    
    void setHyperparameters(const TrainingHyperparameters& params);
    TrainingHyperparameters getHyperparameters() const;

    // Training methods
    bool prepareTraining(const TrainingDataset& dataset, const DigestionConfig& config);
    void startTraining();
    void stopTraining();
    void pauseTraining();
    void resumeTraining();
    
    // Status methods
    bool isTraining() const;
    bool isPaused() const;
    double getTrainingProgress() const;
    QString getTrainingStatus() const;
    QJsonObject getTrainingMetrics() const;
    
    // Model management
    QString getModelOutputPath() const;
    bool quantizeModel(const QString& inputPath, const QString& outputPath, const QString& quantization);
    bool validateModel(const QString& modelPath);
    bool testModel(const QString& modelPath, const QStringList& testPrompts);

signals:
    // Training progress
    void trainingStarted();
    void trainingProgress(double progress, const QJsonObject& metrics);
    void trainingPaused();
    void trainingResumed();
    void trainingCompleted(const QString& modelPath);
    void trainingFailed(const QString& error);
    
    // Epoch and step events
    void epochStarted(int epoch, int totalEpochs);
    void epochCompleted(int epoch, double loss, double accuracy);
    void stepCompleted(int step, int totalSteps, double loss);
    
    // Model events
    void modelSaved(const QString& path);
    void modelQuantized(const QString& path, const QString& quantization);
    void modelValidated(const QString& path, bool isValid);

public slots:
    void onTrainingTimeout();
    void onModelCheckpoint();

private slots:
    void handleTrainingOutput();
    void handleTrainingError();
    void handleTrainingFinished();

private:
    // Core training methods
    bool setupTrainingEnvironment();
    bool prepareTrainingData(const TrainingDataset& dataset);
    bool generateTrainingScript();
    bool executeTraining();
    void cleanupTraining();
    
    // Backend-specific methods
    bool setupLlamaCppTraining();
    bool setupTransformersTraining();
    bool setupCustomTraining();
    bool setupOllamaTraining();
    
    // Data preparation methods
    bool createDatasetFiles(const TrainingDataset& dataset);
    bool generateTokenizerFiles();
    bool createConfigFiles();
    
    // Model creation methods
    bool initializeModelWeights();
    bool createTrainingLoop();
    bool implementValidationLoop();
    bool saveModelCheckpoints();
    
    // Utility methods
    QString generateRequirementsFile();
    bool installDependencies();
    bool checkGPUAvailability();
    QString detectOptimalQuantization();
    
    // Monitoring methods
    void parseTrainingLogs();
    void updateTrainingMetrics();
    void saveTrainingState();

private:
    TrainingBackend m_backend;
    ModelArchitecture m_architecture;
    TrainingHyperparameters m_hyperparameters;
    
    // Training state
    bool m_isTraining;
    bool m_isPaused;
    double m_progress;
    QString m_status;
    QJsonObject m_metrics;
    
    // Training environment
    std::unique_ptr<QTemporaryDir> m_workingDir;
    QString m_modelOutputPath;
    QString m_datasetPath;
    QString m_configPath;
    QString m_scriptPath;
    
    // Training process
    std::unique_ptr<QProcess> m_trainingProcess;
    QTimer* m_progressTimer;
    QTimer* m_checkpointTimer;
    
    // Training data
    TrainingDataset m_dataset;
    DigestionConfig m_config;
    
    // Network for downloading models/dependencies
    QNetworkAccessManager* m_networkManager;
    
    // Training components
    std::unique_ptr<LlamaTrainer> m_llamaTrainer;
    std::unique_ptr<ModelQuantizer> m_quantizer;
    std::unique_ptr<TrainingValidator> m_validator;
    
    // Training statistics
    int m_currentEpoch;
    int m_totalEpochs;
    int m_currentStep;
    int m_totalSteps;
    double m_currentLoss;
    double m_currentAccuracy;
    double m_bestLoss;
    QDateTime m_trainingStartTime;
    
    // Model configuration
    QString m_baseModelPath;
    QString m_tokenizerPath;
    QStringList m_requiredFiles;
};

// LlamaTrainer for llama.cpp backend
class LlamaTrainer : public QObject {
    Q_OBJECT

public:
    explicit LlamaTrainer(QObject* parent = nullptr);
    
    bool prepareTraining(const QString& datasetPath, const ModelArchitecture& arch);
    bool startTraining(const TrainingHyperparameters& params);
    bool quantizeModel(const QString& inputPath, const QString& outputPath, const QString& quantization);
    
signals:
    void trainingProgress(double progress);
    void trainingCompleted(const QString& modelPath);
    void trainingFailed(const QString& error);

private:
    bool downloadLlamaCpp();
    bool buildLlamaCpp();
    bool prepareLlamaData();
    bool executeLlamaTraining();
    
private:
    QString m_llamaCppPath;
    QString m_workingDir;
    std::unique_ptr<QProcess> m_process;
};

// ModelQuantizer for model compression
class ModelQuantizer : public QObject {
    Q_OBJECT

public:
    explicit ModelQuantizer(QObject* parent = nullptr);
    
    bool quantizeModel(const QString& inputPath, const QString& outputPath, const QString& quantization);
    QStringList getSupportedQuantizations() const;
    double estimateQuantizedSize(const QString& modelPath, const QString& quantization);

signals:
    void quantizationProgress(double progress);
    void quantizationCompleted(const QString& outputPath);
    void quantizationFailed(const QString& error);

private:
    bool setupQuantizationEnvironment();
    bool executeQuantization(const QString& inputPath, const QString& outputPath, const QString& quantization);
    bool validateQuantizedModel(const QString& modelPath);
    
private:
    std::unique_ptr<QProcess> m_process;
    QString m_quantizerPath;
};

// TrainingValidator for model validation
class TrainingValidator : public QObject {
    Q_OBJECT

public:
    explicit TrainingValidator(QObject* parent = nullptr);
    
    bool validateModel(const QString& modelPath);
    bool testModel(const QString& modelPath, const QStringList& testPrompts);
    QJsonObject getValidationResults() const;

signals:
    void validationProgress(double progress);
    void validationCompleted(bool isValid, const QJsonObject& results);

private:
    bool checkModelFormat(const QString& modelPath);
    bool validateModelWeights(const QString& modelPath);
    bool testModelInference(const QString& modelPath, const QStringList& prompts);
    double calculatePerplexity(const QString& modelPath, const QStringList& testData);
    
private:
    QJsonObject m_validationResults;
    std::unique_ptr<QProcess> m_testProcess;
};

#endif // AI_TRAINING_PIPELINE_HPP