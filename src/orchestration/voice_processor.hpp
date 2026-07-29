#pragma once

<<<<<<< HEAD
#include <string>
#include <vector>
=======

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <chrono>

<<<<<<< HEAD
class VoiceProcessor {

public:
    explicit VoiceProcessor(void* parent = nullptr);
    ~VoiceProcessor();
=======
/**
 * @class VoiceProcessor
 * @brief Production-ready speech-to-text, intent recognition, and text-to-speech processor
 * 
 * Features:
 * - Audio input capture with configurable format
 * - Speech-to-text transcription with AI integration
 * - Intent detection and command parsing
 * - Plan generation from voice input
 * - Text-to-speech feedback
 * - Structured logging with performance metrics
 * - Error handling and recovery
 * - GDPR-compliant audio data handling
 */
class VoiceProcessor : public void {

public:
    explicit VoiceProcessor(void* parent = nullptr);
    ~VoiceProcessor() override;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    struct Config {
        std::string apiEndpoint;
        std::string apiKey;
        int sampleRate = 16000;
        int channelCount = 1;
        int maxRecordingDurationMs = 30000;
        bool enableMetrics = true;
        bool enableAutoDelete = true;
        int autoDeleteDelayMs = 60000;
    };

    void setConfig(const Config& config);
    Config getConfig() const;

    bool startRecording();
    bool stopRecording();
    bool isRecording() const;
    
    std::string transcribeAudio(const std::vector<uint8_t>& audioData);
<<<<<<< HEAD
    std::string detectIntent(const std::string& transcript);
    std::string generatePlan(const std::string& intent, const std::string& context);
    bool speakText(const std::string& text);

private:
    void* m_parent;
    Config m_config;
    bool m_recording = false;
};

#endif
=======
    void* detectIntent(const std::string& transcription);
    std::string generateSpeech(const std::string& text);
    
    // Metrics
    struct Metrics {
        int64_t recordingCount = 0;
        int64_t transcriptionCount = 0;
        int64_t intentDetectionCount = 0;
        int64_t ttsCount = 0;
        int64_t errorCount = 0;
        double avgRecordingDurationMs = 0.0;
        double avgTranscriptionLatencyMs = 0.0;
        double avgIntentDetectionLatencyMs = 0.0;
        double avgTtsLatencyMs = 0.0;
    };
    
    Metrics getMetrics() const;
    void resetMetrics();

    void recordingStarted();
    void recordingStopped(const std::vector<uint8_t>& audioData);
    void transcriptionReady(const std::string& text);
    void intentDetected(const void*& intent);
    void speechGenerated(const std::vector<uint8_t>& audioData);
    void errorOccurred(const std::string& error);
    void metricsUpdated(const Metrics& metrics);

private:
    void handleAudioStateChanged(QAudio::State state);
    void processRecordedAudio();
    void scheduleAudioDeletion(const std::vector<uint8_t>& audioData);

private:
    // Audio capture
    QAudioSource* m_audioSource;  // Qt 6: QAudioInput renamed to QAudioSource
    QAudioDevice m_audioDevice;
    std::stringstream* m_audioBuffer;
    QAudioFormat m_audioFormat;
    void** m_recordingTimer;
    
    // Configuration
    Config m_config;
    mutable std::mutex m_configMutex;
    
    // State
    bool m_isRecording;
    mutable std::mutex m_stateMutex;
    
    // Metrics
    Metrics m_metrics;
    mutable std::mutex m_metricsMutex;
    
    // Helper methods
    void setupAudioFormat();
    void logStructured(const std::string& level, const std::string& message, const void*& context = void*());
    void updateMetric(const std::string& metricName, int64_t value);
    void recordLatency(const std::string& operation, const std::chrono::milliseconds& duration);
    void* makeApiRequest(const std::string& endpoint, const void*& payload);
    bool validateAudioData(const std::vector<uint8_t>& audioData);
};


>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
