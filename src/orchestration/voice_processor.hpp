#pragma once

#include <string>
#include <vector>
#include <chrono>

class VoiceProcessor {

public:
    explicit VoiceProcessor(void* parent = nullptr);
    ~VoiceProcessor();

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
    std::string detectIntent(const std::string& transcript);
    std::string generatePlan(const std::string& intent, const std::string& context);
    bool speakText(const std::string& text);

private:
    void* m_parent;
    Config m_config;
    bool m_recording = false;
};

#endif
