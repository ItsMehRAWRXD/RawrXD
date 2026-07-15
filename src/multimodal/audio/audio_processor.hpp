// RawrXD Audio Processor
// Phase AS: Multi-Modal Support

#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>

namespace rawrxd {
namespace multimodal {

// Audio format
enum class AudioFormat {
    WAV,
    MP3,
    FLAC,
    OGG,
    AAC,
    PCM
};

// Audio data
struct Audio {
    std::vector<float> samples;
    int sample_rate;
    int channels;
    float duration_seconds;
    AudioFormat format;
    
    Audio()
        : sample_rate(16000)
        , channels(1)
        , duration_seconds(0.0f)
        , format(AudioFormat::WAV) {}
};

// Audio task types
enum class AudioTask {
    SPEECH_RECOGNITION,
    SPEECH_SYNTHESIS,
    AUDIO_CLASSIFICATION,
    AUDIO_EMBEDDING,
    VOICE_ACTIVITY_DETECTION,
    SPEAKER_RECOGNITION
};

// Speech recognition result
struct SpeechResult {
    std::string text;
    float confidence;
    float start_time;
    float end_time;
    std::vector<std::pair<std::string, float>> word_timings;
    
    SpeechResult()
        : confidence(0.0f)
        , start_time(0.0f)
        , end_time(0.0f) {}
};

// Audio output
struct AudioOutput {
    std::string text;
    std::vector<float> embedding;
    std::vector<std::string> labels;
    std::vector<float> label_confidences;
    std::vector<SpeechResult> segments;
    
    AudioOutput() = default;
};

// Audio configuration
struct AudioConfig {
    std::string model_path;
    std::string device;
    int sample_rate;
    int max_duration_seconds;
    std::string language;
    bool enable_punctuation;
    bool enable_word_timings;
    
    AudioConfig()
        : device("cpu")
        , sample_rate(16000)
        , max_duration_seconds(300)
        , language("en")
        , enable_punctuation(true)
        , enable_word_timings(false) {}
};

// Forward declarations
class AudioProcessor;
class SpeechRecognizer;
class AudioEncoder;

/**
 * AudioProcessor - Multi-modal audio processing
 */
class AudioProcessor {
public:
    AudioProcessor();
    ~AudioProcessor();
    
    // Initialize
    bool initialize(const AudioConfig& config);
    void shutdown();
    
    // Audio loading
    Audio loadAudio(const std::string& path);
    Audio loadAudioFromBuffer(const std::vector<uint8_t>& buffer, AudioFormat format);
    Audio decodeBase64(const std::string& base64, AudioFormat format);
    
    // Processing
    AudioOutput process(const Audio& audio, AudioTask task);
    
    // Specific tasks
    std::string transcribe(const Audio& audio);
    std::vector<SpeechResult> transcribeWithTimings(const Audio& audio);
    std::vector<float> encodeAudio(const Audio& audio);
    std::vector<std::string> classifyAudio(const Audio& audio);
    std::vector<std::pair<float, float>> detectVoiceActivity(const Audio& audio);
    
    // Utilities
    Audio resample(const Audio& audio, int target_sample_rate);
    Audio convertChannels(const Audio& audio, int target_channels);
    Audio trimSilence(const Audio& audio, float threshold = 0.01f);
    std::vector<uint8_t> encodeToBuffer(const Audio& audio, AudioFormat format);
    std::string encodeToBase64(const Audio& audio, AudioFormat format);
    
    // Status
    bool isInitialized() const;
    std::string getDevice() const;
    
private:
    AudioConfig config_;
    bool initialized_;
    
    std::unique_ptr<SpeechRecognizer> speech_recognizer_;
    std::unique_ptr<AudioEncoder> audio_encoder_;
    
    // Internal methods
    bool preprocess(Audio& audio);
    AudioOutput runInference(const Audio& audio, AudioTask task);
};

/**
 * SpeechRecognizer - Speech-to-text
 */
class SpeechRecognizer {
public:
    SpeechRecognizer();
    ~SpeechRecognizer();
    
    bool initialize(const std::string& model_path, const std::string& device);
    SpeechResult recognize(const Audio& audio);
    std::vector<SpeechResult> recognizeWithTimings(const Audio& audio);
    
private:
    std::string model_path_;
    std::string device_;
    bool initialized_;
};

/**
 * AudioEncoder - Encode audio to embeddings
 */
class AudioEncoder {
public:
    AudioEncoder();
    ~AudioEncoder();
    
    bool initialize(const std::string& model_path, const std::string& device);
    std::vector<float> encode(const Audio& audio);
    std::vector<std::vector<float>> encodeBatch(const std::vector<Audio>& audio);
    
private:
    std::string model_path_;
    std::string device_;
    bool initialized_;
};

// Global accessor
AudioProcessor* getAudioProcessor();
void setAudioProcessor(std::unique_ptr<AudioProcessor> processor);

// Utility functions
std::string audioFormatToString(AudioFormat format);
AudioFormat stringToAudioFormat(const std::string& str);

} // namespace multimodal
} // namespace rawrxd
