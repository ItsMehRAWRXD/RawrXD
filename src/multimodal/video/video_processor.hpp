// RawrXD Video Processor
// Phase AS: Multi-Modal Support

#pragma once

#include "../vision/vision_processor.hpp"
#include "../audio/audio_processor.hpp"
#include <vector>
#include <string>
#include <memory>

namespace rawrxd {
namespace multimodal {

// Video format
enum class VideoFormat {
    MP4,
    AVI,
    MKV,
    MOV,
    WEBM,
    FLV
};

// Video data
struct Video {
    std::vector<Image> frames;
    Audio audio_track;
    int fps;
    float duration_seconds;
    int width;
    int height;
    VideoFormat format;
    
    Video()
        : fps(30)
        , duration_seconds(0.0f)
        , width(0)
        , height(0)
        , format(VideoFormat::MP4) {}
};

// Video task types
enum class VideoTask {
    FRAME_EXTRACTION,
    SCENE_DETECTION,
    ACTION_RECOGNITION,
    VIDEO_CAPTIONING,
    VIDEO_EMBEDDING,
    TEMPORAL_SEGMENTATION
};

// Scene detection result
struct Scene {
    int start_frame;
    int end_frame;
    float start_time;
    float end_time;
    std::string description;
    float confidence;
    
    Scene()
        : start_frame(0)
        , end_frame(0)
        , start_time(0.0f)
        , end_time(0.0f)
        , confidence(0.0f) {}
};

// Video output
struct VideoOutput {
    std::string caption;
    std::vector<Scene> scenes;
    std::vector<std::string> actions;
    std::vector<float> action_confidences;
    std::vector<float> embedding;
    std::vector<VisionOutput> frame_outputs;
    
    VideoOutput() = default;
};

// Video configuration
struct VideoConfig {
    std::string model_path;
    std::string device;
    int target_fps;
    int max_resolution;
    float scene_threshold;
    int keyframe_interval;
    bool extract_audio;
    bool enable_audio_analysis;
    
    VideoConfig()
        : device("cpu")
        , target_fps(1)
        , max_resolution(720)
        , scene_threshold(0.3f)
        , keyframe_interval(30)
        , extract_audio(true)
        , enable_audio_analysis(true) {}
};

// Forward declarations
class VideoProcessor;
class FrameExtractor;

/**
 * VideoProcessor - Multi-modal video processing
 */
class VideoProcessor {
public:
    VideoProcessor();
    ~VideoProcessor();
    
    // Initialize
    bool initialize(const VideoConfig& config);
    void shutdown();
    
    // Video loading
    Video loadVideo(const std::string& path);
    Video loadVideoFromBuffer(const std::vector<uint8_t>& buffer, VideoFormat format);
    
    // Processing
    VideoOutput process(const Video& video, VideoTask task);
    
    // Specific tasks
    std::vector<Image> extractFrames(const Video& video, int fps = 1);
    std::vector<Scene> detectScenes(const Video& video);
    std::vector<std::string> recognizeActions(const Video& video);
    std::string generateCaption(const Video& video);
    std::vector<float> encodeVideo(const Video& video);
    
    // Combined analysis
    VideoOutput analyze(const Video& video);
    
    // Utilities
    Video resize(const Video& video, int max_resolution);
    Video trim(const Video& video, float start_time, float end_time);
    std::vector<uint8_t> encodeToBuffer(const Video& video, VideoFormat format);
    
    // Status
    bool isInitialized() const;
    std::string getDevice() const;
    
private:
    VideoConfig config_;
    bool initialized_;
    
    std::unique_ptr<VisionProcessor> vision_processor_;
    std::unique_ptr<AudioProcessor> audio_processor_;
    std::unique_ptr<FrameExtractor> frame_extractor_;
    
    // Internal methods
    bool preprocess(Video& video);
    VideoOutput runInference(const Video& video, VideoTask task);
};

/**
 * FrameExtractor - Extract frames from video
 */
class FrameExtractor {
public:
    FrameExtractor();
    ~FrameExtractor();
    
    bool initialize(int target_fps);
    std::vector<Image> extractFrames(const Video& video);
    std::vector<Image> extractKeyframes(const Video& video, int interval);
    Image extractFrameAtTime(const Video& video, float timestamp);
    
private:
    int target_fps_;
    bool initialized_;
};

// Global accessor
VideoProcessor* getVideoProcessor();
void setVideoProcessor(std::unique_ptr<VideoProcessor> processor);

// Utility functions
std::string videoFormatToString(VideoFormat format);
VideoFormat stringToVideoFormat(const std::string& str);

} // namespace multimodal
} // namespace rawrxd
