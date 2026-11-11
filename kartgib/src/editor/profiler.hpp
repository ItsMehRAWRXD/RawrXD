#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <deque>
#include <algorithm>

namespace kartgib::editor {

struct ProfileSample {
    std::string name;
    double startTime = 0.0;
    double endTime = 0.0;
    double duration = 0.0;
    uint64_t callCount = 0;
    double minDuration = 0.0;
    double maxDuration = 0.0;
    double totalDuration = 0.0;
    bool active = false;

    void start() {
        startTime = std::chrono::duration<double>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        active = true;
        callCount++;
    }

    void stop() {
        endTime = std::chrono::duration<double>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        duration = endTime - startTime;
        active = false;
        
        totalDuration += duration;
        if (callCount == 1) {
            minDuration = duration;
            maxDuration = duration;
        } else {
            minDuration = std::min(minDuration, duration);
            maxDuration = std::max(maxDuration, duration);
        }
    }

    double getAverageDuration() const {
        return callCount > 0 ? totalDuration / static_cast<double>(callCount) : 0.0;
    }
};

class Profiler {
    std::unordered_map<std::string, ProfileSample> samples_;
    std::unordered_map<std::string, ProfileSample*> activeSamples_;
    std::mutex mutex_;
    std::deque<double> frameTimes_;
    size_t maxFrameHistory = 120;
    double frameTime = 0.0;
    double fps = 0.0;

public:
    Profiler() {
        frameTimes_.reserve(maxFrameHistory);
    }

    void beginFrame() {
        auto now = std::chrono::duration<double>(std::chrono::high_resolution_clock::now().time_since_epoch()).count();
        frameTimes_.push_back(now);
        if (frameTimes_.size() > maxFrameHistory) frameTimes_.pop_front();
        
        if (frameTimes_.size() >= 2) {
            frameTime = frameTimes_.back() - frameTimes_[frameTimes_.size() - 2];
            fps = frameTime > 0.0 ? 1.0 / frameTime : 0.0;
        }
    }

    void endFrame() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [name, sample] : samples_) {
            sample.callCount = 0; // Reset per frame
            sample.totalDuration = 0.0;
        }
        activeSamples_.clear();
    }

    void beginSample(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = samples_.find(name);
        if (it == samples_.end()) {
            ProfileSample sample;
            sample.name = name;
            sample.start();
            samples_[name] = sample;
            activeSamples_[name] = &samples_[name];
        } else {
            it->second.start();
            activeSamples_[name] = &it->second;
        }
    }

    void endSample(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = samples_.find(name);
        if (it != samples_.end()) {
            it->second.stop();
            activeSamples_.erase(name);
        }
    }

    double getFrameTime() const { return frameTime; }
    double getFPS() const { return fps; }

    const ProfileSample* getSample(const std::string& name) const {
        auto it = samples_.find(name);
        return it != samples_.end() ? &it->second : nullptr;
    }

    std::vector<ProfileSample> getAllSamples() const {
        std::vector<ProfileSample> result;
        for (const auto& [name, sample] : samples_) {
            result.push_back(sample);
        }
        std::sort(result.begin(), result.end(), [](const ProfileSample& a, const ProfileSample& b) {
            return a.totalDuration > b.totalDuration;
        });
        return result;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        samples_.clear();
        activeSamples_.clear();
    }
};

// Global profiler instance
extern Profiler g_profiler;

// Scoped profiler helper
class ScopedProfile {
    std::string name_;
    bool enabled_ = true;
public:
    explicit ScopedProfile(const std::string& name) : name_(name) {
        g_profiler.beginSample(name_);
    }
    ~ScopedProfile() {
        g_profiler.endSample(name_);
    }
};

} // namespace kartgib::editor