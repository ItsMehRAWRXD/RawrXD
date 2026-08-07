#pragma once
// =============================================================================
// Module 4: Stop String Matcher
// Sliding window match for multiple stop strings.
// Bounded memory — each buffer never exceeds (stopString.size() - 1).
// No external dependencies beyond <string>, <vector>.
// =============================================================================

#include <string>
#include <vector>

class StopStringMatcher {
public:
    explicit StopStringMatcher(const std::vector<std::string>& stops)
        : stops_(stops), buffers_() {
        for (size_t i = 0; i < stops_.size(); ++i) {
            buffers_.push_back(std::string());
        }
    }

    // Returns the matched stop string, or empty string if no match.
    // After a match, all buffers are cleared.
    std::string check(const std::string& delta) {
        for (size_t i = 0; i < stops_.size(); ++i) {
            buffers_[i] += delta;

            size_t pos = buffers_[i].find(stops_[i]);
            if (pos != std::string::npos) {
                // Found — clear all buffers
                for (size_t j = 0; j < buffers_.size(); ++j) {
                    buffers_[j].clear();
                }
                return stops_[i];
            }

            // Trim to max keep size to prevent unbounded growth
            size_t maxKeep = 0;
            if (stops_[i].size() > 1) {
                maxKeep = stops_[i].size() - 1;
            }
            if (buffers_[i].size() > maxKeep) {
                buffers_[i].erase(0, buffers_[i].size() - maxKeep);
            }
        }
        return std::string();
    }

    void reset() {
        for (size_t i = 0; i < buffers_.size(); ++i) {
            buffers_[i].clear();
        }
    }

private:
    std::vector<std::string> stops_;
    std::vector<std::string> buffers_;
};