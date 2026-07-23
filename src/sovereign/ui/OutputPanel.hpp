// ============================================================================
// OutputPanel.hpp - Output Panel for Sovereign IDE
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <deque>

namespace Sovereign {

enum class OutputChannel { BUILD, DEBUG, TEST, CONSOLE, AGENT, TELEMETRY, SYSTEM };

struct OutputEntry {
    uint64_t id;
    OutputChannel channel;
    std::string text;
    std::string source;
    uint64_t timestamp;
    int severity; // 0=info, 1=warn, 2=error
    bool isError;
};

class OutputPanel {
public:
    OutputPanel();
    ~OutputPanel();

    bool Initialize(size_t maxEntries = 10000);
    void Shutdown();

    void Write(OutputChannel channel, const std::string& text, const std::string& source = "");
    void WriteLine(OutputChannel channel, const std::string& text, const std::string& source = "");
    void WriteError(OutputChannel channel, const std::string& text, const std::string& source = "");
    void WriteFormat(OutputChannel channel, const std::string& fmt, ...);

    void Clear(OutputChannel channel);
    void ClearAll();

    std::vector<OutputEntry> GetEntries(OutputChannel channel, size_t count = 100) const;
    std::vector<OutputEntry> GetRecent(size_t count = 50) const;
    std::vector<OutputEntry> GetErrors(size_t count = 50) const;

    void SetActiveChannel(OutputChannel channel);
    OutputChannel GetActiveChannel() const { return activeChannel_; }

    void SetWriteCallback(std::function<void(const OutputEntry&)> callback);
    void SetErrorCallback(std::function<void(const OutputEntry&)> callback);

    bool HasErrors() const;
    size_t GetEntryCount(OutputChannel channel) const;
    size_t GetTotalEntryCount() const { return totalEntries_; }

    bool SaveToFile(const std::string& path, OutputChannel channel);
    bool SaveAllToFile(const std::string& path);

    struct OutputStats {
        uint64_t totalEntries;
        uint64_t errorEntries;
        uint64_t warningEntries;
        uint64_t infoEntries;
    };
    OutputStats GetStats() const { return stats_; }

private:
    std::deque<OutputEntry> entries_;
    std::unordered_map<OutputChannel, std::deque<OutputEntry>> channelEntries_;
    OutputChannel activeChannel_ = OutputChannel::CONSOLE;
    size_t maxEntries_;
    uint64_t nextId_ = 1;
    uint64_t totalEntries_ = 0;
    OutputStats stats_;
    
    std::function<void(const OutputEntry&)> writeCallback_;
    std::function<void(const OutputEntry&)> errorCallback_;
    mutable std::mutex mutex_;
    
    void AddEntry(OutputChannel channel, const std::string& text, const std::string& source, int severity);
};

} // namespace Sovereign
