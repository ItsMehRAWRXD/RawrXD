#pragma once

#include <functional>
#include <string>

namespace rawrxd::stt {

// Native Windows SAPI dictation speech-to-text (no Qt, no network).
// Fail-closed: initialize() returns false with an actionable error when no
// recognizer/input device exists. start() delivers recognised sentences on a
// background thread until stop().
class SttEngine {
public:
    using Callback = std::function<void(const std::string& text)>;

    SttEngine();
    ~SttEngine();

    SttEngine(const SttEngine&) = delete;
    SttEngine& operator=(const SttEngine&) = delete;

    bool initialize(std::string& error);
    bool start(Callback callback, std::string& error);
    void stop();
    bool listening() const;

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

} // namespace rawrxd::stt