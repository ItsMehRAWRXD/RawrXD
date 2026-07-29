#pragma once
// zero_touch.hpp – Qt-free ZeroTouch (C++20 / Win32)
#include <string>

<<<<<<< HEAD
class ZeroTouch {
public:
    ZeroTouch();
    ~ZeroTouch() = default;
=======
#include <string>

class ZeroTouch {

public:
    explicit ZeroTouch();
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

    void installAll();
    void installFileWatcher();
    void installGitHook();
    void installVoiceTrigger();

private:
    std::string m_lastVoiceWish;
<<<<<<< HEAD
=======
    bool m_running;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
