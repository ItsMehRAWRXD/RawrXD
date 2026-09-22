#pragma once

#include <stdint.h>

namespace Sunshine {

class Audio {
public:
    bool initialize();
    void shutdown();
    void playTone(float frequency, float durationSeconds);
    void update();
    bool isReady() const;

private:
    bool m_ready = false;
};

} // namespace Sunshine
