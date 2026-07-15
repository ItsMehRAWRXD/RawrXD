#pragma once
#include <string>

namespace seg {

class TelemetryView {
public:
    void Refresh();
    std::string ToString() const;

private:
    // aggregate stats cached here
};

} // namespace seg
