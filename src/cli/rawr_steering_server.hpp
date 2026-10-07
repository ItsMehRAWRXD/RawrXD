#pragma once
#include "rawr_steering_bus.hpp"
namespace rawr {
inline bool SteeringServerOnce(std::string& line) { return SteerServeOnce(line); }
} // namespace rawr
