#pragma once
#include "rawr_steering_bus.hpp"
namespace rawr {
inline bool SteeringClientSend(const std::string& line) { return SteerSend(line); }
} // namespace rawr
