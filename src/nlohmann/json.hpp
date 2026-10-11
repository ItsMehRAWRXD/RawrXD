#pragma once
// Redirect to the real nlohmann::json single-header from 3rdparty
#ifdef _MSC_VER
#  include "../../3rdparty/json/json.hpp"
#else
#  include "../../3rdparty/json/json.hpp"
#endif
