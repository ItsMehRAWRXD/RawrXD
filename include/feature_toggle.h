#pragma once

#include <QString>

namespace RawrXD {
class FeatureToggle {
public:
    static bool isEnabled(const QString& name, bool defaultValue = false);
};
} // namespace RawrXD
