#include "tools/ModelCompilerUtils.h"

#include <QLocale>
#include <QTextStream>

// Returns corpusSizeInBytes divided by the fixed digest factor.
double ModelCompilerUtils::digestCorpusSize(qint64 corpusSizeInBytes)
{
    if (corpusSizeInBytes < 0) {
        return 0.0;
    }

    return static_cast<double>(corpusSizeInBytes) / kDigestFactor;
}

// Builds a human-readable summary for UI surfaces or logs.
QString ModelCompilerUtils::formatCompilerOutput(const QString& modelName, qint64 corpusSizeInBytes)
{
    const double result = digestCorpusSize(corpusSizeInBytes);

    QLocale locale; // default locale keeps thousands separators intuitive.
    const QString formattedBytes = locale.toString(corpusSizeInBytes);
    const QString formattedResult = locale.toString(result, 'f', 2);

    QString output;
    QTextStream stream(&output);
    stream << "--- " << modelName << " Model Compiler Report ---\n"
           << "Input Corpus Size (bytes): " << formattedBytes << "\n"
           << "Digest Factor (PoC): 1 / " << kDigestFactor << "\n"
           << "Calculated Result (Resource Unit): " << formattedResult << "\n"
           << "--------------------------------------\n"
           << "NOTE: The result represents a resource unit derived from"
           << " the raw corpus size.";

    return output;
}
