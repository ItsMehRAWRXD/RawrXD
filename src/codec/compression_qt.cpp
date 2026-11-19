// ============================================================================
// compression_qt.cpp -- Qt adapter over the native compression core.
// ============================================================================
// Preserves the historical source-level interface that existing consumers were
// compiled against:
//
//     namespace codec {
//         QByteArray deflate(const QByteArray& data, bool* success);
//         QByteArray inflate(const QByteArray& data, bool* success);
//         QByteArray deflate_brutal_masm(const QByteArray& data, bool* success);
//     }
//
// All real work is delegated to rawrxd::compression (zlib only). This file is
// Qt-gated and must never be linked into a headless target; headless consumers
// call the native API directly.
//
// Failure behaviour matches the original implementation: on error the bool is
// cleared and an empty QByteArray is returned.
// ============================================================================
#include "codec/compression.h"

#include "codec/compression_core.h"

#include <QtCore/QByteArray>

namespace codec {

QByteArray deflate(const QByteArray& data, bool* success) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.constData());
    auto result = rawrxd::compression::compress(
        bytes, static_cast<std::size_t>(data.size()));

    if (success) *success = static_cast<bool>(result);
    if (!result) return QByteArray();

    return QByteArray(
        reinterpret_cast<const char*>(result.bytes.data()),
        static_cast<qsizetype>(result.bytes.size()));
}

QByteArray inflate(const QByteArray& data, bool* success) {
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.constData());
    auto result = rawrxd::compression::decompress(
        bytes,
        static_cast<std::size_t>(data.size()),
        rawrxd::compression::MaxOutputBytes);

    if (success) *success = static_cast<bool>(result);
    if (!result) return QByteArray();

    return QByteArray(
        reinterpret_cast<const char*>(result.bytes.data()),
        static_cast<qsizetype>(result.bytes.size()));
}

QByteArray deflate_brutal_masm(const QByteArray& data, bool* success) {
    // "Brutal" mode was zlib at Z_BEST_COMPRESSION. Keep that level so the
    // output remains bit-identical to the historical implementation.
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(data.constData());
    auto result = rawrxd::compression::compress(
        bytes, static_cast<std::size_t>(data.size()), 9);

    if (success) *success = static_cast<bool>(result);
    if (!result) return QByteArray();

    return QByteArray(
        reinterpret_cast<const char*>(result.bytes.data()),
        static_cast<qsizetype>(result.bytes.size()));
}

} // namespace codec