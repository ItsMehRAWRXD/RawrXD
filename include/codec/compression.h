#pragma once

#include <QByteArray>
#include <QString>
#include <QtGlobal>

namespace codec {

/** Compress data using the zlib-wrapped DEFLATE format. */
QByteArray deflate(const QByteArray& data, bool* success = nullptr);

/**
 * Stream-decompress one zlib stream using bounded 64 KiB output chunks.
 * Truncated input, trailing bytes, malformed streams, and expansion beyond
 * maxOutputBytes fail closed and return an empty QByteArray.
 * The default output ceiling is 1 GiB; callers can supply a tighter budget.
 */
QByteArray inflate(const QByteArray& data, bool* success = nullptr,
                   qint64 maxOutputBytes = (qint64(1) << 30));

/**
 * Compatibility entry point for maximum-level zlib compression. The name is
 * retained for source compatibility and does not promise MASM dispatch.
 */
QByteArray deflate_brutal_masm(const QByteArray& data, bool* success = nullptr);

} // namespace codec
