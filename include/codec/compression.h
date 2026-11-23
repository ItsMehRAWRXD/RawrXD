#pragma once

#include <QByteArray>
#include <QString>

namespace codec {

/**
 * @brief Compress data using deflate algorithm
 * @param data Input data to compress
 * @param success Optional pointer to receive success status
 * @return Compressed data as QByteArray
 */
QByteArray deflate(const QByteArray& data, bool* success = nullptr);

/**
 * @brief Decompress data using inflate algorithm
 * @param data Compressed data to decompress
 * @param success Optional pointer to receive success status
 * @return Decompressed data as QByteArray
 */
QByteArray inflate(const QByteArray& data, bool* success = nullptr);

/**
 * @brief Compatibility entry point for maximum-level deflate compression.
 *
 * The implementation may use the zlib fallback when an optional MASM codec
 * is not linked. The function name is retained for source compatibility; it
 * does not guarantee that an assembly implementation is selected.
 *
 * @param data Input data to compress
 * @param success Optional pointer to receive success status
 * @return Compressed data as QByteArray
 */
QByteArray deflate_brutal_masm(const QByteArray& data, bool* success = nullptr);

} // namespace codec