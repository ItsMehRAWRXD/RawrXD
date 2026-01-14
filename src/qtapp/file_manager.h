/**
 * @file file_manager.h
 * @brief File management utilities and search result structures for RawrXD IDE.
 *
 * This header provides:
 * - MultiFileSearchResult: Value type representing a single search match
 * - FileManager: Static utility class for file I/O and path manipulation
 *
 * @note Thread Safety: FileManager methods are stateless and thread-safe.
 *       MultiFileSearchResult is a value type safe for concurrent access.
 *
 * @author RawrXD IDE Team
 * @version 2.0.0
 * @date 2025
 *
 * @copyright MIT License
 */
#pragma once

#include <QString>
#include <QFile>
#include <QTextStream>
#include <QFileInfo>
#include <QDir>


/**
 * @class FileManager
 * @brief Static utility class providing file I/O and path manipulation.
 *
 * All methods are static and stateless, making them safe for concurrent use
 * from multiple threads without synchronization.
 *
 * @par Thread Safety:
 * All methods are thread-safe (stateless).
 *
 * @par Usage Example:
 * @code
 * QString content = FileManager::readFile("/path/to/file.cpp");
 * QString relative = FileManager::toRelativePath("/project/src/main.cpp", "/project");
 * @endcode
 */
class FileManager {
public:
    /**
     * @brief Reads the entire contents of a text file.
     * @param filePath Absolute or relative path to the file
     * @return File contents as QString, or empty string on error
     *
     * @note Uses QFile with ReadOnly | Text mode for proper line ending handling.
     * @warning Returns empty string for both empty files and read errors.
     *          Check QFile::exists() first if distinction is needed.
     */
    static QString readFile(const QString& filePath) {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
            return QString();
        }
        QTextStream stream(&file);
        return stream.readAll();
    }

    /**
     * @brief Converts an absolute path to a path relative to a base directory.
     * @param absolutePath The absolute file path to convert
     * @param basePath The base directory for relative path calculation
     * @return Relative path string, or original path if conversion fails
     *
     * @par Example:
     * @code
     * QString rel = FileManager::toRelativePath("/home/user/project/src/main.cpp", "/home/user/project");
     * // Returns: "src/main.cpp"
     * @endcode
     */
    static QString toRelativePath(const QString& absolutePath, const QString& basePath) {
        QDir baseDir(basePath);
        return baseDir.relativeFilePath(absolutePath);
    }

    /**
     * @brief Extracts the filename component from a full path.
     * @param filePath Full path to extract filename from
     * @return Filename with extension, without directory components
     */
    static QString getFileName(const QString& filePath) {
        return QFileInfo(filePath).fileName();
    }

    /**
     * @brief Extracts the directory path component from a full path.
     * @param filePath Full path to extract directory from
     * @return Directory path without the filename component
     */
    static QString getDirectory(const QString& filePath) {
        return QFileInfo(filePath).absolutePath();
    }

    /**
     * @brief Checks if a file exists and is readable.
     * @param filePath Path to check
     * @return true if the file exists and can be read
     */
    static bool fileExists(const QString& filePath) {
        QFileInfo info(filePath);
        return info.exists() && info.isReadable();
    }
};
