// Source management for the RawrXD native compiler.
//
// Owns every source file the compiler touches, maps byte offsets to
// line/column, and keeps an include stack so diagnostics can print the
// full include chain.

#ifndef RAWR_COMPILER_SOURCE_MANAGER_H
#define RAWR_COMPILER_SOURCE_MANAGER_H

#include "rawrstd/string.h"
#include "common/Types.h"
#include "rawrstd/vector.h"

namespace rawr {

// A position inside a source file.
struct SourceLoc {
    uint32 file_id = 0;     // 0 = invalid
    uint32 line = 0;        // 1-based
    uint32 column = 0;      // 1-based, in bytes
    uint32 offset = 0;      // byte offset into the file

    bool valid() const { return file_id != 0; }
};

// One buffer of source text plus its line table.
struct SourceFile {
    uint32 id = 0;
    rawrstd::String path;         // path as opened
    rawrstd::String contents;     // full text
    rawrstd::Vector<uint32> line_starts;  // byte offset of each line start
    bool is_system = false;       // found via a <> include
};

class SourceManager {
public:
    SourceManager() = default;

    // Reads a file from disk. Returns false and reports via `error` on failure.
    bool load_file(const char* path, bool is_system, uint32* out_id, rawrstd::String* error);

    // Registers an in-memory buffer (used for command-line -D blobs and for
    // the synthesized stdlib preamble).
    uint32 add_buffer(const char* path, const char* text, size_type length);

    // Adds an include-directory search path.
    void add_include_dir(const char* dir) { include_dirs_.push_back(dir); }

    // Resolves an include. `is_system` selects the <> search list.
    // Returns the resolved path, or an empty string when not found.
    rawrstd::String resolve_include(const char* name, bool is_system) const;

    const SourceFile& file(uint32 id) const { return files_[id - 1]; }
    uint32 file_count() const { return static_cast<uint32>(files_.size()); }

    // Maps a byte offset to a line/column.
    void locate(uint32 file_id, uint32 offset, uint32* out_line, uint32* out_column) const;

    // Returns the text of the given line (without the newline).
    rawrstd::String line_text(uint32 file_id, uint32 line) const;

    const rawrstd::Vector<rawrstd::String>& include_dirs() const { return include_dirs_; }

    // Path helpers.
    static rawrstd::String join_path(const char* dir, const char* name);
    static rawrstd::String parent_dir(const char* path);
    static rawrstd::String file_name(const char* path);
    static bool file_exists(const char* path);
    static rawrstd::String normalize_slashes(const char* path);

private:
    void compute_line_starts(SourceFile& f);

    rawrstd::Vector<SourceFile> files_;
    rawrstd::Vector<rawrstd::String> include_dirs_;
};

} // namespace rawr

#endif // RAWR_COMPILER_SOURCE_MANAGER_H
