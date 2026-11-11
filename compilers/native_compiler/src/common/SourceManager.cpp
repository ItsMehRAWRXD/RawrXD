#include "common/SourceManager.h"

#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;

void SourceManager::compute_line_starts(SourceFile& f) {
    f.line_starts.clear();
    f.line_starts.push_back(0);
    const char* data = f.contents.data();
    size_type n = f.contents.size();
    for (size_type i = 0; i < n; ++i) {
        if (data[i] == '\n') {
            f.line_starts.push_back(static_cast<uint32>(i + 1));
        }
    }
}

bool SourceManager::load_file(const char* path, bool is_system, uint32* out_id, String* error) {
    rawrstd::File f;
    if (!f.open(path, rawrstd::FileMode::Read)) {
        if (error) *error = String("cannot open source file: ") + path;
        return false;
    }

    // Read the whole file.
    String text;
    char buffer[65536];
    for (;;) {
        int64 got = f.read(buffer, sizeof(buffer));
        if (got <= 0) break;
        text.append(buffer, static_cast<size_type>(got));
    }
    f.close();

    SourceFile sf;
    sf.id = static_cast<uint32>(files_.size()) + 1;
    sf.path = normalize_slashes(path);
    sf.contents = static_cast<String&&>(text);
    sf.is_system = is_system;
    compute_line_starts(sf);

    files_.push_back(static_cast<SourceFile&&>(sf));
    *out_id = files_.back().id;
    return true;
}

uint32 SourceManager::add_buffer(const char* path, const char* text, size_type length) {
    SourceFile sf;
    sf.id = static_cast<uint32>(files_.size()) + 1;
    sf.path = normalize_slashes(path);
    sf.contents.assign(text, length);
    sf.is_system = false;
    compute_line_starts(sf);
    files_.push_back(static_cast<SourceFile&&>(sf));
    return files_.back().id;
}

String SourceManager::resolve_include(const char* name, bool is_system) const {
    // Absolute path wins outright.
    if (name[0] == '/' || (name[0] && name[1] == ':')) {
        if (file_exists(name)) return normalize_slashes(name);
        return String();
    }

    for (size_type i = 0; i < include_dirs_.size(); ++i) {
        if (is_system && !include_dirs_[i].starts_with("<builtin>")) {
            // Non-system dirs are still searched for <> includes as a
            // fallback, but the builtin list is tried first.
        }
        String candidate = join_path(include_dirs_[i].data(), name);
        if (file_exists(candidate.data())) return candidate;
    }
    return String();
}

void SourceManager::locate(uint32 file_id, uint32 offset, uint32* out_line, uint32* out_column) const {
    *out_line = 1;
    *out_column = 1;
    if (file_id == 0 || file_id > files_.size()) return;

    const SourceFile& f = files_[file_id - 1];
    if (offset > f.contents.size()) offset = static_cast<uint32>(f.contents.size());

    // Binary search the line table.
    size_type lo = 0, hi = f.line_starts.size();
    while (lo + 1 < hi) {
        size_type mid = lo + (hi - lo) / 2;
        if (f.line_starts[mid] <= offset) lo = mid;
        else hi = mid;
    }
    *out_line = static_cast<uint32>(lo + 1);
    *out_column = offset - f.line_starts[lo] + 1;
}

String SourceManager::line_text(uint32 file_id, uint32 line) const {
    if (file_id == 0 || file_id > files_.size()) return String();
    const SourceFile& f = files_[file_id - 1];
    if (line == 0 || line > f.line_starts.size()) return String();

    size_type start = f.line_starts[line - 1];
    size_type end = (line < f.line_starts.size()) ? f.line_starts[line] : f.contents.size();
    while (end > start && (f.contents[end - 1] == '\n' || f.contents[end - 1] == '\r')) --end;
    return String(f.contents.data() + start, end - start);
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

String SourceManager::join_path(const char* dir, const char* name) {
    String r;
    r.assign(dir);
    size_type n = r.size();
    if (n > 0 && r[n - 1] != '/' && r[n - 1] != '\\') {
        r.push_back('/');
    }
    r.append(name);
    return r;
}

String SourceManager::parent_dir(const char* path) {
    String p;
    p.assign(path);
    for (size_type i = p.size(); i > 0; --i) {
        char c = p[i - 1];
        if (c == '/' || c == '\\') {
            return String(p.data(), i - 1);
        }
    }
    return String();
}

String SourceManager::file_name(const char* path) {
    String p;
    p.assign(path);
    for (size_type i = p.size(); i > 0; --i) {
        char c = p[i - 1];
        if (c == '/' || c == '\\') {
            return String(p.data() + i, p.size() - i);
        }
    }
    return p;
}

bool SourceManager::file_exists(const char* path) {
    rawrstd::File f;
    bool ok = f.open(path, rawrstd::FileMode::Read);
    if (ok) f.close();
    return ok;
}

String SourceManager::normalize_slashes(const char* path) {
    String r;
    r.assign(path);
    for (size_type i = 0; i < r.size(); ++i) {
        if (r[i] == '\\') r[i] = '/';
    }
    return r;
}

} // namespace rawr
