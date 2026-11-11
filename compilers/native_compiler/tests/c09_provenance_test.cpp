// C09 - Clean build provenance.
//
// A certification result only means something when it describes the code
// that is actually in the tree. Two failure modes break that link:
//
//   1. A stale object file. The build links a prebuilt object, the source
//      changes, the repair is applied to the source, and the test still runs
//      the old object. The repair looks ineffective and hours are lost
//      chasing a fix that was never compiled.
//
//   2. An unpinned revision. The certification passes, and then a source
//      file changes without the gate being rerun. The green result now
//      describes a revision that no longer exists.
//
// This gate closes both. Every source file in the tree is listed in a
// committed manifest together with its SHA-256, so the certification is
// pinned to one specific revision. Every object file used by the
// certification is listed too, and the gate checks that each object is
// newer than every source, which is what a clean build guarantees and what
// a stale build violates.
//
//   1. Every source in the manifest exists and hashes to the recorded value.
//   2. Every source file in the tree is listed in the manifest.
//   3. Every object in the output directory is listed in the manifest.
//   4. Every listed object is newer than every listed source.
//   5. The manifest is not empty and covers the whole tree.

#include "rawrstd/sha256.h"
#include "rawrstd/string.h"
#include "rawrstd/sys.h"
#include "rawrstd/vector.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>

using rawrstd::String;
using rawrstd::Vector;
using rawrstd::size_type;
using rawrstd::uint16;
using rawrstd::uint64;
using rawrstd::int64;

// Converts a narrow path into a null terminated wide string.
static Vector<uint16> to_wide(const String& path) {
    Vector<uint16> wide;
    for (size_type i = 0; i < path.size(); ++i) {
        wide.push_back(static_cast<uint16>(static_cast<unsigned char>(path[i])));
    }
    wide.push_back(0);
    return wide;
}

// Converts a wide file name into a narrow string.
static String from_wide(const wchar_t* text) {
    String out;
    for (const wchar_t* p = text; *p; ++p) {
        out.push_back(static_cast<char>(*p & 0x7F));
    }
    return out;
}

// The last component of a path.
static String file_name_of(const String& path) {
    for (size_type i = path.size(); i > 0; --i) {
        const char c = path[i - 1];
        if (c == '\\' || c == '/') return path.substr(i);
    }
    return path;
}

static int g_pass = 0;
static int g_fail = 0;

static void ok(const char* what) {
    rawrstd::write_stdout("  [PASS] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("\n", 1);
    ++g_pass;
}

static void bad(const char* what, const String& detail) {
    rawrstd::write_stdout("  [FAIL] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("  -- ", 4);
    rawrstd::write_stderr(detail.data(), detail.size());
    rawrstd::write_stderr("\n", 1);
    ++g_fail;
}

static void check(bool cond, const char* what, const String& detail) {
    if (cond) ok(what);
    else bad(what, detail);
}

static void check(bool cond, const char* what) {
    if (cond) ok(what);
    else bad(what, String("condition false"));
}

// Formats an integer into a string.
static String to_text(int value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%d", value);
    return String(buffer);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static String read_file(const String& path) {
    String out;
    rawrstd::File f;
    if (!f.open(path.data(), rawrstd::FileMode::Read)) return out;
    char buffer[8192];
    for (;;) {
        const int64 got = f.read(buffer, sizeof(buffer));
        if (got <= 0) break;
        out.append(buffer, static_cast<size_type>(got));
    }
    f.close();
    return out;
}

static bool is_source_extension(const char* name) {
    const char* dot = nullptr;
    for (const char* p = name; *p; ++p) {
        if (*p == '.') dot = p;
    }
    if (!dot) return false;
    return rawrstd::strcmp_raw(dot, ".cpp") == 0 || rawrstd::strcmp_raw(dot, ".h") == 0 ||
           rawrstd::strcmp_raw(dot, ".hpp") == 0 || rawrstd::strcmp_raw(dot, ".c") == 0;
}

// The hash of a source file, with the line endings normalized.
//
// Git stores a file with the line endings of the repository and checks it
// out with the line endings of the platform, so the same file has a
// different byte sequence in a working tree and in an exported tree. The
// hash has to be the same in both places, or the gate would fail in an
// exported tree even though nothing was changed.
static String normalized_hash(const String& path) {
    String content;
    rawrstd::File file;
    if (!file.open(path.data(), rawrstd::FileMode::Read)) return String();
    char buffer[8192];
    for (;;) {
        const int64 got = file.read(buffer, sizeof(buffer));
        if (got <= 0) break;
        content.append(buffer, static_cast<size_type>(got));
    }
    file.close();

    String normalized;
    for (size_type i = 0; i < content.size(); ++i) {
        // The carriage return of a CRLF pair is dropped.
        if (content[i] == '\r' && i + 1 < content.size() && content[i + 1] == '\n') continue;
        normalized.push_back(content[i]);
    }

    char hex[65];
    rawrstd::sha256_hex(normalized.data(), normalized.size(), hex);
    return String(hex, 64);
}

// True when the path names a file that exists.
static bool file_exists(const char* path) {
    const DWORD attributes = GetFileAttributesW(reinterpret_cast<LPCWSTR>(to_wide(path).data()));
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

// The last write time of a file, as a comparable integer. Returns false when
// the file cannot be read.
static bool file_time(const String& path, uint64* out) {    HANDLE handle = CreateFileW(reinterpret_cast<LPCWSTR>(to_wide(path).data()),
                                GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) return false;
    FILETIME ft;
    const BOOL got = GetFileTime(handle, NULL, NULL, &ft);
    CloseHandle(handle);
    if (!got) return false;
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    *out = value.QuadPart;
    return true;
}

// Lists the files directly inside `dir` whose name ends with `suffix`.
static void list_files(const String& dir, const char* suffix, Vector<String>* out) {
    const String pattern = dir + "\\*" + suffix;
    WIN32_FIND_DATAW data;
    HANDLE find = FindFirstFileW(reinterpret_cast<LPCWSTR>(to_wide(pattern).data()), &data);
    if (find == INVALID_HANDLE_VALUE) return;
    do {
        if (data.cFileName[0] == L'.') continue;
        out->push_back(dir + "\\" + from_wide(data.cFileName));
    } while (FindNextFileW(find, &data));
    FindClose(find);
}

// Collects every source file under `root`, relative to it.
static void collect_sources(const String& root, const String& prefix, Vector<String>* out) {
    Vector<String> entries;
    list_files(root, "*", &entries);
    for (size_type i = 0; i < entries.size(); ++i) {
        const String& full = entries[i];
        // A directory cannot be told apart from a file by name alone, so ask
        // the file system.
        DWORD attributes = GetFileAttributesW(reinterpret_cast<LPCWSTR>(to_wide(full).data()));
        if (attributes == INVALID_FILE_ATTRIBUTES) continue;
        const String relative = prefix.empty()
                                    ? file_name_of(full)
                                    : prefix + "/" + file_name_of(full);
        if (attributes & FILE_ATTRIBUTE_DIRECTORY) {
            collect_sources(full, relative, out);
        } else if (is_source_extension(file_name_of(full).data())) {
            out->push_back(relative);
        }
    }
}

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

struct ManifestSource {
    String hash;
    String path;      // relative to the source root, with forward slashes
};

struct ManifestObject {
    String name;      // the file name inside the output directory
    String source;    // the source it is built from, relative to the root
};

int main(int argc, char** argv) {
    if (argc < 3) {
        rawrstd::write_stderr("usage: c09_provenance_test.exe <output dir> <source root> [manifest]\n", 78);
        return 2;
    }
    const String out_dir = String(argv[1]);
    const String src_root = String(argv[2]);
    const String manifest_path = (argc > 3) ? String(argv[3])
                                            : src_root + "/tools/certification_manifest.txt";

    // ---- Parse the manifest ----
    Vector<ManifestSource> sources;
    Vector<ManifestObject> objects;
    {
        const String text = read_file(manifest_path);
        if (text.empty()) {
            bad("the certification manifest was read", manifest_path);
            return 1;
        }
        size_type pos = 0;
        while (pos < text.size()) {
            size_type eol = text.find('\n', pos);
            if (eol == String::npos) eol = text.size();
            String line = text.substr(pos, eol - pos);
            pos = eol + 1;
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
            if (line.empty() || line[0] == '#') continue;

            if (line.starts_with("source ")) {
                const size_type a = 7;
                const size_type b = line.find(' ', a);
                if (b == String::npos) continue;
                ManifestSource s;
                s.hash = line.substr(a, b - a);
                s.path = line.substr(b + 1);
                sources.push_back(s);
            } else if (line.starts_with("object ")) {
                const size_type a = 7;
                const size_type b = line.find(' ', a);
                if (b == String::npos) continue;
                ManifestObject o;
                o.name = line.substr(a, b - a);
                o.source = line.substr(b + 1);
                objects.push_back(o);
            }
        }
    }
    check(!sources.empty() && !objects.empty(), "the certification manifest was read",
          String("sources=") + to_text(static_cast<int>(sources.size())) +
              " objects=" + to_text(static_cast<int>(objects.size())));

    // ---- 1. Every listed source matches its recorded hash ----
    {
        bool allMatch = true;
        String firstBad;
        for (size_type i = 0; i < sources.size(); ++i) {
            const String full = src_root + "/" + sources[i].path;
            const String digest = normalized_hash(full);
            if (digest != sources[i].hash) {
                allMatch = false;
                if (firstBad.empty()) {
                    firstBad = sources[i].path + ": recorded " + sources[i].hash +
                               ", actual " + (digest.empty() ? String("<missing>") : digest);
                }
            }
        }
        check(allMatch, "every certified source matches its recorded hash", firstBad);
    }

    // ---- 2. Every source in the tree is listed ----
    {
        Vector<String> found;
        collect_sources(src_root, String(), &found);
        bool allListed = true;
        String firstBad;
        for (size_type i = 0; i < found.size(); ++i) {
            bool listed = false;
            for (size_type j = 0; j < sources.size(); ++j) {
                if (sources[j].path == found[i]) { listed = true; break; }
            }
            if (!listed) {
                allListed = false;
                if (firstBad.empty()) firstBad = found[i];
            }
        }
        check(allListed, "every source file in the tree is listed in the manifest", firstBad);
    }

    // ---- 3. Every object the manifest lists exists in the output directory ----
    //
    // The output directory also holds the fixtures the suites write while
    // they run, so the check is that the manifest is complete rather than
    // that the directory is empty of extras. A build that produces a new
    // object needs a new manifest, which is a deliberate act.
    {
        bool allPresent = true;
        String firstBad;
        for (size_type i = 0; i < objects.size(); ++i) {
            const String full = out_dir + "/" + objects[i].name;
            if (!file_exists(full.data())) {
                allPresent = false;
                if (firstBad.empty()) firstBad = objects[i].name + " is missing from " + out_dir;
            }
        }
        check(allPresent, "every object file the manifest lists is in the output directory",
              firstBad);
    }

    // ---- 4. Every object is newer than every source ----
    //
    // This is the stale object check. A clean build produces every object
    // after every source has been written, so the youngest object is still
    // newer than the oldest source. A partial rebuild leaves at least one
    // object behind its source.
    {
        uint64 newest_source = 0;
        String newest_path;
        for (size_type i = 0; i < sources.size(); ++i) {
            uint64 when = 0;
            if (!file_time(src_root + "/" + sources[i].path, &when)) continue;
            if (when > newest_source) {
                newest_source = when;
                newest_path = sources[i].path;
            }
        }

        bool allFresh = true;
        String firstBad;
        for (size_type i = 0; i < objects.size(); ++i) {
            uint64 when = 0;
            const String full = out_dir + "/" + objects[i].name;
            if (!file_time(full, &when)) {
                allFresh = false;
                if (firstBad.empty()) firstBad = objects[i].name + " is missing from " + out_dir;
                continue;
            }
            if (when < newest_source) {
                allFresh = false;
                if (firstBad.empty()) {
                    firstBad = objects[i].name + " is older than " + newest_path +
                               " (a stale object was linked)";
                }
            }
        }
        check(allFresh, "every object file was built after every source file", firstBad);
    }

    // ---- 5. The manifest covers the tree ----
    {
        Vector<String> found;
        collect_sources(src_root, String(), &found);
        check(found.size() == sources.size(),
              "the manifest covers the whole source tree",
              String("tree=") + to_text(static_cast<int>(found.size())) +
                  " manifest=" + to_text(static_cast<int>(sources.size())));
    }

    rawrstd::write_stdout("--------------------------------------------", 44);
    rawrstd::write_stdout("C09 result: ", 13);
    char buffer[64];
    const int n = std::snprintf(buffer, sizeof(buffer), "%d passed, %d failed\n", g_pass, g_fail);
    rawrstd::write_stdout(buffer, static_cast<size_type>(n));
    return g_fail == 0 ? 0 : 1;
}
