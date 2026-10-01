// ImmutableReceiptAuthority.cpp — RAWRXD_RECEIPT_IMMUTABILITY_AUTHORITY_001
#include "agentmodes/ImmutableReceiptAuthority.h"
#include "agentmodes/RawrCertAuthority.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <windows.h>

namespace fs = std::filesystem;

namespace rawrxd { namespace imreceipt {

namespace {

std::mutex g_mutex;
std::atomic<unsigned long long> g_seq{0};

std::string utcStamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", &tm);
    return buf;
}

std::string digest12(const std::string& sha) {
    return sha.size() >= 12 ? sha.substr(0, 12) : sha;
}

// Create the file exclusively. Returns false when the path already exists or
// cannot be created. CREATE_NEW is the primitive that makes immutability real:
// the open itself fails if anything is already at that path.
bool createNewFile(const std::string& path, const std::string& content) {
    HANDLE h = CreateFileA(path.c_str(),
                           GENERIC_WRITE,
                           0,                       // no sharing
                           nullptr,
                           CREATE_NEW,              // fails if the path exists
                           FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    const char*  data = content.data();
    DWORD        remaining = static_cast<DWORD>(content.size());
    bool         ok = true;
    while (remaining > 0) {
        DWORD written = 0;
        if (!WriteFile(h, data, remaining, &written, nullptr) || written == 0) { ok = false; break; }
        data += written;
        remaining -= written;
    }
    CloseHandle(h);

    if (!ok) { DeleteFileA(path.c_str()); return false; }
    return true;
}

// Reject any value that would escape the receipts tree when used as a path
// element.
//
// `gateName` and the caller-supplied `runId` are concatenated straight into
// `<root>/<gateName>/runs/<runId>.ini`. Neither was validated, so
// commitAs("..\\..\\startup\\evil", ...) wrote outside the receipts directory,
// and the same values were interpolated unescaped into index.jsonl where a
// newline forges additional records.
//
// A gate name and a run id are identifiers, not paths. Restricting them to a
// conservative character set is the whole defence; no legitimate run id needs
// a separator, a dot segment, or a control character.
bool isSafePathElement(const std::string& s, size_t maxLen) {
    if (s.empty() || s.size() > maxLen) return false;
    if (s == "." || s == "..") return false;
    for (char c : s) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

// Escape a value for a single-line JSONL record.
std::string jsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x",
                                  static_cast<unsigned>(static_cast<unsigned char>(c)));
                    o += buf;
                } else {
                    o += c;
                }
        }
    }
    return o;
}

} // namespace

ImmutableReceipt::ImmutableReceipt(std::string gateName, std::string root)
    : gateName_(std::move(gateName)), root_(std::move(root)) {}

void ImmutableReceipt::set(const std::string& key, const std::string& value) {
    for (auto& kv : fields_) {
        if (kv.first == key) { kv.second = value; return; }
    }
    fields_.emplace_back(key, value);
}

void ImmutableReceipt::setInt(const std::string& key, int64_t value) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%lld", static_cast<long long>(value));
    set(key, buf);
}

void ImmutableReceipt::setFloat(const std::string& key, double value) {
    char buf[40];
    std::snprintf(buf, sizeof buf, "%.6f", value);
    set(key, buf);
}

bool ImmutableReceipt::has(const std::string& key) const {
    for (const auto& kv : fields_) if (kv.first == key) return true;
    return false;
}

std::string ImmutableReceipt::get(const std::string& key) const {
    for (const auto& kv : fields_) if (kv.first == key) return kv.second;
    return std::string();
}

std::string ImmutableReceipt::serialize() const {
    std::ostringstream os;
    for (const auto& kv : fields_) os << kv.first << "=" << kv.second << "\n";
    return os.str();
}

std::string ImmutableReceipt::runDir(const std::string& gateName, const std::string& root) {
    return (fs::path(root) / gateName / "runs").string();
}
std::string ImmutableReceipt::latestPath(const std::string& gateName, const std::string& root) {
    return (fs::path(root) / gateName / "latest.txt").string();
}
std::string ImmutableReceipt::indexPath(const std::string& gateName, const std::string& root) {
    return (fs::path(root) / gateName / "index.jsonl").string();
}

ReceiptRun ImmutableReceipt::commit(const std::string& verdict) {
    return commitAs(std::string(), verdict);   // run id derived by the writer
}

ReceiptRun ImmutableReceipt::writeLocked(const std::string& runIdIn, const std::string& verdict) {
    std::lock_guard<std::mutex> lock(g_mutex);

    // The body is built before the run id so the id can be derived from the
    // content. A monotonic sequence is included because timestamp+pid alone
    // collides when a gate legitimately runs twice in the same second, and a
    // collision must not be reported as "evidence already exists".
    std::ostringstream body;
    body << "GATE=" << gateName_ << "\n";
    for (const auto& kv : fields_) body << kv.first << "=" << kv.second << "\n";
    body << "VERDICT=" << verdict << "\n";
    const std::string bodyText = body.str();

    const std::string bodySha = cert::sha256Bytes(bodyText.data(), bodyText.size());
    const unsigned long long seq = ++g_seq;
    const std::string runId = runIdIn.empty()
        ? (utcStamp() + "_pid" + std::to_string(_getpid()) + "_s" +
           std::to_string(seq) + "_" + digest12(bodySha))
        : runIdIn;

    ReceiptRun r;
    // Identity validation happens before any path is built. A rejected value
    // produces a failed ReceiptRun with a reason, never a write outside the
    // receipts tree.
    if (!isSafePathElement(gateName_, 128)) {
        r.gateName = gateName_;
        r.error = "gate name rejected: must be 1-128 chars of [A-Za-z0-9_.-]";
        return r;
    }
    if (!isSafePathElement(runId, 200)) {
        r.gateName = gateName_;
        r.runId    = runId;
        r.error    = "run id rejected: must be 1-200 chars of [A-Za-z0-9_.-]";
        return r;
    }

    r.gateName   = gateName_;
    r.runId      = runId;
    r.verdict    = verdict;
    r.runPath    = (fs::path(runDir(gateName_, root_)) / (runId + ".ini")).string();
    r.latestPath = latestPath(gateName_, root_);
    r.indexPath  = indexPath(gateName_, root_);

    std::error_code ec;
    fs::create_directories(fs::path(r.runPath).parent_path(), ec);
    if (ec) { r.error = "cannot create run directory: " + ec.message(); return r; }

    const std::string content = "RUN_ID=" + runId + "\n" + bodyText;
    r.sha256 = cert::sha256Bytes(content.data(), content.size());

    // Refuse to touch an existing artifact. This is the whole point.
    const bool alreadyThere = fs::exists(r.runPath, ec);
    if (alreadyThere) {
        r.preexisted = true;
        r.error = "run receipt already exists; refusing to overwrite evidence";
        return r;
    }
    if (!createNewFile(r.runPath, content)) {
        r.preexisted = fs::exists(r.runPath, ec);
        r.error = "exclusive create failed";
        return r;
    }
    r.success = true;

    // The latest pointer is explicitly allowed to be mutable.
    {
        FILE* f = nullptr;
        if (fopen_s(&f, r.latestPath.c_str(), "w") == 0 && f) {
            std::fprintf(f, "%s\n", r.runId.c_str());
            std::fclose(f);
            r.latestUpdated = true;
        }
    }

    // The index is append-only. Values are JSON-escaped: a run id or verdict
    // containing a quote or a newline would otherwise close the string early or
    // terminate the record early, forging an extra line in the index.
    {
        FILE* f = nullptr;
        if (fopen_s(&f, r.indexPath.c_str(), "a") == 0 && f) {
            std::fprintf(f,
                "{\"run_id\":\"%s\",\"sha256\":\"%s\",\"verdict\":\"%s\"}\n",
                jsonEscape(r.runId).c_str(), jsonEscape(r.sha256).c_str(),
                jsonEscape(verdict).c_str());
            std::fclose(f);
            r.indexAppended = true;
        }
    }
    return r;
}

ReceiptRun ImmutableReceipt::commitAs(const std::string& runId, const std::string& verdict) {
    return writeLocked(runId, verdict);
}

}} // namespace rawrxd::imreceipt
