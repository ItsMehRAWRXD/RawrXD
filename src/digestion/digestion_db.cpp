<<<<<<< HEAD
// ============================================================================
// digestion_db.cpp — Digestion Database Implementation (SQLite3 C API, no Qt)
// ============================================================================
#include "digestion_db.h"

#include <sqlite3.h>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdio>

DigestionDatabase::DigestionDatabase() {}

DigestionDatabase::~DigestionDatabase() {
    close();
}

bool DigestionDatabase::isOpen() const {
    return m_db != nullptr;
}

void DigestionDatabase::close() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

bool DigestionDatabase::open(const std::string &path, std::string *error) {
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_db) {
        sqlite3_close(m_db);
        m_db = nullptr;
    }

    int rc = sqlite3_open(path.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        if (error) {
            const char* msg = sqlite3_errmsg(m_db);
            *error = msg ? msg : "unknown sqlite error";
        }
        sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }

    // Enable WAL + foreign keys
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(m_db, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
=======
#include "digestion_db.h"
#include <fstream>
#include <iostream>
#include <ctime>

DigestionDatabase::DigestionDatabase() {}

bool DigestionDatabase::open(const std::string &path, std::string *error) {
    m_dbPath = path;
    // ensure file exists
    std::ifstream f(m_dbPath);
    if (!f.good()) {
        json root = {{"runs", json::array()}};
        return saveDb(root);
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    return true;
}

bool DigestionDatabase::ensureSchema(const std::string &schemaPath, std::string *error) {
<<<<<<< HEAD
    std::string schemaSql;
    if (!schemaPath.empty()) {
        std::ifstream ifs(schemaPath);
        if (ifs.is_open()) {
            schemaSql.assign(std::istreambuf_iterator<char>(ifs),
                             std::istreambuf_iterator<char>());
        }
    }
    if (schemaSql.empty()) schemaSql = defaultSchema();

    // Split by semicolons
    std::vector<std::string> statements;
    std::istringstream iss(schemaSql);
    std::string chunk;
    while (std::getline(iss, chunk, ';')) {
        // Trim
        size_t start = chunk.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        size_t end = chunk.find_last_not_of(" \t\r\n");
        std::string stmt = chunk.substr(start, end - start + 1);
        if (!stmt.empty()) statements.push_back(std::move(stmt));
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) {
        if (error) *error = "Database not open";
        return false;
    }

    char* errmsg = nullptr;
    sqlite3_exec(m_db, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);

    bool ok = executeBatch(statements, error);

    if (ok) {
        sqlite3_exec(m_db, "COMMIT;", nullptr, nullptr, &errmsg);
        sqlite3_free(errmsg);
    } else {
        sqlite3_exec(m_db, "ROLLBACK;", nullptr, nullptr, nullptr);
    }
    return ok;
}

bool DigestionDatabase::insertRun(const std::string &rootDir, const DigestionMetrics &metrics,
                                   const std::string &reportJson, int *runId, std::string *error)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) {
        if (error) *error = "Database not open";
        return false;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO digestion_runs "
        "(root_dir, start_ms, end_ms, elapsed_ms, total_files, scanned_files, "
        "stubs_found, fixes_applied, bytes_processed) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }

    sqlite3_bind_text(stmt, 1, rootDir.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, metrics.startMs);
    sqlite3_bind_int64(stmt, 3, metrics.endMs);
    sqlite3_bind_int64(stmt, 4, metrics.elapsedMs);
    sqlite3_bind_int(stmt, 5, metrics.totalFiles);
    sqlite3_bind_int(stmt, 6, metrics.scannedFiles);
    sqlite3_bind_int(stmt, 7, metrics.stubsFound);
    sqlite3_bind_int(stmt, 8, metrics.fixesApplied);
    sqlite3_bind_int64(stmt, 9, metrics.bytesProcessed);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }

    int id = static_cast<int>(sqlite3_last_insert_rowid(m_db));
    if (runId) *runId = id;

    // Insert report if provided
    if (!reportJson.empty()) {
        sqlite3_stmt* rptStmt = nullptr;
        if (sqlite3_prepare_v2(m_db,
                "INSERT INTO digestion_reports (run_id, report_json) VALUES (?, ?)",
                -1, &rptStmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(rptStmt, 1, id);
            sqlite3_bind_text(rptStmt, 2, reportJson.c_str(), -1, SQLITE_TRANSIENT);
            if (sqlite3_step(rptStmt) != SQLITE_DONE && error) {
                *error = sqlite3_errmsg(m_db);
            }
            sqlite3_finalize(rptStmt);
        }
    }

    return true;
}

bool DigestionDatabase::insertFileResult(int runId, const DigestionFileObj &fileObj, std::string *error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) {
        if (error) *error = "Database not open";
        return false;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO digestion_files "
        "(run_id, path, language, size_bytes, stubs_found, hash) "
        "VALUES (?, ?, ?, ?, ?, ?)";

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }

    sqlite3_bind_int(stmt, 1, runId);
    sqlite3_bind_text(stmt, 2, fileObj.file.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, fileObj.language.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, fileObj.sizeBytes);
    sqlite3_bind_int(stmt, 5, fileObj.stubsFound);
    sqlite3_bind_text(stmt, 6, fileObj.hash.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }

    return true;
}

bool DigestionDatabase::insertTask(int fileId, const DigestionTaskObj &taskObj, std::string *error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) {
        if (error) *error = "Database not open";
        return false;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT INTO digestion_tasks "
        "(file_id, line_number, stub_type, context, suggested_fix, confidence, applied, backup_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)";

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }

    sqlite3_bind_int(stmt, 1, fileId);
    sqlite3_bind_int(stmt, 2, taskObj.line);
    sqlite3_bind_text(stmt, 3, taskObj.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, taskObj.context.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, taskObj.suggestedFix.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, taskObj.confidence.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, taskObj.applied ? 1 : 0);
    sqlite3_bind_text(stmt, 8, taskObj.backupId.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }
    return true;
}

std::vector<DigestionRunRow> DigestionDatabase::fetchRecentRuns(int limit, std::string *error) const {
    std::vector<DigestionRunRow> runs;
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_db) {
        if (error) *error = "Database not open";
        return runs;
    }

    sqlite3_stmt* stmt = nullptr;
    const char* sql =
        "SELECT id, root_dir, start_ms, end_ms, elapsed_ms, total_files, scanned_files, "
        "stubs_found, fixes_applied, bytes_processed, created_at "
        "FROM digestion_runs ORDER BY id DESC LIMIT ?";

    if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        if (error) *error = sqlite3_errmsg(m_db);
        return runs;
    }

    sqlite3_bind_int(stmt, 1, limit);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        DigestionRunRow row{};
        row.id = sqlite3_column_int(stmt, 0);
        const char* rd = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        row.rootDir = rd ? rd : "";
        row.startMs = sqlite3_column_int64(stmt, 2);
        row.endMs = sqlite3_column_int64(stmt, 3);
        row.elapsedMs = sqlite3_column_int64(stmt, 4);
        row.totalFiles = sqlite3_column_int(stmt, 5);
        row.scannedFiles = sqlite3_column_int(stmt, 6);
        row.stubsFound = sqlite3_column_int(stmt, 7);
        row.fixesApplied = sqlite3_column_int(stmt, 8);
        row.bytesProcessed = sqlite3_column_int64(stmt, 9);
        const char* ca = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 10));
        row.createdAt = ca ? ca : "";
        runs.push_back(std::move(row));
    }
    sqlite3_finalize(stmt);
    return runs;
=======
    // For JSON store, schema is implicit structure.
    // Use this to validate or migrate if needed.
    return true; 
}

bool DigestionDatabase::insertRun(const std::string &rootDir, const DigestionMetrics &metrics, const json& report, int *runId, std::string *error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    try {
        json db = loadDb();
        if (!db.contains("runs")) db["runs"] = json::array();

        int nextId = 1;
        if (!db["runs"].empty()) {
            nextId = db["runs"].back()["id"].get<int>() + 1;
        }

        json run = {
            {"id", nextId},
            {"rootDir", rootDir},
            {"timestamp", std::time(nullptr)},
            {"metrics", {
                {"startMs", metrics.startMs},
                {"endMs", metrics.endMs},
                {"elapsedMs", metrics.elapsedMs},
                {"totalFiles", metrics.totalFiles},
                {"scannedFiles", metrics.scannedFiles},
                {"stubsFound", metrics.stubsFound},
                {"fixesApplied", metrics.fixesApplied},
                {"bytesProcessed", metrics.bytesProcessed}
            }},
            {"report", report},
            {"file_results", json::array()}
        };

        db["runs"].push_back(run);
        if (runId) *runId = nextId;

        return saveDb(db);
    } catch (const std::exception& e) {
        if (error) *error = e.what();
        return false;
    }
}

bool DigestionDatabase::insertFileResult(int runId, const json& fileObj, std::string *error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    try {
        json db = loadDb();
        for (auto& run : db["runs"]) {
            if (run["id"] == runId) {
                if (!run.contains("file_results")) run["file_results"] = json::array();
                run["file_results"].push_back(fileObj);
                return saveDb(db);
            }
        }
        if (error) *error = "Run ID not found";
        return false;
    } catch (const std::exception& e) {
        if (error) *error = e.what();
        return false;
    }
}

std::vector<json> DigestionDatabase::fetchRecentRuns(int limit, std::string *error) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    try {
        json db = loadDb();
        std::vector<json> results;
        if (!db.contains("runs")) return results;
        
        const auto& runs = db["runs"];
        // Iterate backwards for recent
        int count = 0;
        for (auto it = runs.rbegin(); it != runs.rend(); ++it) {
            results.push_back(*it);
            if (++count >= limit) break;
        }
        return results;
    } catch (const std::exception& e) {
        if (error) *error = e.what();
        return {};
    }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

bool DigestionDatabase::deleteRun(int runId, std::string *error) {
    std::lock_guard<std::mutex> lock(m_mutex);
<<<<<<< HEAD
    if (!m_db) {
        if (error) *error = "Database not open";
        return false;
    }

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(m_db, "DELETE FROM digestion_runs WHERE id = ?",
                           -1, &stmt, nullptr) != SQLITE_OK) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }

    sqlite3_bind_int(stmt, 1, runId);
    int rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(m_db);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        if (error) *error = sqlite3_errmsg(m_db);
        return false;
    }
    return changes > 0;
}

std::string DigestionDatabase::defaultSchema() {
    return R"SQL(
=======
    try {
        json db = loadDb();
        if (!db.contains("runs")) return false;
        
        auto& runs = db["runs"];
        runs.erase(std::remove_if(runs.begin(), runs.end(), [runId](const json& j) {
            return j["id"] == runId;
        }), runs.end());
        
        return saveDb(db);
    } catch (const std::exception& e) {
        if (error) *error = e.what();
        return false;
    }
}

std::string DigestionDatabase::defaultSchema() {
    return "{}"; // JSON, no SQL schema
}

json DigestionDatabase::loadDb() const {
    std::ifstream f(m_dbPath);
    if (!f.is_open()) return {{"runs", json::array()}};
    json j;
    f >> j;
    return j;
}

bool DigestionDatabase::saveDb(const json& db) const {
    std::ofstream f(m_dbPath);
    if (!f.is_open()) return false;
    f << db.dump(4);
    return true;
}
        "FROM digestion_runs ORDER BY id DESC LIMIT ?"));
    query.addBindValue(limit);

    if (!query.exec()) {
        if (error) *error = query.lastError().text();
        return runs;
    }

    while (query) {
        void* row;
        row.insert("id", query.value(0));
        row.insert("root_dir", query.value(1).toString());
        row.insert("start_ms", query.value(2).toLongLong());
        row.insert("end_ms", query.value(3).toLongLong());
        row.insert("elapsed_ms", query.value(4).toLongLong());
        row.insert("total_files", query.value(5));
        row.insert("scanned_files", query.value(6));
        row.insert("stubs_found", query.value(7));
        row.insert("fixes_applied", query.value(8));
        row.insert("bytes_processed", query.value(9).toLongLong());
        row.insert("created_at", query.value(10).toString());
        runs.append(row);
    }
    return runs;
}

bool DigestionDatabase::deleteRun(int runId, std::string *error) {
    if (!m_db.isValid()) {
        if (error) *error = std::stringLiteral("Database connection is not open");
        return false;
    }

    QSqlQuery query(m_db);
    query.prepare(std::stringLiteral("DELETE FROM digestion_runs WHERE id = ?"));
    query.addBindValue(runId);
    if (!query.exec()) {
        if (error) *error = query.lastError().text();
        return false;
    }
    return query.numRowsAffected() > 0;
}

bool DigestionDatabase::insertFileResult(int runId, const void* &fileObj, std::string *error) {
    QSqlQuery query(m_db);
    query.prepare("INSERT INTO digestion_files (run_id, path, language, size_bytes, stubs_found, hash) "
                  "VALUES (?, ?, ?, ?, ?, ?)");
    query.addBindValue(runId);
    query.addBindValue(fileObj.value("file").toString());
    query.addBindValue(fileObj.value("language").toString());
    query.addBindValue(fileObj.value("size_bytes").toVariant());
    query.addBindValue(fileObj.value("stubs_found"));
    query.addBindValue(fileObj.value("hash").toString());

    if (!query.exec()) {
        if (error) *error = query.lastError().text();
        return false;
    }

    const int fileId = query.lastInsertId();
    const void* tasks = fileObj.value("tasks").toArray();
    for (const void* &taskVal : tasks) {
        if (!insertTask(fileId, taskVal.toObject(), error)) {
            return false;
        }
    }
    return true;
}

bool DigestionDatabase::insertTask(int fileId, const void* &taskObj, std::string *error) {
    QSqlQuery query(m_db);
    query.prepare("INSERT INTO digestion_tasks (file_id, line_number, stub_type, context, suggested_fix, confidence, applied, backup_id) "
                  "VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    query.addBindValue(fileId);
    query.addBindValue(taskObj.value("line"));
    query.addBindValue(taskObj.value("type").toString());
    query.addBindValue(taskObj.value("context").toString());
    query.addBindValue(taskObj.value("suggested_fix").toString());
    query.addBindValue(taskObj.value("confidence").toString());
    query.addBindValue(taskObj.value("applied").toBool());
    query.addBindValue(taskObj.value("backup_id").toString());

    if (!query.exec()) {
        if (error) *error = query.lastError().text();
        return false;
    }
    return true;
}

std::string DigestionDatabase::defaultSchema() {
    return std::string::fromUtf8(R"SQL(
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
CREATE TABLE IF NOT EXISTS digestion_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    root_dir TEXT NOT NULL,
    start_ms INTEGER,
    end_ms INTEGER,
    elapsed_ms INTEGER,
    total_files INTEGER,
    scanned_files INTEGER,
    stubs_found INTEGER,
    fixes_applied INTEGER,
    bytes_processed INTEGER,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS digestion_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    report_json TEXT,
    FOREIGN KEY(run_id) REFERENCES digestion_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS digestion_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    language TEXT,
    size_bytes INTEGER,
    stubs_found INTEGER,
    hash TEXT,
    FOREIGN KEY(run_id) REFERENCES digestion_runs(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS digestion_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL,
    line_number INTEGER,
    stub_type TEXT,
    context TEXT,
    suggested_fix TEXT,
    confidence TEXT,
    applied INTEGER,
    backup_id TEXT,
    FOREIGN KEY(file_id) REFERENCES digestion_files(id) ON DELETE CASCADE
);
<<<<<<< HEAD
)SQL";
}

bool DigestionDatabase::executeBatch(const std::vector<std::string> &statements, std::string *error) {
    for (const auto &stmt : statements) {
        char* errmsg = nullptr;
        int rc = sqlite3_exec(m_db, stmt.c_str(), nullptr, nullptr, &errmsg);
        if (rc != SQLITE_OK) {
            if (error) *error = errmsg ? errmsg : "unknown error";
            sqlite3_free(errmsg);
            return false;
        }
        sqlite3_free(errmsg);
=======
)SQL");
}

bool DigestionDatabase::executeBatch(const std::stringList &statements, std::string *error) {
    QSqlQuery query(m_db);
    for (const std::string &stmt : statements) {
        if (!query.exec(stmt)) {
            if (error) *error = query.lastError().text();
            return false;
        }
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    }
    return true;
}

