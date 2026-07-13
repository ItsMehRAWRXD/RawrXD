/**
 * sqlite3_stub.cpp
 * 
 * Minimal SQLite stub implementation for Phase C.0 Batch 3/5 testing
 */

#include "sqlite3_stub.h"
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>
#include <algorithm>

// Simple in-memory database implementation
struct sqlite3 {
    std::string name;
    std::map<std::string, std::vector<std::map<std::string, std::string>>> tables;
    std::string lastError;
    int lastErrorCode;
};

struct sqlite3_stmt {
    sqlite3* db;
    std::string sql;
    std::vector<std::map<std::string, std::string>> results;
    size_t currentRow;
    std::vector<std::string> boundValues;
    bool executed;
};

// Global databases for :memory: support
static std::map<std::string, std::unique_ptr<sqlite3>> g_databases;

int sqlite3_open(const char* filename, sqlite3** ppDb) {
    return sqlite3_open_v2(filename, ppDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
}

int sqlite3_open_v2(const char* filename, sqlite3** ppDb, int flags, const char* /*zVfs*/) {
    *ppDb = nullptr;
    
    std::string dbName = filename ? filename : ":memory:";
    
    auto db = std::make_unique<sqlite3>();
    db->name = dbName;
    db->lastErrorCode = SQLITE_OK;
    
    *ppDb = db.get();
    
    if (dbName == ":memory:") {
        // Store in global map for in-memory databases
        g_databases[dbName] = std::move(db);
    } else {
        // For file-based, just keep the pointer
        db.release();
    }
    
    return SQLITE_OK;
}

int sqlite3_close(sqlite3* db) {
    if (!db) return SQLITE_OK;
    
    // Remove from global map if it's an in-memory database
    for (auto it = g_databases.begin(); it != g_databases.end(); ++it) {
        if (it->second.get() == db) {
            g_databases.erase(it);
            return SQLITE_OK;
        }
    }
    
    // Otherwise just delete it
    delete db;
    return SQLITE_OK;
}

int sqlite3_exec(sqlite3* db, const char* sql, int (*callback)(void*, int, char**, char**), void* arg, char** errmsg) {
    (void)callback;
    (void)arg;
    (void)errmsg;
    
    if (!db) return SQLITE_ERROR;
    
    std::string sqlStr(sql);
    
    // Simple CREATE TABLE parsing - extract table name
    if (sqlStr.find("CREATE TABLE") != std::string::npos) {
        size_t start = sqlStr.find("CREATE TABLE") + 12;
        size_t ifNotExists = sqlStr.find("IF NOT EXISTS");
        if (ifNotExists != std::string::npos) {
            start = ifNotExists + 13;
        }
        
        // Extract table name
        while (start < sqlStr.size() && (sqlStr[start] == ' ' || sqlStr[start] == '\n' || sqlStr[start] == '\t')) start++;
        size_t end = sqlStr.find('(', start);
        if (end == std::string::npos) end = sqlStr.size();
        
        std::string tableName = sqlStr.substr(start, end - start);
        // Trim whitespace
        size_t first = tableName.find_first_not_of(" \t\n");
        size_t last = tableName.find_last_not_of(" \t\n");
        if (first != std::string::npos) {
            tableName = tableName.substr(first, last - first + 1);
        }
        
        // Create table if not exists
        if (db->tables.find(tableName) == db->tables.end()) {
            db->tables[tableName] = std::vector<std::map<std::string, std::string>>();
        }
    }
    
    // Simple DELETE parsing
    if (sqlStr.find("DELETE FROM") != std::string::npos) {
        // Just acknowledge for now
    }
    
    // Transaction commands
    if (sqlStr.find("BEGIN") != std::string::npos ||
        sqlStr.find("COMMIT") != std::string::npos ||
        sqlStr.find("ROLLBACK") != std::string::npos) {
        // Just acknowledge
    }
    
    // PRAGMA commands
    if (sqlStr.find("PRAGMA") != std::string::npos) {
        // Just acknowledge
    }
    
    // CREATE INDEX
    if (sqlStr.find("CREATE INDEX") != std::string::npos) {
        // Just acknowledge
    }
    
    return SQLITE_OK;
}

int sqlite3_prepare_v2(sqlite3* db, const char* zSql, int nByte, sqlite3_stmt** ppStmt, const char** pzTail) {
    if (!db || !zSql || !ppStmt) return SQLITE_ERROR;
    
    auto stmt = std::make_unique<sqlite3_stmt>();
    stmt->db = db;
    stmt->sql = (nByte < 0) ? zSql : std::string(zSql, nByte);
    stmt->currentRow = 0;
    stmt->executed = false;
    
    *ppStmt = stmt.release();
    if (pzTail) *pzTail = zSql + strlen(zSql);
    
    return SQLITE_OK;
}

int sqlite3_step(sqlite3_stmt* pStmt) {
    if (!pStmt) return SQLITE_MISUSE;
    
    if (!pStmt->executed) {
        // Parse and execute the SQL
        std::string sql = pStmt->sql;
        
        // Simple INSERT parsing
        if (sql.find("INSERT INTO") != std::string::npos) {
            size_t tableStart = sql.find("INSERT INTO") + 11;
            while (tableStart < sql.size() && sql[tableStart] == ' ') tableStart++;
            size_t tableEnd = sql.find(' ', tableStart);
            if (tableEnd == std::string::npos) {
                // Try to find VALUES
                tableEnd = sql.find("VALUES", tableStart);
            }
            std::string tableName = sql.substr(tableStart, tableEnd - tableStart);
            
            // Trim whitespace
            size_t first = tableName.find_first_not_of(" \t\n");
            size_t last = tableName.find_last_not_of(" \t\n");
            if (first != std::string::npos) {
                tableName = tableName.substr(first, last - first + 1);
            }
            
            // Create table if not exists
            if (pStmt->db->tables.find(tableName) == pStmt->db->tables.end()) {
                pStmt->db->tables[tableName] = std::vector<std::map<std::string, std::string>>();
            }
            
            // Create a dummy row
            std::map<std::string, std::string> row;
            row["id"] = std::to_string(pStmt->db->tables[tableName].size() + 1);
            
            // Add bound values if any
            for (size_t i = 0; i < pStmt->boundValues.size() && i < 20; i++) {
                row["col" + std::to_string(i)] = pStmt->boundValues[i];
            }
            
            pStmt->db->tables[tableName].push_back(row);
            pStmt->executed = true;
            return SQLITE_DONE;
        }
        
        // Simple SELECT parsing
        if (sql.find("SELECT") != std::string::npos) {
            // Extract table name (simplified)
            size_t fromPos = sql.find("FROM");
            if (fromPos != std::string::npos) {
                size_t tableStart = fromPos + 4;
                while (tableStart < sql.size() && sql[tableStart] == ' ') tableStart++;
                size_t tableEnd = sql.find(' ', tableStart);
                if (tableEnd == std::string::npos) tableEnd = sql.size();
                std::string tableName = sql.substr(tableStart, tableEnd - tableStart);
                
                // Trim
                size_t first = tableName.find_first_not_of(" \t\n");
                size_t last = tableName.find_last_not_of(" \t\n");
                if (first != std::string::npos) {
                    tableName = tableName.substr(first, last - first + 1);
                }
                
                auto it = pStmt->db->tables.find(tableName);
                if (it != pStmt->db->tables.end()) {
                    pStmt->results = it->second;
                }
            }
            
            // Handle COUNT(*)
            if (sql.find("COUNT(*)") != std::string::npos) {
                std::map<std::string, std::string> countRow;
                countRow["count"] = std::to_string(pStmt->results.size());
                pStmt->results.clear();
                pStmt->results.push_back(countRow);
            }
            
            pStmt->executed = true;
        }
        
        // Simple DELETE parsing
        if (sql.find("DELETE FROM") != std::string::npos) {
            pStmt->executed = true;
            return SQLITE_DONE;
        }
    }
    
    // Return rows
    if (pStmt->currentRow < pStmt->results.size()) {
        pStmt->currentRow++;
        return SQLITE_ROW;
    }
    
    return SQLITE_DONE;
}

int sqlite3_finalize(sqlite3_stmt* pStmt) {
    delete pStmt;
    return SQLITE_OK;
}

int sqlite3_reset(sqlite3_stmt* pStmt) {
    if (!pStmt) return SQLITE_MISUSE;
    pStmt->currentRow = 0;
    pStmt->executed = false;
    return SQLITE_OK;
}

// Binding functions
int sqlite3_bind_int(sqlite3_stmt* stmt, int idx, int value) {
    if (!stmt) return SQLITE_MISUSE;
    if (idx > (int)stmt->boundValues.size()) {
        stmt->boundValues.resize(idx);
    }
    stmt->boundValues[idx - 1] = std::to_string(value);
    return SQLITE_OK;
}

int sqlite3_bind_int64(sqlite3_stmt* stmt, int idx, int64_t value) {
    if (!stmt) return SQLITE_MISUSE;
    if (idx > (int)stmt->boundValues.size()) {
        stmt->boundValues.resize(idx);
    }
    stmt->boundValues[idx - 1] = std::to_string(value);
    return SQLITE_OK;
}

int sqlite3_bind_double(sqlite3_stmt* stmt, int idx, double value) {
    if (!stmt) return SQLITE_MISUSE;
    if (idx > (int)stmt->boundValues.size()) {
        stmt->boundValues.resize(idx);
    }
    stmt->boundValues[idx - 1] = std::to_string(value);
    return SQLITE_OK;
}

int sqlite3_bind_text(sqlite3_stmt* stmt, int idx, const char* value, int len, void(*/*destructor*/)(void*)) {
    if (!stmt) return SQLITE_MISUSE;
    if (idx > (int)stmt->boundValues.size()) {
        stmt->boundValues.resize(idx);
    }
    if (len < 0) {
        stmt->boundValues[idx - 1] = value ? value : "";
    } else {
        stmt->boundValues[idx - 1] = value ? std::string(value, len) : "";
    }
    return SQLITE_OK;
}

int sqlite3_bind_null(sqlite3_stmt* stmt, int idx) {
    if (!stmt) return SQLITE_MISUSE;
    if (idx > (int)stmt->boundValues.size()) {
        stmt->boundValues.resize(idx);
    }
    stmt->boundValues[idx - 1] = "";
    return SQLITE_OK;
}

// Column access functions
int sqlite3_column_int(sqlite3_stmt* stmt, int idx) {
    if (!stmt || stmt->currentRow == 0 || stmt->currentRow > stmt->results.size()) return 0;
    
    const auto& row = stmt->results[stmt->currentRow - 1];
    auto it = row.find("col" + std::to_string(idx));
    if (it != row.end()) {
        return std::stoi(it->second);
    }
    
    // Try count column
    auto countIt = row.find("count");
    if (countIt != row.end()) {
        return std::stoi(countIt->second);
    }
    
    return 0;
}

int64_t sqlite3_column_int64(sqlite3_stmt* stmt, int idx) {
    if (!stmt || stmt->currentRow == 0 || stmt->currentRow > stmt->results.size()) return 0;
    
    const auto& row = stmt->results[stmt->currentRow - 1];
    auto it = row.find("col" + std::to_string(idx));
    if (it != row.end()) {
        return std::stoll(it->second);
    }
    
    auto countIt = row.find("count");
    if (countIt != row.end()) {
        return std::stoll(countIt->second);
    }
    
    return 0;
}

double sqlite3_column_double(sqlite3_stmt* stmt, int idx) {
    if (!stmt || stmt->currentRow == 0 || stmt->currentRow > stmt->results.size()) return 0.0;
    
    const auto& row = stmt->results[stmt->currentRow - 1];
    auto it = row.find("col" + std::to_string(idx));
    if (it != row.end()) {
        return std::stod(it->second);
    }
    
    return 0.0;
}

const char* sqlite3_column_text(sqlite3_stmt* stmt, int idx) {
    if (!stmt || stmt->currentRow == 0 || stmt->currentRow > stmt->results.size()) return "";
    
    const auto& row = stmt->results[stmt->currentRow - 1];
    auto it = row.find("col" + std::to_string(idx));
    if (it != row.end()) {
        // Return a pointer to the string data - this is unsafe but works for testing
        static std::string lastValue;
        lastValue = it->second;
        return lastValue.c_str();
    }
    
    return "";
}

const void* sqlite3_column_blob(sqlite3_stmt* stmt, int /*idx*/) {
    (void)stmt;
    return nullptr;
}

int sqlite3_column_bytes(sqlite3_stmt* stmt, int /*idx*/) {
    (void)stmt;
    return 0;
}

int sqlite3_column_type(sqlite3_stmt* stmt, int /*idx*/) {
    (void)stmt;
    return 1; // SQLITE_INTEGER
}

// Error handling
const char* sqlite3_errmsg(sqlite3* db) {
    if (!db) return "no database";
    return db->lastError.c_str();
}

int sqlite3_errcode(sqlite3* db) {
    if (!db) return SQLITE_ERROR;
    return db->lastErrorCode;
}

void sqlite3_free(void* ptr) {
    free(ptr);
}

// WAL mode
int sqlite3_wal_checkpoint(sqlite3* /*db*/, const char* /*zDb*/) {
    return SQLITE_OK;
}
