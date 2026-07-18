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
#include <memory>

// Table definition with column order
struct TableDef {
    std::vector<std::string> columnOrder;  // Ordered list of column names
    std::vector<std::map<std::string, std::string>> rows;
};

// Simple in-memory database implementation
struct sqlite3 {
    std::string name;
    std::map<std::string, TableDef> tables;
    std::string lastError;
    int lastErrorCode;
};

struct sqlite3_stmt {
    sqlite3* db;
    std::string sql;
    std::vector<std::map<std::string, std::string>> results;
    size_t currentRow;
    std::vector<std::string> boundValues;
    std::vector<std::string> columnNames;  // Column names for SELECT results
    bool executed;
};

// Global databases for :memory: support
static std::map<std::string, std::unique_ptr<sqlite3>> g_databases;

int sqlite3_open(const char* filename, sqlite3** ppDb) {
    return sqlite3_open_v2(filename, ppDb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
}

int sqlite3_open_v2(const char* filename, sqlite3** ppDb, int flags, const char* /*zVfs*/) {
    (void)flags;
    *ppDb = nullptr;
    
    std::string dbName = filename ? filename : ":memory:";
    
    // For :memory: databases, return existing one if available
    if (dbName == ":memory:") {
        auto it = g_databases.find(dbName);
        if (it != g_databases.end()) {
            *ppDb = it->second.get();
            return SQLITE_OK;
        }
    }
    
    // Create new database
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
            db->tables[tableName] = TableDef();
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

// Helper to extract column names from INSERT statement
static std::vector<std::string> ExtractInsertColumns(const std::string& sql) {
    std::vector<std::string> columns;
    
    // Find opening parenthesis after table name
    size_t openParen = sql.find('(');
    if (openParen == std::string::npos) return columns;
    
    // Find closing parenthesis
    size_t closeParen = sql.find(')', openParen);
    if (closeParen == std::string::npos) return columns;
    
    // Extract column list
    std::string colList = sql.substr(openParen + 1, closeParen - openParen - 1);
    
    // Split by comma
    std::stringstream ss(colList);
    std::string col;
    while (std::getline(ss, col, ',')) {
        // Trim whitespace
        size_t first = col.find_first_not_of(" \t\n");
        size_t last = col.find_last_not_of(" \t\n");
        if (first != std::string::npos) {
            columns.push_back(col.substr(first, last - first + 1));
        }
    }
    
    return columns;
}

// Helper to extract table name from INSERT/SELECT
static std::string ExtractTableName(const std::string& sql, const std::string& keyword) {
    size_t pos = sql.find(keyword);
    if (pos == std::string::npos) return "";
    
    size_t start = pos + keyword.length();
    while (start < sql.size() && (sql[start] == ' ' || sql[start] == '\t' || sql[start] == '\n')) start++;
    
    size_t end = sql.find_first_of(" (\t\n", start);
    if (end == std::string::npos) end = sql.size();
    
    std::string tableName = sql.substr(start, end - start);
    
    // Trim
    size_t first = tableName.find_first_not_of(" \t\n");
    size_t last = tableName.find_last_not_of(" \t\n");
    if (first != std::string::npos) {
        tableName = tableName.substr(first, last - first + 1);
    }
    
    return tableName;
}

int sqlite3_step(sqlite3_stmt* pStmt) {
    if (!pStmt) return SQLITE_MISUSE;
    
    if (!pStmt->executed) {
        // Parse and execute the SQL
        std::string sql = pStmt->sql;
        
        // Simple INSERT parsing
        if (sql.find("INSERT INTO") != std::string::npos) {
            std::string tableName = ExtractTableName(sql, "INSERT INTO");
            fprintf(stderr, "[STUB] INSERT tableName='%s'\n", tableName.c_str()); fflush(stderr);
            if (tableName.empty()) {
                pStmt->executed = true;
                return SQLITE_DONE;
            }
            
            // Create table if not exists
            if (pStmt->db->tables.find(tableName) == pStmt->db->tables.end()) {
                pStmt->db->tables[tableName] = TableDef();
            }
            
            // Extract column names
            std::vector<std::string> columns = ExtractInsertColumns(sql);
            fprintf(stderr, "[STUB] INSERT columns=%zu, boundValues=%zu\n", 
                    columns.size(), pStmt->boundValues.size()); fflush(stderr);
            
            // Store column order if this is the first insert
            TableDef& table = pStmt->db->tables[tableName];
            if (table.columnOrder.empty()) {
                // Set column order to match RowToRecord expectations
                // Must match: id, execution_id, component, operation, component_type, timestamp,
                // duration_ms, throughput_tps, convergence_score, convergence_gain, memory_bytes,
                // cpu_cores_used, cpu_utilization, success, error_message, retry_count,
                // batch_number, cycle_name, task_category
                table.columnOrder = {
                    "id", "execution_id", "component", "operation", "component_type",
                    "timestamp", "duration_ms", "throughput_tps", "convergence_score",
                    "convergence_gain", "memory_bytes", "cpu_cores_used", "cpu_utilization",
                    "success", "error_message", "retry_count", "batch_number",
                    "cycle_name", "task_category"
                };
            }
            
            // Create a row with bound values mapped to columns
            std::map<std::string, std::string> row;
            row["id"] = std::to_string(table.rows.size() + 1);
            
            // Map bound values to column names
            for (size_t i = 0; i < pStmt->boundValues.size() && i < columns.size(); i++) {
                row[columns[i]] = pStmt->boundValues[i];
            }
            
            table.rows.push_back(row);
            fprintf(stderr, "[STUB] INSERT success, rows=%zu, returning SQLITE_DONE\n", table.rows.size()); fflush(stderr);
            pStmt->executed = true;
            fprintf(stderr, "[STUB] About to return SQLITE_DONE=%d\n", SQLITE_DONE); fflush(stderr);
            return SQLITE_DONE;
        }
        
        // Simple SELECT parsing
        if (sql.find("SELECT") != std::string::npos) {
            fprintf(stderr, "[STUB] SELECT sql='%s'\n", sql.c_str()); fflush(stderr);
            std::string tableName = ExtractTableName(sql, "FROM");
            
            // Debug output
            fprintf(stderr, "[STUB] SELECT tableName='%s', tables=%zu\n", 
                    tableName.c_str(), pStmt->db->tables.size()); fflush(stderr);
            for (const auto& t : pStmt->db->tables) {
                fprintf(stderr, "[STUB]   Table: '%s'\n", t.first.c_str()); fflush(stderr);
            }
            
            auto it = pStmt->db->tables.find(tableName);
            if (it != pStmt->db->tables.end()) {
                pStmt->results = it->second.rows;
                pStmt->columnNames = it->second.columnOrder;
                
                fprintf(stderr, "[STUB] Found table, rows=%zu, cols=%zu\n", 
                        pStmt->results.size(), pStmt->columnNames.size()); fflush(stderr);
                
                // Handle WHERE clause (simple equality only)
                size_t wherePos = sql.find("WHERE");
                fprintf(stderr, "[STUB] WHERE pos=%zu\n", wherePos); fflush(stderr);
                if (wherePos != std::string::npos) {
                    std::string whereClause = sql.substr(wherePos + 5);
                    // Trim leading space
                    size_t first = whereClause.find_first_not_of(" \t\n");
                    if (first != std::string::npos) {
                        whereClause = whereClause.substr(first);
                    }
                    
                    // Find end of WHERE clause (ORDER, LIMIT, etc.)
                    size_t whereEnd = whereClause.find_first_of(";");
                    if (whereEnd != std::string::npos) {
                        whereClause = whereClause.substr(0, whereEnd);
                    }
                    
                    fprintf(stderr, "[STUB] WHERE clause='%s'\n", whereClause.c_str()); fflush(stderr);
                    
                    // Parse simple equality: column = 'value' or column = number
                    size_t eqPos = whereClause.find('=');
                    fprintf(stderr, "[STUB] EQ pos=%zu\n", eqPos); fflush(stderr);
                    if (eqPos != std::string::npos) {
                        std::string colName = whereClause.substr(0, eqPos);
                        std::string value = whereClause.substr(eqPos + 1);
                        
                        // Trim column name
                        size_t colFirst = colName.find_first_not_of(" \t\n");
                        size_t colLast = colName.find_last_not_of(" \t\n");
                        if (colFirst != std::string::npos) {
                            colName = colName.substr(colFirst, colLast - colFirst + 1);
                        }
                        
                        // Trim value and stop at ORDER/LIMIT keywords
                        size_t valFirst = value.find_first_not_of(" \t\n");
                        size_t valEnd = value.find_first_of(" \t\n;");
                        if (valFirst != std::string::npos) {
                            if (valEnd != std::string::npos) {
                                value = value.substr(valFirst, valEnd - valFirst);
                            } else {
                                value = value.substr(valFirst);
                            }
                        }
                        
                        // Remove quotes if present
                        if (value.size() >= 2 && value[0] == '\'' && value[value.size()-1] == '\'') {
                            value = value.substr(1, value.size() - 2);
                        }
                        
                        // Filter results
                        std::vector<std::map<std::string, std::string>> filtered;
                        for (const auto& row : pStmt->results) {
                            auto it = row.find(colName);
                            if (it != row.end() && it->second == value) {
                                filtered.push_back(row);
                            }
                        }
                        pStmt->results = filtered;
                    }
                }
            } else {
                fprintf(stderr, "[STUB] Table not found!\n"); fflush(stderr);
            }
            
            // Handle COUNT(*)
            if (sql.find("COUNT(*)") != std::string::npos) {
                std::map<std::string, std::string> countRow;
                countRow["count"] = std::to_string(pStmt->results.size());
                pStmt->results.clear();
                pStmt->results.push_back(countRow);
                pStmt->columnNames.clear();
                pStmt->columnNames.push_back("count");
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
    fprintf(stderr, "[STUB] finalize called\n"); fflush(stderr);
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

// Helper to get column name from index
static std::string GetColumnName(sqlite3_stmt* stmt, int idx) {
    if (idx >= 0 && idx < (int)stmt->columnNames.size()) {
        return stmt->columnNames[idx];
    }
    // Fallback to legacy naming
    return "col" + std::to_string(idx);
}

// Debug helper
static void DebugLog(const char* msg) {
    // fprintf(stderr, "[STUB] %s\n", msg);
}

// Column access functions
int sqlite3_column_int(sqlite3_stmt* stmt, int idx) {
    if (!stmt || stmt->currentRow == 0 || stmt->currentRow > stmt->results.size()) {
        fprintf(stderr, "[STUB] column_int: invalid state row=%zu results=%zu\n", 
                stmt ? stmt->currentRow : 0, stmt ? stmt->results.size() : 0);
        return 0;
    }
    
    const auto& row = stmt->results[stmt->currentRow - 1];
    std::string colName = GetColumnName(stmt, idx);
    fprintf(stderr, "[STUB] column_int idx=%d colName='%s'\n", idx, colName.c_str());
    auto it = row.find(colName);
    if (it != row.end()) {
        fprintf(stderr, "[STUB] column_int value='%s'\n", it->second.c_str());
        return std::stoi(it->second);
    }
    
    // Try count column
    auto countIt = row.find("count");
    if (countIt != row.end()) {
        return std::stoi(countIt->second);
    }
    
    fprintf(stderr, "[STUB] column_int: column not found\n");
    return 0;
}

int64_t sqlite3_column_int64(sqlite3_stmt* stmt, int idx) {
    if (!stmt || stmt->currentRow == 0 || stmt->currentRow > stmt->results.size()) return 0;
    
    const auto& row = stmt->results[stmt->currentRow - 1];
    std::string colName = GetColumnName(stmt, idx);
    auto it = row.find(colName);
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
    std::string colName = GetColumnName(stmt, idx);
    auto it = row.find(colName);
    if (it != row.end()) {
        return std::stod(it->second);
    }
    
    return 0.0;
}

// Static storage for column text values - limited but works for testing
static std::string g_columnTextValues[32];

const char* sqlite3_column_text(sqlite3_stmt* stmt, int idx) {
    if (!stmt || stmt->currentRow == 0 || stmt->currentRow > stmt->results.size()) return "";
    if (idx < 0 || idx >= 32) return "";
    
    const auto& row = stmt->results[stmt->currentRow - 1];
    std::string colName = GetColumnName(stmt, idx);
    auto it = row.find(colName);
    if (it != row.end()) {
        // Store in static array to ensure persistence
        g_columnTextValues[idx] = it->second;
        return g_columnTextValues[idx].c_str();
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
