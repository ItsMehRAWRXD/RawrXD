/**
 * sqlite3_stub.h
 * 
 * Minimal SQLite stub for Phase C.0 Batch 3/5 testing
 * Provides just enough functionality to validate the Historical Performance Store
 */

#ifndef SQLITE3_STUB_H
#define SQLITE3_STUB_H

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>

// SQLite type definitions
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int64_t sqlite3_int64;

// SQLite constants
#define SQLITE_OK           0
#define SQLITE_ERROR        1
#define SQLITE_ROW          100
#define SQLITE_DONE         101
#define SQLITE_BUSY         5
#define SQLITE_MISUSE       21

// Open flags
#define SQLITE_OPEN_READONLY         0x00000001
#define SQLITE_OPEN_READWRITE        0x00000002
#define SQLITE_OPEN_CREATE           0x00000004
#define SQLITE_OPEN_MEMORY           0x00000080

// Destructor types
#define SQLITE_STATIC      ((void(*)(void*))0)
#define SQLITE_TRANSIENT   ((void(*)(void*))-1)

// Function declarations
int sqlite3_open(const char* filename, sqlite3** ppDb);
int sqlite3_open_v2(const char* filename, sqlite3** ppDb, int flags, const char* zVfs);
int sqlite3_close(sqlite3* db);

int sqlite3_exec(sqlite3* db, const char* sql, int (*callback)(void*, int, char**, char**), void* arg, char** errmsg);

int sqlite3_prepare_v2(sqlite3* db, const char* zSql, int nByte, sqlite3_stmt** ppStmt, const char** pzTail);
int sqlite3_step(sqlite3_stmt* pStmt);
int sqlite3_finalize(sqlite3_stmt* pStmt);
int sqlite3_reset(sqlite3_stmt* pStmt);

int sqlite3_bind_int(sqlite3_stmt* stmt, int idx, int value);
int sqlite3_bind_int64(sqlite3_stmt* stmt, int idx, int64_t value);
int sqlite3_bind_double(sqlite3_stmt* stmt, int idx, double value);
int sqlite3_bind_text(sqlite3_stmt* stmt, int idx, const char* value, int len, void(*destructor)(void*));
int sqlite3_bind_null(sqlite3_stmt* stmt, int idx);

int sqlite3_column_int(sqlite3_stmt* stmt, int idx);
int64_t sqlite3_column_int64(sqlite3_stmt* stmt, int idx);
double sqlite3_column_double(sqlite3_stmt* stmt, int idx);
const char* sqlite3_column_text(sqlite3_stmt* stmt, int idx);
const void* sqlite3_column_blob(sqlite3_stmt* stmt, int idx);
int sqlite3_column_bytes(sqlite3_stmt* stmt, int idx);
int sqlite3_column_type(sqlite3_stmt* stmt, int idx);

const char* sqlite3_errmsg(sqlite3* db);
int sqlite3_errcode(sqlite3* db);

void sqlite3_free(void* ptr);

// WAL mode
int sqlite3_wal_checkpoint(sqlite3* db, const char* zDb);

#endif // SQLITE3_STUB_H
