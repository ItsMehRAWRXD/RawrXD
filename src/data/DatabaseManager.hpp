/**
 * DatabaseManager.hpp
 *
 * Phase M Batch 1/5: Database Abstraction & Connection Pooling
 *
 * Unified database abstraction layer with connection pooling, query building,
 * and support for multiple database backends.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <queue>
#include <chrono>
#include <future>

namespace Data {

// ============================================================================
// Forward Declarations
// ============================================================================

class Connection;
class ConnectionPool;
class QueryBuilder;
class ResultSet;
class DatabaseManager;
class Transaction;

// ============================================================================
// Database Types
// ============================================================================

enum class DatabaseType {
    POSTGRESQL,
    MYSQL,
    SQLITE,
    MONGODB,
    REDIS,
    CASSANDRA,
    ELASTICSEARCH,
    CLICKHOUSE,
    DUCKDB,
    CUSTOM
};

std::string DatabaseTypeToString(DatabaseType type);
DatabaseType DatabaseTypeFromString(const std::string& str);

// ============================================================================
// Connection Config
// ============================================================================

/**
 * Database connection configuration.
 */
struct ConnectionConfig {
    DatabaseType type;
    std::string host;
    uint16_t port;
    std::string database;
    std::string username;
    std::string password;
    std::map<std::string, std::string> options;
    
    // SSL settings
    bool useSsl;
    std::string sslCert;
    std::string sslKey;
    std::string sslCa;
    bool sslVerify;
    
    // Pool settings
    uint32_t minConnections;
    uint32_t maxConnections;
    std::chrono::seconds connectionTimeout;
    std::chrono::seconds idleTimeout;
    std::chrono::seconds maxLifetime;
    
    // Retry settings
    uint32_t maxRetries;
    std::chrono::milliseconds retryDelay;
    
    static ConnectionConfig PostgreSQL(const std::string& host, uint16_t port,
                                        const std::string& database,
                                        const std::string& username,
                                        const std::string& password);
    static ConnectionConfig SQLite(const std::string& path);
    static ConnectionConfig Redis(const std::string& host, uint16_t port);
};

// ============================================================================
// Field Value
// ============================================================================

/**
 * Generic database field value.
 */
class FieldValue {
public:
    enum class Type {
        NULL_VALUE,
        BOOL,
        INT32,
        INT64,
        UINT32,
        UINT64,
        FLOAT,
        DOUBLE,
        STRING,
        BLOB,
        TIMESTAMP,
        UUID,
        JSON,
        ARRAY
    };
    
    FieldValue();
    explicit FieldValue(std::nullptr_t);
    explicit FieldValue(bool value);
    explicit FieldValue(int32_t value);
    explicit FieldValue(int64_t value);
    explicit FieldValue(uint32_t value);
    explicit FieldValue(uint64_t value);
    explicit FieldValue(float value);
    explicit FieldValue(double value);
    explicit FieldValue(const std::string& value);
    explicit FieldValue(std::string&& value);
    explicit FieldValue(const std::vector<uint8_t>& value);
    explicit FieldValue(std::chrono::system_clock::time_point value);
    
    // Type checking
    Type GetType() const { return type_; }
    bool IsNull() const { return type_ == Type::NULL_VALUE; }
    
    // Value access
    template<typename T>
    T Get() const;
    
    template<typename T>
    std::optional<T> GetOptional() const;
    
    // Conversion
    std::string ToString() const;
    std::vector<uint8_t> ToBlob() const;
    
    // Comparison
    bool operator==(const FieldValue& other) const;
    bool operator!=(const FieldValue& other) const;
    bool operator<(const FieldValue& other) const;
    
private:
    Type type_;
    union {
        bool boolValue_;
        int32_t int32Value_;
        int64_t int64Value_;
        uint32_t uint32Value_;
        uint64_t uint64Value_;
        float floatValue_;
        double doubleValue_;
    };
    std::string stringValue_;
    std::vector<uint8_t> blobValue_;
    std::chrono::system_clock::time_point timestampValue_;
};

// ============================================================================
// Row
// ============================================================================

/**
 * Database row.
 */
class Row {
public:
    Row();
    explicit Row(const std::map<std::string, FieldValue>& fields);
    
    // Field access
    bool HasField(const std::string& name) const;
    const FieldValue& GetField(const std::string& name) const;
    FieldValue& GetField(const std::string& name);
    std::optional<FieldValue> GetFieldOptional(const std::string& name) const;
    
    template<typename T>
    T Get(const std::string& name) const;
    
    template<typename T>
    std::optional<T> GetOptional(const std::string& name) const;
    
    // Iteration
    const std::map<std::string, FieldValue>& GetFields() const { return fields_; }
    std::map<std::string, FieldValue>& GetFields() { return fields_; }
    
    // Modification
    void SetField(const std::string& name, const FieldValue& value);
    void RemoveField(const std::string& name);
    
    // Serialization
    std::string ToJson() const;
    static Row FromJson(const std::string& json);
    
private:
    std::map<std::string, FieldValue> fields_;
};

// ============================================================================
// Result Set
// ============================================================================

/**
 * Database query result set.
 */
class ResultSet {
public:
    ResultSet();
    explicit ResultSet(const std::vector<Row>& rows);
    
    // Iteration
    bool Next();
    bool IsValid() const;
    const Row& GetCurrentRow() const;
    Row& GetCurrentRow();
    
    // Random access
    const Row& GetRow(size_t index) const;
    Row& GetRow(size_t index);
    
    // Properties
    size_t GetRowCount() const { return rows_.size(); }
    bool IsEmpty() const { return rows_.empty(); }
    
    // Column info
    std::vector<std::string> GetColumnNames() const;
    
    // Conversion
    std::vector<Row> ToVector() const { return rows_; }
    std::string ToJson() const;
    
    // Single value extraction
    template<typename T>
    std::optional<T> GetSingleValue() const;
    
    // Reset
    void Reset();
    
private:
    std::vector<Row> rows_;
    size_t currentIndex_;
};

// ============================================================================
// Connection
// ============================================================================

/**
 * Database connection interface.
 */
class Connection {
public:
    virtual ~Connection() = default;
    
    // Lifecycle
    virtual bool Connect() = 0;
    virtual bool Disconnect() = 0;
    virtual bool IsConnected() const = 0;
    virtual bool Ping() = 0;
    
    // Query execution
    virtual ResultSet ExecuteQuery(const std::string& sql) = 0;
    virtual int ExecuteUpdate(const std::string& sql) = 0;
    virtual bool Execute(const std::string& sql) = 0;
    
    // Prepared statements
    virtual std::string PrepareStatement(const std::string& sql) = 0;
    virtual ResultSet ExecutePrepared(const std::string& statementId,
                                       const std::vector<FieldValue>& params) = 0;
    virtual int ExecutePreparedUpdate(const std::string& statementId,
                                       const std::vector<FieldValue>& params) = 0;
    virtual void ClosePreparedStatement(const std::string& statementId) = 0;
    
    // Transactions
    virtual bool BeginTransaction() = 0;
    virtual bool Commit() = 0;
    virtual bool Rollback() = 0;
    virtual bool IsInTransaction() const = 0;
    
    // Metadata
    virtual std::vector<std::string> GetTables() = 0;
    virtual std::vector<std::string> GetColumns(const std::string& table) = 0;
    virtual std::map<std::string, std::string> GetTableSchema(const std::string& table) = 0;
    
    // Info
    virtual DatabaseType GetType() const = 0;
    virtual std::string GetServerVersion() const = 0;
    virtual uint64_t GetLastInsertId() const = 0;
    
    // Statistics
    struct ConnectionStats {
        uint64_t queriesExecuted;
        uint64_t rowsFetched;
        uint64_t rowsAffected;
        std::chrono::milliseconds totalQueryTime;
        std::chrono::system_clock::time_point connectedSince;
    };
    virtual ConnectionStats GetStats() const = 0;
    
    // Reset statistics
    virtual void ResetStats() = 0;
};

// ============================================================================
// Connection Pool
// ============================================================================

/**
 * Database connection pool.
 */
class ConnectionPool {
public:
    struct Config {
        ConnectionConfig connectionConfig;
        uint32_t minConnections;
        uint32_t maxConnections;
        std::chrono::seconds connectionTimeout;
        std::chrono::seconds idleTimeout;
        std::chrono::seconds maxLifetime;
        bool testOnBorrow;
        bool testOnReturn;
        std::chrono::seconds validationInterval;
    };
    
    explicit ConnectionPool(const Config& config);
    ~ConnectionPool();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Connection management
    std::shared_ptr<Connection> Acquire();
    bool Release(std::shared_ptr<Connection> connection);
    
    // Scoped connection
    class ScopedConnection {
    public:
        explicit ScopedConnection(ConnectionPool& pool);
        ~ScopedConnection();
        
        Connection* operator->() { return connection_.get(); }
        Connection& operator*() { return *connection_; }
        std::shared_ptr<Connection> Get() { return connection_; }
        
    private:
        ConnectionPool& pool_;
        std::shared_ptr<Connection> connection_;
    };
    
    // Statistics
    struct PoolStats {
        uint32_t totalConnections;
        uint32_t activeConnections;
        uint32_t idleConnections;
        uint32_t waitingRequests;
        uint64_t totalRequests;
        uint64_t timeouts;
        double averageWaitTimeMs;
    };
    PoolStats GetStats() const;
    
    // Maintenance
    void EvictIdleConnections();
    void ValidateConnections();
    void CloseExpiredConnections();
    
private:
    Config config_;
    bool initialized_;
    
    std::queue<std::shared_ptr<Connection>> idleConnections_;
    std::set<std::shared_ptr<Connection>> activeConnections_;
    std::queue<std::promise<std::shared_ptr<Connection>>> waitingRequests_;
    
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::thread maintenanceThread_;
    std::atomic<bool> stopMaintenance_;
    
    PoolStats stats_;
    mutable std::mutex statsMutex_;
    
    std::shared_ptr<Connection> CreateConnection();
    void MaintenanceLoop();
    bool IsConnectionValid(std::shared_ptr<Connection> connection);
    bool IsConnectionExpired(std::shared_ptr<Connection> connection);
};

// ============================================================================
// Query Builder
// ============================================================================

/**
 * SQL query builder.
 */
class QueryBuilder {
public:
    QueryBuilder();
    explicit QueryBuilder(const std::string& table);
    
    // SELECT
    QueryBuilder& Select(const std::vector<std::string>& columns);
    QueryBuilder& Select(const std::string& column);
    QueryBuilder& SelectAll();
    QueryBuilder& Distinct();
    
    // FROM
    QueryBuilder& From(const std::string& table);
    QueryBuilder& From(const std::string& table, const std::string& alias);
    
    // JOIN
    QueryBuilder& Join(const std::string& table, const std::string& condition);
    QueryBuilder& LeftJoin(const std::string& table, const std::string& condition);
    QueryBuilder& RightJoin(const std::string& table, const std::string& condition);
    QueryBuilder& InnerJoin(const std::string& table, const std::string& condition);
    QueryBuilder& CrossJoin(const std::string& table);
    
    // WHERE
    QueryBuilder& Where(const std::string& condition);
    QueryBuilder& Where(const std::string& column, const std::string& op,
                         const FieldValue& value);
    QueryBuilder& AndWhere(const std::string& condition);
    QueryBuilder& OrWhere(const std::string& condition);
    QueryBuilder& WhereIn(const std::string& column,
                          const std::vector<FieldValue>& values);
    QueryBuilder& WhereBetween(const std::string& column,
                                 const FieldValue& min,
                                 const FieldValue& max);
    QueryBuilder& WhereNull(const std::string& column);
    QueryBuilder& WhereNotNull(const std::string& column);
    
    // GROUP BY / HAVING
    QueryBuilder& GroupBy(const std::vector<std::string>& columns);
    QueryBuilder& Having(const std::string& condition);
    
    // ORDER BY
    QueryBuilder& OrderBy(const std::string& column, bool ascending = true);
    QueryBuilder& OrderByDesc(const std::string& column);
    
    // LIMIT / OFFSET
    QueryBuilder& Limit(uint64_t count);
    QueryBuilder& Offset(uint64_t count);
    
    // INSERT
    QueryBuilder& Insert(const std::string& table);
    QueryBuilder& Values(const std::map<std::string, FieldValue>& values);
    QueryBuilder& Values(const std::vector<std::map<std::string, FieldValue>>& rows);
    
    // UPDATE
    QueryBuilder& Update(const std::string& table);
    QueryBuilder& Set(const std::string& column, const FieldValue& value);
    QueryBuilder& Set(const std::map<std::string, FieldValue>& values);
    
    // DELETE
    QueryBuilder& Delete();
    QueryBuilder& DeleteFrom(const std::string& table);
    
    // Raw
    QueryBuilder& Raw(const std::string& sql);
    
    // Build
    std::string Build() const;
    std::pair<std::string, std::vector<FieldValue>> BuildWithParams() const;
    
    // Reset
    void Reset();
    
private:
    enum class QueryType {
        SELECT,
        INSERT,
        UPDATE,
        DELETE,
        RAW
    };
    
    QueryType type_;
    std::string table_;
    std::vector<std::string> columns_;
    std::vector<std::string> joins_;
    std::vector<std::string> whereConditions_;
    std::vector<FieldValue> whereParams_;
    std::vector<std::string> groupByColumns_;
    std::vector<std::string> havingConditions_;
    std::vector<std::pair<std::string, bool>> orderByColumns_;
    std::optional<uint64_t> limit_;
    std::optional<uint64_t> offset_;
    bool distinct_;
    
    std::map<std::string, FieldValue> insertValues_;
    std::vector<std::map<std::string, FieldValue>> insertRows_;
    std::map<std::string, FieldValue> updateValues_;
    std::string rawSql_;
    
    std::string BuildSelect() const;
    std::string BuildInsert() const;
    std::string BuildUpdate() const;
    std::string BuildDelete() const;
};

// ============================================================================
// Database Manager
// ============================================================================

/**
 * Central database manager.
 */
class DatabaseManager {
public:
    struct Config {
        std::map<std::string, ConnectionPool::Config> pools;
        std::string defaultPool;
        bool enableQueryLogging;
        bool enableSlowQueryLogging;
        std::chrono::milliseconds slowQueryThreshold;
    };
    
    explicit DatabaseManager(const Config& config);
    ~DatabaseManager();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Pool management
    bool AddPool(const std::string& name, const ConnectionPool::Config& config);
    void RemovePool(const std::string& name);
    std::shared_ptr<ConnectionPool> GetPool(const std::string& name);
    std::shared_ptr<ConnectionPool> GetDefaultPool();
    
    // Convenience methods
    ResultSet Query(const std::string& sql);
    ResultSet Query(const std::string& sql, const std::vector<FieldValue>& params);
    int Execute(const std::string& sql);
    int Execute(const std::string& sql, const std::vector<FieldValue>& params);
    
    // Query builder
    ResultSet ExecuteQuery(const QueryBuilder& builder);
    int ExecuteUpdate(const QueryBuilder& builder);
    
    // Transactions
    std::unique_ptr<Transaction> BeginTransaction();
    std::unique_ptr<Transaction> BeginTransaction(const std::string& poolName);
    
    // Batch operations
    std::vector<ResultSet> ExecuteBatch(const std::vector<std::string>& queries);
    std::vector<int> ExecuteBatchUpdate(const std::vector<std::string>& queries);
    
    // Async operations
    std::future<ResultSet> QueryAsync(const std::string& sql);
    std::future<int> ExecuteAsync(const std::string& sql);
    
    // Migrations
    bool RunMigrations(const std::string& migrationsPath);
    bool CreateMigration(const std::string& name);
    bool RollbackMigration(uint32_t steps = 1);
    
    // Statistics
    struct ManagerStats {
        uint64_t totalQueries;
        uint64_t totalUpdates;
        uint64_t slowQueries;
        uint64_t failedQueries;
        double averageQueryTimeMs;
        std::map<std::string, ConnectionPool::PoolStats> poolStats;
    };
    ManagerStats GetStats() const;
    void ResetStats();
    
    // Health check
    bool HealthCheck() const;
    std::map<std::string, bool> GetPoolHealth() const;
    
private:
    Config config_;
    bool initialized_;
    std::map<std::string, std::shared_ptr<ConnectionPool>> pools_;
    std::shared_ptr<ConnectionPool> defaultPool_;
    mutable std::mutex mutex_;
    
    ManagerStats stats_;
    mutable std::mutex statsMutex_;
    
    void LogQuery(const std::string& sql, std::chrono::milliseconds duration);
    void LogSlowQuery(const std::string& sql, std::chrono::milliseconds duration);
};

// ============================================================================
// Transaction
// ============================================================================

/**
 * Database transaction.
 */
class Transaction {
public:
    explicit Transaction(std::shared_ptr<Connection> connection);
    ~Transaction();
    
    // Disable copy
    Transaction(const Transaction&) = delete;
    Transaction& operator=(const Transaction&) = delete;
    
    // Enable move
    Transaction(Transaction&&) noexcept;
    Transaction& operator=(Transaction&&) noexcept;
    
    // Lifecycle
    bool Begin();
    bool Commit();
    bool Rollback();
    bool IsActive() const;
    
    // Query execution
    ResultSet Query(const std::string& sql);
    ResultSet Query(const std::string& sql, const std::vector<FieldValue>& params);
    int Execute(const std::string& sql);
    int Execute(const std::string& sql, const std::vector<FieldValue>& params);
    
    // Savepoints
    bool CreateSavepoint(const std::string& name);
    bool RollbackToSavepoint(const std::string& name);
    bool ReleaseSavepoint(const std::string& name);
    
    // Connection access
    Connection* GetConnection() { return connection_.get(); }
    
private:
    std::shared_ptr<Connection> connection_;
    bool active_;
    std::vector<std::string> savepoints_;
    mutable std::mutex mutex_;
};

} // namespace Data
