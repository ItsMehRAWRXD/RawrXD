/**
 * SchemaManager.hpp
 *
 * Phase M Batch 5/5: Data Migration & Schema Management
 *
 * Schema versioning, migration management, and data transformation
 * for database evolution and maintenance.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>

namespace Data {

// ============================================================================
// Forward Declarations
// ============================================================================

class Schema;
class Migration;
class SchemaManager;
class DataTransformer;

// ============================================================================
// Column Definition
// ============================================================================

/**
 * Database column definition.
 */
struct ColumnDefinition {
    enum class DataType {
        BOOLEAN,
        TINYINT,
        SMALLINT,
        INTEGER,
        BIGINT,
        FLOAT,
        DOUBLE,
        DECIMAL,
        VARCHAR,
        TEXT,
        BLOB,
        DATE,
        TIME,
        TIMESTAMP,
        UUID,
        JSON,
        ARRAY,
        ENUM
    };
    
    std::string name;
    DataType type;
    std::optional<uint32_t> length;
    std::optional<uint32_t> precision;
    std::optional<uint32_t> scale;
    bool nullable;
    std::optional<std::string> defaultValue;
    bool autoIncrement;
    bool primaryKey;
    bool unique;
    std::optional<std::string> checkConstraint;
    std::optional<std::string> collation;
    std::map<std::string, std::string> metadata;
    
    static ColumnDefinition Boolean(const std::string& name, bool nullable = false);
    static ColumnDefinition Integer(const std::string& name, bool nullable = false);
    static ColumnDefinition BigInt(const std::string& name, bool nullable = false);
    static ColumnDefinition Varchar(const std::string& name, uint32_t length,
                                     bool nullable = false);
    static ColumnDefinition Text(const std::string& name, bool nullable = false);
    static ColumnDefinition Timestamp(const std::string& name, bool nullable = false);
    static ColumnDefinition Json(const std::string& name, bool nullable = false);
    static ColumnDefinition Uuid(const std::string& name, bool nullable = false);
};

// ============================================================================
// Index Definition
// ============================================================================

/**
 * Database index definition.
 */
struct IndexDefinition {
    enum class IndexType {
        BTREE,
        HASH,
        GIN,
        GIST,
        FULLTEXT,
        SPATIAL,
        UNIQUE
    };
    
    std::string name;
    std::vector<std::string> columns;
    IndexType type;
    bool unique;
    std::map<std::string, std::string> options;
    std::optional<std::string> whereClause;
    std::optional<std::string> tablespace;
};

// ============================================================================
// Foreign Key Definition
// ============================================================================

/**
 * Foreign key constraint definition.
 */
struct ForeignKeyDefinition {
    std::string name;
    std::vector<std::string> columns;
    std::string referencedTable;
    std::vector<std::string> referencedColumns;
    std::string onDelete;  // CASCADE, SET NULL, RESTRICT, NO ACTION
    std::string onUpdate;  // CASCADE, SET NULL, RESTRICT, NO ACTION
    bool deferrable;
    std::string initially;  // DEFERRED, IMMEDIATE
};

// ============================================================================
// Table Definition
// ============================================================================

/**
 * Database table definition.
 */
struct TableDefinition {
    std::string name;
    std::string schema;
    std::vector<ColumnDefinition> columns;
    std::vector<IndexDefinition> indexes;
    std::vector<ForeignKeyDefinition> foreignKeys;
    std::vector<std::string> primaryKey;
    std::map<std::string, std::string> constraints;
    std::map<std::string, std::string> options;
    std::optional<std::string> partitionKey;
    std::optional<std::string> comment;
    
    std::optional<ColumnDefinition> GetColumn(const std::string& name) const;
    bool HasColumn(const std::string& name) const;
    void AddColumn(const ColumnDefinition& column);
    void RemoveColumn(const std::string& name);
    void AddIndex(const IndexDefinition& index);
    void RemoveIndex(const std::string& name);
};

// ============================================================================
// Schema
// ============================================================================

/**
 * Database schema.
 */
class Schema {
public:
    struct Config {
        std::string name;
        std::string version;
        std::string description;
        std::chrono::system_clock::time_point createdAt;
        std::map<std::string, TableDefinition> tables;
        std::map<std::string, std::string> views;
        std::map<std::string, std::string> functions;
        std::map<std::string, std::string> triggers;
    };
    
    explicit Schema(const Config& config);
    
    // Schema info
    const std::string& GetName() const { return config_.name; }
    const std::string& GetVersion() const { return config_.version; }
    
    // Table management
    void AddTable(const TableDefinition& table);
    void RemoveTable(const std::string& name);
    std::optional<TableDefinition> GetTable(const std::string& name) const;
    std::vector<std::string> GetTableNames() const;
    bool HasTable(const std::string& name) const;
    
    // View management
    void AddView(const std::string& name, const std::string& definition);
    void RemoveView(const std::string& name);
    std::optional<std::string> GetView(const std::string& name) const;
    
    // Function management
    void AddFunction(const std::string& name, const std::string& definition);
    void RemoveFunction(const std::string& name);
    std::optional<std::string> GetFunction(const std::string& name) const;
    
    // Trigger management
    void AddTrigger(const std::string& name, const std::string& definition);
    void RemoveTrigger(const std::string& name);
    std::optional<std::string> GetTrigger(const std::string& name) const;
    
    // Comparison
    struct SchemaDiff {
        std::vector<TableDefinition> tablesAdded;
        std::vector<std::string> tablesRemoved;
        std::vector<std::pair<TableDefinition, TableDefinition>> tablesModified;
        std::vector<std::string> viewsAdded;
        std::vector<std::string> viewsRemoved;
    };
    SchemaDiff CompareTo(const Schema& other) const;
    
    // Serialization
    std::string ToJson() const;
    static Schema FromJson(const std::string& json);
    std::string ToSql(DatabaseType dbType) const;
    
private:
    Config config_;
};

// ============================================================================
// Migration
// ============================================================================

/**
 * Database migration.
 */
class Migration {
public:
    enum class MigrationType {
        SCHEMA_CHANGE,
        DATA_MIGRATION,
        INDEX_CREATION,
        SEED_DATA
    };
    
    enum class MigrationStatus {
        PENDING,
        RUNNING,
        COMPLETED,
        FAILED,
        ROLLED_BACK
    };
    
    struct Config {
        std::string migrationId;
        std::string name;
        std::string description;
        MigrationType type;
        std::string version;
        std::optional<std::string> dependsOn;
        std::chrono::system_clock::time_point createdAt;
        std::optional<std::chrono::system_clock::time_point> executedAt;
        std::optional<std::chrono::system_clock::time_point> rolledBackAt;
        MigrationStatus status;
        std::optional<std::string> errorMessage;
        uint64_t executionTimeMs;
    };
    
    using MigrationFunction = std::function<bool()>;
    using RollbackFunction = std::function<bool()>;
    
    explicit Migration(const Config& config);
    
    // Migration functions
    void SetUpFunction(MigrationFunction func);
    void SetDownFunction(RollbackFunction func);
    void SetVerifyFunction(std::function<bool()> func);
    
    // Execution
    bool Execute();
    bool Rollback();
    bool Verify();
    
    // Status
    MigrationStatus GetStatus() const { return config_.status; }
    bool IsPending() const { return config_.status == MigrationStatus::PENDING; }
    bool IsCompleted() const { return config_.status == MigrationStatus::COMPLETED; }
    bool IsFailed() const { return config_.status == MigrationStatus::FAILED; }
    
    // Info
    const Config& GetConfig() const { return config_; }
    const std::string& GetMigrationId() const { return config_.migrationId; }
    const std::string& GetVersion() const { return config_.version; }
    
    // Dependencies
    bool DependsOn(const std::string& migrationId) const;
    void AddDependency(const std::string& migrationId);
    std::vector<std::string> GetDependencies() const;
    
private:
    Config config_;
    MigrationFunction upFunction_;
    RollbackFunction downFunction_;
    std::function<bool()> verifyFunction_;
    std::vector<std::string> dependencies_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Migration Generator
// ============================================================================

/**
 * Migration code generator.
 */
class MigrationGenerator {
public:
    struct MigrationTemplate {
        std::string name;
        std::string description;
        std::string upCode;
        std::string downCode;
        Migration::MigrationType type;
    };
    
    // Generation
    static MigrationTemplate GenerateCreateTable(const TableDefinition& table);
    static MigrationTemplate GenerateDropTable(const std::string& tableName);
    static MigrationTemplate GenerateAddColumn(const std::string& tableName,
                                                const ColumnDefinition& column);
    static MigrationTemplate GenerateDropColumn(const std::string& tableName,
                                                 const std::string& columnName);
    static MigrationTemplate GenerateModifyColumn(const std::string& tableName,
                                                   const ColumnDefinition& oldColumn,
                                                   const ColumnDefinition& newColumn);
    static MigrationTemplate GenerateCreateIndex(const std::string& tableName,
                                                  const IndexDefinition& index);
    static MigrationTemplate GenerateDropIndex(const std::string& tableName,
                                                const std::string& indexName);
    static MigrationTemplate GenerateAddForeignKey(const std::string& tableName,
                                                    const ForeignKeyDefinition& fk);
    static MigrationTemplate GenerateDropForeignKey(const std::string& tableName,
                                                     const std::string& fkName);
    static MigrationTemplate GenerateRenameTable(const std::string& oldName,
                                                  const std::string& newName);
    static MigrationTemplate GenerateDataMigration(const std::string& description,
                                                    const std::string& transformCode);
    
    // Code generation
    static std::string GenerateCppCode(const MigrationTemplate& tmpl);
    static std::string GenerateSqlCode(const MigrationTemplate& tmpl, DatabaseType dbType);
    static std::string GeneratePythonCode(const MigrationTemplate& tmpl);
};

// ============================================================================
// Schema Manager
// ============================================================================

/**
 * Central schema and migration manager.
 */
class SchemaManager {
public:
    struct Config {
        std::string migrationsPath;
        std::string schemaTable;
        bool autoMigrate;
        bool validateChecksums;
        bool backupBeforeMigration;
        std::string backupPath;
        bool dryRun;
        bool interactive;
    };
    
    explicit SchemaManager(const Config& config);
    ~SchemaManager();
    
    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Schema operations
    bool CreateSchema(const Schema& schema);
    bool UpdateSchema(const Schema& newSchema);
    bool DropSchema(const std::string& schemaName);
    std::optional<Schema> GetCurrentSchema() const;
    std::optional<Schema> GetSchemaAtVersion(const std::string& version) const;
    
    // Migration management
    bool RegisterMigration(std::shared_ptr<Migration> migration);
    bool UnregisterMigration(const std::string& migrationId);
    std::shared_ptr<Migration> GetMigration(const std::string& migrationId) const;
    std::vector<std::shared_ptr<Migration>> GetPendingMigrations() const;
    std::vector<std::shared_ptr<Migration>> GetAllMigrations() const;
    std::vector<std::shared_ptr<Migration>> GetExecutedMigrations() const;
    
    // Migration execution
    bool Migrate();
    bool MigrateTo(const std::string& version);
    bool MigrateOne();
    bool Rollback(uint32_t steps = 1);
    bool RollbackTo(const std::string& version);
    bool Redo();
    
    // Migration status
    bool IsMigrationPending(const std::string& migrationId) const;
    bool IsMigrationExecuted(const std::string& migrationId) const;
    std::optional<std::string> GetCurrentVersion() const;
    std::optional<std::string> GetTargetVersion() const;
    
    // Migration generation
    std::string CreateMigration(const std::string& name,
                                 Migration::MigrationType type = Migration::MigrationType::SCHEMA_CHANGE);
    std::string CreateMigrationFromDiff(const Schema& oldSchema, const Schema& newSchema);
    
    // Validation
    bool ValidateMigrations();
    bool ValidateSchema();
    std::vector<std::string> GetValidationErrors() const;
    
    // Seeding
    bool Seed(const std::string& seedFile);
    bool SeedData(const std::map<std::string, std::vector<std::map<std::string, std::string>>>& data);
    
    // Reset
    bool Reset();
    bool Fresh();
    
    // Statistics
    struct MigrationStats {
        uint32_t totalMigrations;
        uint32_t pendingMigrations;
        uint32_t executedMigrations;
        uint32_t failedMigrations;
        std::chrono::seconds totalMigrationTime;
        std::string currentVersion;
        std::optional<std::string> latestVersion;
    };
    MigrationStats GetStats() const;
    
    // History
    struct MigrationHistory {
        std::string migrationId;
        std::string version;
        Migration::MigrationStatus status;
        std::chrono::system_clock::time_point executedAt;
        uint64_t executionTimeMs;
        std::optional<std::string> errorMessage;
    };
    std::vector<MigrationHistory> GetHistory() const;
    
    // Export/Import
    bool ExportSchema(const std::string& path) const;
    bool ImportSchema(const std::string& path);
    bool ExportMigrations(const std::string& path) const;
    bool ImportMigrations(const std::string& path);
    
private:
    Config config_;
    bool initialized_;
    std::map<std::string, std::shared_ptr<Migration>> migrations_;
    std::optional<Schema> currentSchema_;
    mutable std::mutex mutex_;
    
    std::vector<std::shared_ptr<Migration>> TopologicalSort() const;
    bool ExecuteMigration(std::shared_ptr<Migration> migration);
    bool ExecuteRollback(std::shared_ptr<Migration> migration);
    void RecordMigration(const Migration& migration, bool success);
    void UpdateSchemaVersion(const std::string& version);
    bool CreateBackup();
    bool RestoreBackup();
};

// ============================================================================
// Data Transformer
// ============================================================================

/**
 * Data transformation for migrations.
 */
class DataTransformer {
public:
    using TransformFunction = std::function<std::map<std::string, std::string>(
        const std::map<std::string, std::string>&)>;
    using FilterFunction = std::function<bool(const std::map<std::string, std::string>&)>;
    
    struct TransformConfig {
        std::string sourceTable;
        std::string targetTable;
        std::vector<std::string> sourceColumns;
        std::vector<std::string> targetColumns;
        TransformFunction transform;
        std::optional<FilterFunction> filter;
        std::optional<uint32_t> batchSize;
        bool deleteSource;
    };
    
    explicit DataTransformer(std::shared_ptr<DatabaseManager> dbManager);
    
    // Transformation
    bool Transform(const TransformConfig& config);
    bool TransformBatch(const std::vector<TransformConfig>& configs);
    
    // Column transformations
    static TransformFunction RenameColumn(const std::string& oldName,
                                           const std::string& newName);
    static TransformFunction ChangeType(const std::string& column,
                                         ColumnDefinition::DataType newType);
    static TransformFunction AddColumn(const std::string& column,
                                      const std::string& defaultValue);
    static TransformFunction RemoveColumn(const std::string& column);
    static TransformFunction SplitColumn(const std::string& column,
                                          const std::vector<std::string>& newColumns,
                                          char delimiter);
    static TransformFunction MergeColumns(const std::vector<std::string>& columns,
                                           const std::string& newColumn,
                                           const std::string& separator);
    static TransformFunction MapValues(const std::string& column,
                                        const std::map<std::string, std::string>& valueMap);
    static TransformFunction ComputeColumn(const std::string& newColumn,
                                            const std::vector<std::string>& sourceColumns,
                                            std::function<std::string(const std::vector<std::string>&)> compute);
    
    // Table transformations
    bool SplitTable(const std::string& sourceTable,
                    const std::vector<std::string>& splitColumns,
                    const std::vector<std::string>& newTables);
    bool MergeTables(const std::vector<std::string>& sourceTables,
                     const std::string& targetTable,
                     const std::vector<std::string>& keyColumns);
    bool PivotTable(const std::string& sourceTable,
                    const std::string& pivotColumn,
                    const std::string& valueColumn,
                    const std::string& targetTable);
    bool UnpivotTable(const std::string& sourceTable,
                      const std::vector<std::string>& valueColumns,
                      const std::string& nameColumn,
                      const std::string& valueColumn,
                      const std::string& targetTable);
    
    // Data validation
    bool ValidateTransform(const TransformConfig& config);
    struct ValidationResult {
        bool valid;
        uint64_t rowsProcessed;
        uint64_t rowsFailed;
        std::vector<std::string> errors;
    };
    ValidationResult ValidateData(const std::string& table,
                                   const std::vector<std::string>& columns,
                                   std::function<bool(const std::map<std::string, std::string>&)> validator);
    
    // Statistics
    struct TransformStats {
        uint64_t rowsProcessed;
        uint64_t rowsTransformed;
        uint64_t rowsFailed;
        std::chrono::seconds duration;
    };
    TransformStats GetStats() const;
    
private:
    std::shared_ptr<DatabaseManager> dbManager_;
    TransformStats stats_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Schema Comparator
// ============================================================================

/**
 * Schema comparison utility.
 */
class SchemaComparator {
public:
    struct ComparisonResult {
        bool identical;
        std::vector<std::string> differences;
        std::vector<TableDefinition> tablesOnlyInFirst;
        std::vector<TableDefinition> tablesOnlyInSecond;
        std::vector<ColumnDifference> columnDifferences;
        std::vector<IndexDifference> indexDifferences;
    };
    
    struct ColumnDifference {
        std::string tableName;
        std::string columnName;
        std::string differenceType;  // added, removed, modified
        std::optional<ColumnDefinition> oldDefinition;
        std::optional<ColumnDefinition> newDefinition;
    };
    
    struct IndexDifference {
        std::string tableName;
        std::string indexName;
        std::string differenceType;
        std::optional<IndexDefinition> oldDefinition;
        std::optional<IndexDefinition> newDefinition;
    };
    
    static ComparisonResult Compare(const Schema& schema1, const Schema& schema2);
    static ComparisonResult CompareTables(const TableDefinition& table1,
                                           const TableDefinition& table2);
    static bool AreColumnsEqual(const ColumnDefinition& col1, const ColumnDefinition& col2);
    static bool AreIndexesEqual(const IndexDefinition& idx1, const IndexDefinition& idx2);
    
    // Generate migration from comparison
    static std::vector<std::shared_ptr<Migration>> GenerateMigrations(
        const ComparisonResult& comparison);
};

// ============================================================================
// Schema Documentation
// ============================================================================

/**
 * Schema documentation generator.
 */
class SchemaDocumentation {
public:
    // Generation
    static std::string GenerateMarkdown(const Schema& schema);
    static std::string GenerateHtml(const Schema& schema);
    static std::string GeneratePdf(const Schema& schema);
    static std::string GeneratePlantUml(const Schema& schema);
    static std::string GenerateDbml(const Schema& schema);
    
    // Entity Relationship Diagram
    static std::string GenerateERD(const Schema& schema);
    
    // Data dictionary
    static std::string GenerateDataDictionary(const Schema& schema);
    
    // API documentation
    static std::string GenerateApiDocs(const Schema& schema);
};

} // namespace Data
