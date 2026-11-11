# Database Integration
## Sovereign IDE Integration Documentation

**Version:** 1.0.0
**Date:** 2026-07-11
**Status:** ✅ Complete

---

## Overview

Database integration enables persistent storage of analysis results and project data.

### Supported Databases

| Database | Driver | Status |
|----------|--------|--------|
| PostgreSQL | libpq | ✅ Supported |
| MySQL | libmysqlclient | ✅ Supported |
| SQLite | Built-in | ✅ Supported |
| MongoDB | mongoc | 🔄 Planned |

---

## Configuration

```yaml
# database.yml
database:
  type: postgresql
  host: localhost
  port: 5432
  name: sovereign_db
  user: sovereign
  password: ${DB_PASSWORD}
  pool_size: 10
```

---

## Schema

```sql
-- Projects table
CREATE TABLE projects (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    path VARCHAR(1024) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Binaries table
CREATE TABLE binaries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID REFERENCES projects(id),
    path VARCHAR(1024) NOT NULL,
    hash VARCHAR(64) NOT NULL,
    size BIGINT NOT NULL,
    architecture VARCHAR(32),
    format VARCHAR(32),
    analyzed_at TIMESTAMP
);

-- Analysis results table
CREATE TABLE analysis_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    binary_id UUID REFERENCES binaries(id),
    type VARCHAR(64) NOT NULL,
    results JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

---

## API Usage

```cpp
// Connect to database
auto db = Database::Connect("postgresql://localhost/sovereign_db");

// Store analysis results
AnalysisResult result;
result.binary_id = binary->GetId();
result.type = "symbolic_execution";
result.data = SerializeResults();

db->Insert("analysis_results", result);

// Query results
auto results = db->Query<AnalysisResult>(
    "SELECT * FROM analysis_results WHERE binary_id = $1",
    binary_id
);
```

---

## Summary

Database Integration provides:

- ✅ **PostgreSQL support**
- ✅ **MySQL support**
- ✅ **SQLite support**
- ✅ **Connection pooling**
- ✅ **JSON storage**

**Status:** ✅ Complete
