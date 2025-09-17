# CB-176 E2E Test Environment Setup

## Prerequisites

Before running CB-176 End-to-End Authentication Flow tests, ensure your local environment is properly configured.

### 1. PostgreSQL Setup

**Your Configuration:**
- **Host**: localhost
- **Port**: 5432  
- **Database**: authdb
- **Schema**: auth
- **User**: auth
- **Password**: 123456

**Setup Commands:**
```bash
# Connect to PostgreSQL as superuser (postgres)
psql -U postgres -h localhost

# Create database and user
CREATE DATABASE authdb;
CREATE USER auth WITH PASSWORD '123456';
GRANT ALL PRIVILEGES ON DATABASE authdb TO auth;

# Connect to the new database
\c authdb

# Run the setup script
\i internal/tests/database_setup.sql
```

### 2. Redis Setup

**Your Configuration:**
- **Host**: localhost
- **Port**: 6379
- **Password**: (none)
- **Test DB**: 1 (to avoid conflicts with dev data)

**Verify Redis is running:**
```bash
redis-cli ping
# Should return: PONG
```

### 3. Environment Configuration

The following configuration files have been created:

- **`.env`** - Development configuration
- **`.env.test`** - Test environment configuration  
- **`internal/tests/config/test_config.go`** - Test configuration utilities

### 4. Running the Tests

Once your environment is set up:

```bash
# Ensure dependencies are available
go mod tidy

# Set up test database schema
go run cmd/authzsvc/main.go migrate # This will create tables in auth schema

# Run E2E tests (when implemented)
go test -v ./internal/tests/e2e/... -timeout=30s

# Run with race detection
go test -race -v ./internal/tests/e2e/...

# Run benchmarks
go test -bench=. ./internal/tests/benchmarks/...
```

### 5. Test Data Management

The setup includes:

- **Automatic cleanup** of test data after each test
- **Isolated test database** (DB 1 for Redis, auth schema for PostgreSQL)
- **Mock external services** (Twilio SMS) for deterministic testing
- **Test user factories** for consistent test data

### 6. Troubleshooting

**Database Connection Issues:**
```bash
# Test database connection
psql -U auth -h localhost -d authdb -c "SELECT version();"
```

**Redis Connection Issues:**
```bash
# Test Redis connection
redis-cli -h localhost -p 6379 ping
```

**Environment Variables:**
```bash
# Check current configuration
env | grep -E "(DATABASE|REDIS|JWT|OTP)"
```

### 7. Security Notes

- **Test credentials** are used for local development only
- **JWT secrets** are test-specific and different from production
- **Database isolation** prevents test data from affecting development
- **Mock services** prevent real SMS/email sending during tests

---

## Next Steps

With this configuration in place, you're ready to proceed with CB-176 E2E test implementation:

1. ✅ Database configured (PostgreSQL with auth schema)
2. ✅ Redis configured (localhost with test DB)
3. ✅ Environment files created (.env, .env.test)
4. ✅ Test configuration utilities implemented
5. ✅ Database setup script provided

**Ready to start CB-176 Phase 1: E2E Test Infrastructure**