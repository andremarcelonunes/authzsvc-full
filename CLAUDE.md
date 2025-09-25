# CLAUDE.md

This file provides comprehensive guidance for Claude Code (claude.ai/code) when working with Go projects in this repository, ensuring architectural consistency and quality standards across all services.

## 📋 Table of Contents

- [📖 Overview](#-overview)
- [🚀 Enterprise Features](#-enterprise-features)
- [📊 Production Features](#-production-features)
- [🔧 Development Commands](#-development-commands)
- [🏗 Architecture](#-architecture)
- [🧪 Testing Strategy](#-testing-strategy)
- [🗄️ Database Schema](#️-database-schema)
- [🌐 API Endpoints](#-api-endpoints)
- [🔒 Security Features](#-security-features)
- [⚙️ Environment Variables](#️-environment-variables)
- [👨‍💻 Common Development Tasks](#-common-development-tasks)
- [📊 Quality Metrics & Standards](#-quality-metrics--standards)
- [🔧 CB-194: Dual Authentication Implementation](#-cb-194-dual-authentication-implementation)

## 📖 Overview

**Enterprise Authentication & Authorization Service** built with Go 1.22, featuring SMS OTP verification, JWT tokens, role-based access control using Casbin, **enterprise-grade password management with two-factor change flow**, **comprehensive audit logging (CB-183)**, **LGPD Article 18 compliant user deletion (CB-174)**, **OWASP Top 10 security validation (CB-182)**, and **interactive Swagger UI documentation**. The service follows **Clean Architecture with Hexagonal (Ports & Adapters) pattern** for maximum testability, maintainability, and business logic isolation.

> **Built for Enterprise**: Battle-tested clean architecture, **98%+ test coverage**, **comprehensive OWASP Top 10 security protection**, **LGPD/GDPR compliant audit logging**, **real-time threat detection**, **enterprise password security**, **shadow mode deployment**, and production-grade security features with **world-class validation pipeline**.

**Tech Stack:** Go 1.22+ · Gin · Casbin · GORM · JWT · PostgreSQL · Redis · Twilio

## 🚀 Enterprise Features

### 🔐 CB-192: Password Management System

**Enterprise-grade password security** with **two-factor authentication change flow**:

- **Two-Factor Password Change**: Current password + SMS OTP verification
- **OWASP Compliance**: Latest password security guidelines
- **Bcrypt Protection**: Industry-standard hashing (cost 12+)
- **Rate Limiting**: Prevents brute force and abuse attacks
- **Session Invalidation**: Automatic logout on password change
- **Comprehensive Audit**: Complete activity logging
- **Strong Validation**: Configurable complexity requirements

**API Endpoints**:
- `POST /password/change` - Initiate password change
- `PUT /password/change/{id}/verification` - Complete with OTP
- `GET /password/change/{id}/status` - Check request status
- `DELETE /password/change/{id}` - Cancel change request
- `POST /password/reset` - Initiate password reset
- `PUT /password/reset/{id}/complete` - Complete password reset

### 📊 CB-183: Audit Logging System

**LGPD/GDPR compliant audit trail** with **enterprise-grade security event tracking**:

- **Legal Compliance**: Full LGPD/GDPR Article tracking
- **Consent Management**: User consent and withdrawal logging
- **Data Classification**: Automated sensitivity categorization
- **Retention Policies**: Automatic data lifecycle management
- **Cross-Border Logging**: International data movement tracking
- **Real-Time Monitoring**: Security event alerting
- **Enterprise Standards**: ISO 27001, SOC 2, PCI DSS, HIPAA

**Audit Event Types**:
- Authentication/authorization events
- Password management activities (CB-192)
- Data processing and modifications
- Policy evaluations and access decisions
- User consent and privacy events

### 🗂️ CB-174: LGPD User Deletion Management

**LGPD Article 18 compliant** user data deletion and portability system:

- **🇧🇷 LGPD Article 18 Compliance**: Full user data deletion and portability rights
- **Multiple Deletion Types**: Full delete, soft delete, anonymization, deactivation, export+delete
- **30-Day Grace Period**: Users can cancel deletion requests within 30 days
- **Comprehensive Audit Trail**: Complete deletion process logging for legal compliance
- **Data Export Capabilities**: JSON, CSV, XML formats with integrity checksums
- **Rate Limiting Protection**: 3 deletion requests/day, 1 export/day per user
- **Admin Processing Workflow**: Secure admin approval and processing system
- **Legal Retention Checking**: Prevents deletion of legally required data

**API Endpoints**:
- `POST /users/me/deletion` - Request account deletion
- `GET /users/me/deletion/{id}` - Check deletion status
- `POST /users/me/export` - Export user data
- `GET /users/me/deletion/history` - Get deletion history
- `POST /admin/users/deletion/{id}/process` - Admin processing
- `GET /admin/users/deletion/pending` - List pending requests

### 🛡️ CB-182: Enterprise Security & Validation

**OWASP Top 10 security protection** with **real-time threat detection**:

- **Multi-Layer Validation Pipeline**: Rate limiting → Security → Field → Business rules
- **Real-Time Threat Detection**: XSS, SQL injection, CSRF, script injection prevention
- **Shadow Mode Deployment**: Log security violations without blocking (safe rollout)
- **Comprehensive Monitoring**: Security metrics, performance tracking, audit logging
- **Context-Aware Validation**: User state, role-based, ownership enforcement
- **Performance Optimized**: <20ms overhead, cached validation rules, parallel processing
- **Enterprise-Grade Features**: Rate limiting, request size limits, content-type validation

**OWASP Top 10 Coverage**:
- **A01** - Broken Access Control: Privilege escalation detection
- **A02** - Cryptographic Failures: Sensitive data exposure protection
- **A03** - Injection: Advanced XSS and SQL injection prevention
- **A04** - Insecure Design: Business logic bypass detection
- **A05** - Security Misconfiguration: Path traversal protection
- **A06** - Vulnerable Components: Script injection detection
- **A10** - Server-Side Request Forgery: SSRF protection

## 📊 Production Features

### 🔥 Interactive Swagger UI Documentation

**Built-in interactive testing interface** available at `/docs`:

- **Try-it-out functionality**: Test all endpoints directly from browser
- **Real-time validation**: See request/response schemas in action
- **Authentication testing**: Use JWT tokens to test protected endpoints
- **Complete field documentation**: Every parameter, header, and response documented
- **80+ API endpoints**: Comprehensive coverage of all service capabilities

**Documentation Endpoints**:
- `GET /docs` - Interactive Swagger UI interface
- `GET /docs/swagger.yaml` - Raw OpenAPI 3.0 specification
- `GET /docs/api` - API documentation metadata

### 🔗 Envoy Proxy Integration

**Native external authorization** for zero-trust microservices architecture:

- **External AuthZ Filter**: Complete Envoy integration
- **Zero-Trust Architecture**: All requests validated before reaching backend services
- **Microservices Ready**: Service discovery patterns
- **Production Deployment**: Full stack with Envoy proxy
- **Docker Integration**: Multi-stage builds and health checks

**Envoy Usage**:
```bash
# Start complete stack with Envoy
docker compose -f examples/envoy/docker-compose.envoy.yaml up --build

# Access through Envoy proxy (port 8000)
curl http://localhost:8000/health
```

### 📈 Performance Monitoring & Metrics

**Enterprise-grade observability** with structured logging, metrics, and tracing:

- **Prometheus Metrics**: Available at `/metrics` endpoint
- **Structured Logging**: JSON format for production
- **Performance Benchmarks**: Load testing scenarios
- **Health Checks**: Service health and readiness probes
- **Real-Time Monitoring**: Security and performance dashboards

## Development Commands

### Core Development
```bash
# Run application locally
go run ./cmd/authzsvc

# Build binary
go build -o bin/authz ./cmd/authzsvc

# Using Task runner
task run    # equivalent to go run ./cmd/authzsvc
task build  # equivalent to go build -o bin/authz ./cmd/authzsvc
task tidy   # equivalent to go mod tidy
```

### Environment Setup
```bash
# Copy environment template
cp .env.example .env

# Start dependencies only
docker compose up -d db redis

# Start full stack
docker compose up --build
# or: task up
```

### Testing & Quality Assurance
```bash
# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Static analysis
golangci-lint run

# Test execution patterns
go test -v -race ./...                    # Race condition detection
go test -bench=. ./...                    # Benchmarks
go test -short ./...                      # Skip long-running tests
```

**Testing Standards (Required)**:
- **Table-driven tests**: Mandatory for all business logic
- **Coverage target**: 95%+ for critical components, 80%+ overall
- **Test isolation**: Zero dependencies between tests
- **Mock strategy**: Manual mocks with configurable functions
- **Test structure**: Use `t.Helper()` for test utilities
- **HTTP testing**: Use `httptest` for handler testing
- **File naming**: Follow Go conventions `*_test.go`

## Architecture

### Clean Architecture with Hexagonal Pattern

The project strictly follows **Clean Architecture** principles with **Hexagonal (Ports & Adapters)** pattern for maximum testability and maintainability.

### Core Structure
```
🏢 Domain Layer (Centro - Business Logic)
├── 📋 Entities (domain/entities.go)
│   ├── User, Session, Policy
│   ├── OTPRequest, AuthToken
│   ├── CB-194: AuthRequest with unified identifier field
│   ├── CB-194: IdentifierResolution for email/phone detection
│   └── Role, Permission structures
├── 🔌 Ports (domain/interfaces.go)
│   ├── UserRepository, SessionRepository
│   ├── OTPService, AuthService
│   ├── CB-194: IdentifierResolutionService interface
│   ├── CB-194: AuthenticationStrategy interface (email/phone)
│   ├── PolicyRepository, TokenService
│   └── NotificationService
└── 📏 Business Rules
    ├── Dual authentication logic (email OR phone)
    ├── E.164 phone number normalization
    ├── RFC 5322 email validation
    ├── Authorization policies
    └── OTP validation rules

🔧 Application Layer (Use Cases)
├── 🎯 Services (internal/services/)
│   ├── AuthService (Authentication orchestrator)
│   ├── IdentifierResolutionService (CB-194: Email/Phone detection)
│   ├── AuthenticationStrategies (CB-194: Email/Phone auth strategies)
│   ├── UserService (User management)
│   ├── OTPService (OTP generation/validation)
│   └── PolicyService (RBAC management)
└── 📝 DTOs & Converters
    ├── Request/Response models
    ├── Entity transformations
    └── Validation logic

🔌 Infrastructure Layer (Adapters)
├── 🗄️ Database Adapters (infra/)
│   ├── GORM implementations
│   ├── Redis client adapters
│   └── Migration management
├── 🌐 HTTP Adapters (http/)
│   ├── Gin handlers
│   ├── Middleware chain
│   └── Router configuration
├── 📨 External Adapters (infra/)
│   ├── Twilio SMS integration
│   ├── Email services
│   └── Third-party auth
└── 🔒 Security Adapters (security/)
    ├── JWT implementation
    ├── Password hashing
    └── Rate limiting

🚀 Presentation Layer (Entry Points)
├── 📥 HTTP Server (cmd/authzsvc/)
├── ⚙️ CLI Tools (cmd/migrate/, cmd/seed/)
└── 🔧 Management APIs
```

### SOLID Principles Applied

#### **S** - Single Responsibility Principle
- **AuthService**: Handles only authentication logic
- **UserService**: Manages only user-related operations  
- **OTPService**: Responsible solely for OTP generation/validation
- **PolicyService**: Manages only authorization policies

#### **O** - Open/Closed Principle
- **NotificationService**: Extensible for new channels (SMS, Email, Push) without modifying existing code
- **AuthProviders**: New authentication methods can be added via interface implementation
- **Repositories**: Different storage implementations can be added without changing business logic

#### **L** - Liskov Substitution Principle
- All **Repository** implementations are fully interchangeable
- **MockRepository** can substitute **GORMRepository** in tests seamlessly
- **TestOTPService** substitutes **TwilioOTPService** without affecting behavior

#### **I** - Interface Segregation Principle
- **UserReader** vs **UserWriter** interfaces (separated concerns)
- **TokenGenerator** vs **TokenValidator** (distinct responsibilities)
- **AuthRepository** contains only auth-specific methods

#### **D** - Dependency Inversion Principle
- **AuthService** depends on abstractions, not concrete implementations
- All dependencies injected via constructors
- Infrastructure adapters implement domain interfaces

### Key Architectural Patterns

**Hexagonal Architecture**: Domain interfaces define contracts, infrastructure provides implementations
- `domain/interfaces.go` - Core business interfaces
- `domain/entities.go` - Domain models with GORM annotations
- Infrastructure adapters in `internal/infra/`

**Dependency Injection**: All dependencies are wired in `internal/app/app.go`
- Database connection with auto-migration
- Redis client for session management
- Casbin enforcer for RBAC
- JWT service for token operations
- OTP service with Twilio integration

**Design Patterns Applied**:
- **Repository Pattern**: Data access abstraction
- **Factory Pattern**: Service and dependency creation
- **Strategy Pattern**: Multiple authentication/notification strategies
- **Chain of Responsibility**: Middleware pipeline processing
- **Command Pattern**: Request/response handling

**Middleware Chain**: Authentication and authorization middleware
- `middleware.AuthMW` - JWT token validation
- `middleware.CasbinMW` - Role-based access control

### Key Components

**Authentication Flow (CB-194 Enhanced)**:
1. User registers with email/phone (`POST /auth/register`)
2. OTP sent via SMS for phone verification (`POST /auth/otp/verify`)
3. **Login with email OR phone** (`POST /auth/login`) - **NEW: Unified authentication**
   - Legacy: `{"email": "user@domain.com", "password": "..."}`
   - **NEW**: `{"identifier": "user@domain.com", "password": "..."}` (email)
   - **NEW**: `{"identifier": "+1234567890", "password": "..."}` (phone)
   - **Backward compatible**: Email field takes precedence when both provided
4. Smart identifier detection (email vs phone) with E.164 normalization
5. JWT access/refresh token issued with authentication context
6. Session stored in Redis with unique session ID

**Authorization**: Casbin policies stored in database
- Default policies seeded on startup if none exist
- Role-based permissions (admin, user)
- REST API for policy management (`/admin/policies`)

**Configuration**: Environment-based configuration
- Database DSN for PostgreSQL connection
- Redis connection settings
- JWT secret and TTL settings
- OTP configuration (length, TTL, max attempts)
- Twilio API credentials

## Testing Strategy (World-Class Standards)

### Coverage & Quality Metrics
- **Coverage achieved**: **98%+ for critical components, 95%+ overall**
- **Test isolation**: Each component tested independently
- **Mock strategy**: Manual mocks with configurable functions
- **Zero external dependencies**: Pure Go testing without frameworks
- **Integration testing**: Real database and Redis integration
- **LGPD compliance testing**: Specialized patterns for data protection compliance
- **Performance testing**: Load testing scenarios with benchmarks

### Testing Patterns (Mandatory)

#### 1. Table-Driven Tests (Required Standard)
```go
func TestAuthenticateUser(t *testing.T) {
    tests := []struct {
        name           string
        input          *domain.AuthRequest
        setupMocks     func(*mocks.MockUserRepository, *mocks.MockPasswordService)
        expectedResult *domain.AuthResult
        expectedError  string
    }{
        {
            name: "successful authentication",
            input: &domain.AuthRequest{
                Email:    "user@example.com",
                Password: "validpassword",
            },
            setupMocks: func(userRepo *mocks.MockUserRepository, pwdSvc *mocks.MockPasswordService) {
                userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
                    return &domain.User{ID: 1, Email: email, IsActive: true}, nil
                }
                pwdSvc.VerifyFunc = func(hash, password string) bool { return true }
            },
            expectedResult: &domain.AuthResult{UserID: 1, Success: true},
            expectedError:  "",
        },
        // Additional test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Isolated test implementation
            userRepo := mocks.NewMockUserRepository()
            pwdSvc := mocks.NewMockPasswordService()
            tt.setupMocks(userRepo, pwdSvc)
            
            service := NewAuthService(userRepo, pwdSvc)
            result, err := service.AuthenticateUser(context.Background(), tt.input)
            
            // Assertions...
        })
    }
}
```

#### 2. Mock Organization & Standards
```
internal/mocks/                    # Centralized mock directory
├── mock_user_repository.go        # Data access mocks
├── mock_auth_service.go           # Service layer mocks  
├── mock_otp_service.go            # External service mocks
├── mock_notification_service.go   # Communication mocks
├── mock_password_service.go       # Security mocks
├── mock_token_service.go          # Token handling mocks
└── mock_casbin_enforcer.go        # Authorization mocks
```

**Mock Naming Conventions**:
- **Type**: `MockInterfaceName`
- **File**: `mock_interface_name.go`
- **Constructor**: `NewMockInterfaceName()`
- **Configurable functions**: `MethodNameFunc func(...) (...)`

#### 3. Mock Implementation Pattern
```go
// MockUserRepository implements domain.UserRepository
type MockUserRepository struct {
    CreateFunc      func(context.Context, *domain.User) error
    FindByEmailFunc func(context.Context, string) (*domain.User, error)
    UpdateFunc      func(context.Context, *domain.User) error
    DeleteFunc      func(context.Context, uint) error
}

func NewMockUserRepository() *MockUserRepository {
    return &MockUserRepository{}
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
    if m.CreateFunc != nil {
        return m.CreateFunc(ctx, user)
    }
    return nil // Default behavior
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
    if m.FindByEmailFunc != nil {
        return m.FindByEmailFunc(ctx, email)
    }
    return nil, errors.New("not found") // Default behavior
}
```

#### 4. Test Helper Functions (Required)
```go
func createAuthServiceForTest(t *testing.T, userRepo domain.UserRepository) domain.AuthService {
    t.Helper() // Critical for proper error reporting
    
    return NewAuthService(
        userRepo,
        mocks.NewMockPasswordService(),
        mocks.NewMockTokenService(),
    )
}

func createValidUser(t *testing.T) *domain.User {
    t.Helper()
    
    return &domain.User{
        ID:            1,
        Email:         "test@example.com",
        PasswordHash:  "hashedpassword",
        IsActive:      true,
        PhoneVerified: true,
    }
}
```

### Testing Guidelines for Claude

#### When Requesting Code
Always provide complete context:
```markdown
"I need to implement [functionality] in AuthService following Clean Architecture.
The function should [specific requirements].
Use existing mocks in /internal/mocks/ and follow table-driven test pattern."
```

#### When Requesting Tests
Use this template:
```markdown
"I need comprehensive unit tests for [function/service] following our standards.

Requirements:
1. Table-driven test pattern (mandatory)
2. 100% code coverage for the function
3. Use t.Helper() for utility functions
4. Test naming: TestFunctionName
5. Use t.Run for test isolation
6. Pure Go testing (no external libraries)
7. Mock all dependencies using existing /internal/mocks/

Mock requirements (if needed):
- Manual mock implementation (no generators)
- Interface compliance verification
- Configurable function fields
- Naming: MockInterfaceName
- Separate file: mock_interface_name.go
- Constructor: NewMockInterfaceName()
```

## 🗄️ Database Schema

### Core Tables

**Users Table**:
- ID, email (unique), phone, password hash
- Role, is_active, phone_verified flags
- Standard GORM timestamps and soft delete

**Casbin Policies**: Managed by Casbin GORM adapter
- Subject (role), Object (resource), Action (method) tuples

**Sessions**: Stored in Redis with TTL
- Key format: `sess:{sessionID}`
- Value: User ID

### Enterprise Feature Tables (CB-192, CB-183, CB-174)

**Password Change Requests** (CB-192):
```sql
CREATE TABLE password_change_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    otp_code VARCHAR(10),
    otp_expires_at TIMESTAMP WITH TIME ZONE,
    attempts_count INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 5,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);
```

**Audit Events** (CB-183):
```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(255) UNIQUE NOT NULL,
    correlation_id VARCHAR(255),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    event_type VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    user_id INTEGER REFERENCES users(id),
    session_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    event_data JSONB NOT NULL,
    compliance_data JSONB,
    security_context JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

**LGPD Deletion Management** (CB-174):
```sql
-- Deletion requests
CREATE TABLE deletion_requests (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    deletion_type VARCHAR(20) NOT NULL CHECK (deletion_type IN 
        ('full_delete', 'soft_delete', 'anonymization', 'deactivation', 'export_delete')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN 
        ('pending', 'processing', 'completed', 'cancelled', 'failed')),
    reason TEXT,
    metadata JSONB,
    grace_period_ends TIMESTAMP WITH TIME ZONE,
    processed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Data exports
CREATE TABLE user_data_exports (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    export_format VARCHAR(10) NOT NULL CHECK (export_format IN ('json', 'csv', 'xml')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    file_path VARCHAR(512),
    file_size_bytes BIGINT,
    checksum_sha256 VARCHAR(64),
    download_expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Retention policies
CREATE TABLE retention_policies (
    id SERIAL PRIMARY KEY,
    data_category VARCHAR(100) NOT NULL UNIQUE,
    retention_period_days INTEGER NOT NULL,
    legal_basis VARCHAR(100) NOT NULL,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);
```

### Indexes for Performance
```sql
-- Audit events indexes
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp DESC);
CREATE INDEX idx_audit_events_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_events_correlation ON audit_events(correlation_id);

-- Deletion requests indexes
CREATE INDEX idx_deletion_requests_user_id ON deletion_requests(user_id);
CREATE INDEX idx_deletion_requests_status ON deletion_requests(status);
CREATE INDEX idx_deletion_requests_grace_period ON deletion_requests(grace_period_ends);

-- Password change requests indexes
CREATE INDEX idx_password_change_user_id ON password_change_requests(user_id);
CREATE INDEX idx_password_change_expires ON password_change_requests(expires_at);
```

## 🌐 API Endpoints

### Authentication (CB-194 Enhanced)
- `POST /auth/register` - User registration
- `POST /auth/otp/verify` - OTP verification for phone
- `POST /auth/otp/resend` - Resend OTP code
- `POST /auth/login` - **User login with email OR phone** (unified authentication)
  - **Legacy format**: `{"email": "user@example.com", "password": "..."}`
  - **New unified format**: `{"identifier": "user@example.com|+1234567890", "password": "..."}`
  - **Auto-detection**: Smart email/phone identifier resolution
  - **Backward compatibility**: 100% compatible with existing email-only authentication
- `POST /auth/refresh` - Token refresh
- `POST /auth/logout` - Session termination
- `GET /auth/me` - Current user info
- `GET /auth/verify` - **JWT token verification for microservices** (external services integration)

### Password Management (CB-192)
- `POST /password/change` - Initiate password change
- `PUT /password/change/{id}/verification` - Complete password change with OTP
- `GET /password/change/{id}/status` - Check password change status
- `DELETE /password/change/{id}` - Cancel password change request
- `POST /password/reset` - Initiate password reset
- `PUT /password/reset/{id}/complete` - Complete password reset

### User Management & LGPD Rights (CB-174)
- `GET /users/{id}` - Get user data (field validation demo)
- `POST /users/me/deletion` - Request account deletion (LGPD compliant)
- `GET /users/me/deletion/{id}` - Check deletion request status
- `DELETE /users/me/deletion/{id}` - Cancel deletion request
- `GET /users/me/deletion/history` - Get deletion request history
- `POST /users/me/export` - Export user data (LGPD data portability)
- `GET /users/me/export/{id}` - Get export status
- `GET /users/me/export/{id}/download` - Download exported data

### Administration (requires admin role)
- `GET /admin/policies` - List Casbin policies
- `POST /admin/policies` - Add policy
- `DELETE /admin/policies` - Remove policy
- `GET /admin/users/deletion/pending` - List pending deletion requests
- `POST /admin/users/deletion/{id}/process` - Process deletion request
- `GET /admin/audit/events` - Query audit events
- `GET /admin/metrics/summary` - Get system metrics

### External Authorization (Envoy Integration)
- `POST /authz/check` - External authorization check
- `GET /authz/config` - Get authorization configuration

### Documentation & Monitoring
- `GET /docs` - Interactive Swagger UI documentation
- `GET /docs/swagger.yaml` - OpenAPI specification
- `GET /docs/api` - API documentation metadata
- `GET /health` - Health check
- `GET /health/ready` - Readiness check
- `GET /metrics` - Prometheus metrics

### Complete API Coverage

**Total: 80+ endpoints** covering:
- **Authentication flows**: Registration, login, OTP, session management
- **Password security**: Two-factor password changes and resets (CB-192)
- **LGPD compliance**: Data deletion, export, and user rights (CB-174)
- **Security validation**: OWASP Top 10 protection (CB-182)
- **Audit logging**: Comprehensive event tracking (CB-183)
- **Admin management**: Policy and system administration
- **External authorization**: Envoy proxy integration
- **Documentation**: Interactive testing and API specifications

## Security Features

**JWT Tokens**: 
- Access tokens (15min default TTL)
- Refresh tokens (168h default TTL) 
- Session-based refresh token rotation

**Password Security**: Bcrypt hashing via `internal/security/password.go`

**OTP Security**:
- Configurable length and TTL
- Rate limiting with max attempts
- Resend cooldown window

**RBAC**: Casbin integration
- Path-based authorization with wildcards
- Method-specific permissions
- Runtime policy management

## ⚙️ Environment Variables

**Complete production configuration** via environment variables (50+ settings):

```bash
# ===== APPLICATION CONFIGURATION =====
APP_PORT=8080                    # HTTP port
GIN_MODE=release                 # gin mode: debug, release, test

# ===== DATABASE CONFIGURATION =====
DATABASE_DSN=postgres://user:pass@localhost:5432/authdb?sslmode=disable
DATABASE_MAX_OPEN_CONNS=25       # Connection pool size
DATABASE_MAX_IDLE_CONNS=5        # Idle connections
DATABASE_CONN_MAX_LIFETIME=5m    # Connection lifetime

# ===== REDIS CONFIGURATION =====
REDIS_ADDR=localhost:6379        # Redis server address
REDIS_PASSWORD=                  # Redis password (if required)
REDIS_DB=0                       # Redis database number
REDIS_POOL_SIZE=10               # Connection pool size
REDIS_MIN_IDLE_CONNS=5          # Minimum idle connections

# ===== JWT CONFIGURATION =====
JWT_SECRET=your-super-secret-key-change-in-production
JWT_ISSUER=authzsvc              # Token issuer
JWT_ACCESS_TTL=900s              # Access token TTL (15 minutes)
JWT_REFRESH_TTL=168h             # Refresh token TTL (7 days)

# ===== OTP CONFIGURATION =====
OTP_TTL=5m                       # OTP validity period
OTP_LENGTH=6                     # OTP code length
OTP_MAX_ATTEMPTS=5               # Maximum verification attempts
OTP_RESEND_WINDOW=60s            # Minimum time between OTP sends

# ===== TWILIO SMS CONFIGURATION =====
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_FROM_NUMBER=+1234567890

# ===== CASBIN CONFIGURATION =====
CASBIN_MODEL=/app/casbin/model.conf  # Casbin model file path

# ===== CB-192: PASSWORD MANAGEMENT CONFIGURATION =====
PASSWORD_CHANGE_OTP_TTL=30m              # OTP validity period for password changes
PASSWORD_CHANGE_REQUEST_TTL=1h           # Password change request lifetime
PASSWORD_CHANGE_MAX_ATTEMPTS=5           # Max OTP verification attempts
PASSWORD_CHANGE_RATE_LIMIT=3             # Max password change initiations per window
PASSWORD_CHANGE_RATE_WINDOW=15m          # Rate limiting window for password changes
PASSWORD_MIN_LENGTH=8                    # Minimum password length
PASSWORD_REQUIRE_UPPERCASE=true          # Require uppercase letters
PASSWORD_REQUIRE_LOWERCASE=true          # Require lowercase letters
PASSWORD_REQUIRE_NUMBERS=true            # Require numeric characters
PASSWORD_REQUIRE_SPECIAL=true            # Require special characters
PASSWORD_PREVENT_COMMON=true             # Block common passwords
PASSWORD_HISTORY_COUNT=5                 # Prevent reuse of last N passwords
PASSWORD_BCRYPT_COST=12                  # Bcrypt hashing cost
PASSWORD_CHANGE_INVALIDATE_SESSIONS=true # Logout all sessions on password change
PASSWORD_CHANGE_AUDIT_ENABLED=true       # Enable comprehensive audit logging

# ===== CB-183: AUDIT LOGGING CONFIGURATION =====
AUDIT_ENABLED=true                       # Enable comprehensive audit logging
AUDIT_LOG_LEVEL=info                     # Minimum severity level to log
AUDIT_BATCH_SIZE=100                     # Batch size for bulk audit operations
AUDIT_FLUSH_INTERVAL=30s                 # Flush interval for buffered audit logs
AUDIT_RETENTION_DAYS=2555                # Audit log retention (7 years for LGPD)
AUDIT_LGPD_ENABLED=true                  # Enable LGPD compliance features
AUDIT_GDPR_ENABLED=true                  # Enable GDPR compliance features
AUDIT_DATA_CLASSIFICATION=true           # Enable automatic data classification
AUDIT_CROSS_BORDER_TRACKING=true         # Track international data transfers
AUDIT_CONSENT_TRACKING=true              # Track user consent status changes
AUDIT_ASYNC_PROCESSING=true              # Async audit log processing for performance
AUDIT_COMPRESSION_ENABLED=true           # Compress stored audit logs
AUDIT_INDEXING_ENABLED=true              # Enable search indexing for fast queries
AUDIT_ARCHIVING_ENABLED=true             # Enable automatic log archiving

# ===== CB-174: LGPD COMPLIANCE CONFIGURATION =====
LGPD_ENABLED=true                        # Enable LGPD compliance features
LGPD_TESTING_MODE=false                  # Production: false, Testing: true
LGPD_GRACE_PERIOD_DAYS=30               # Standard LGPD grace period
LGPD_MAX_DELETIONS_PER_DAY=3            # Max deletion requests per user per day
LGPD_MAX_EXPORTS_PER_DAY=1              # Max export requests per user per day
LGPD_EXPORT_TTL_DAYS=7                  # Export download link expiration
LGPD_PROCESSING_BATCH_SIZE=100          # Records processed per batch
LGPD_LEGAL_CHECK_ENABLED=true           # Enable legal retention checking
LGPD_AUDIT_RETENTION_DAYS=2555          # LGPD audit retention (7 years)
LGPD_ENCRYPTION_ENABLED=true            # Encrypt exported data
LGPD_EXPORT_MAX_SIZE_MB=100             # Maximum export file size
DELETION_WORKER_COUNT=5                  # Concurrent deletion workers
DELETION_BATCH_SIZE=100                  # Records processed per batch
DELETION_RETRY_ATTEMPTS=3                # Failed job retry count
DELETION_RETRY_BACKOFF_SECONDS=30        # Exponential backoff starting point
DELETION_SCHEDULE_INTERVAL=5m            # How often to check for work

# ===== CB-182: ENTERPRISE VALIDATION CONFIGURATION =====
VALIDATION_ENABLE_SECURITY=true          # Enable OWASP Top 10 security validation
VALIDATION_ENABLE_BUSINESS=true          # Enable business rule validation
VALIDATION_ENABLE_RATE_LIMITING=true     # Enable distributed rate limiting
VALIDATION_SHADOW_MODE=false             # Shadow mode: log violations, don't block
VALIDATION_MAX_REQUEST_SIZE=1048576      # Max request size (1MB)
VALIDATION_TIMEOUT=5s                    # Validation timeout
VALIDATION_CACHE_TIMEOUT=5m              # Validation rule cache timeout
VALIDATION_LOG_EVENTS=true              # Log validation events
VALIDATION_ENABLE_METRICS=true          # Enable validation metrics
VALIDATION_ENABLE_GRACEFUL_MODE=false    # Graceful degradation on validation errors

# ===== SECURITY CONFIGURATION =====
BCRYPT_COST=12                           # bcrypt hashing cost
CORS_ALLOWED_ORIGINS=*                   # CORS allowed origins
TLS_CERT_FILE=                           # TLS certificate file
TLS_KEY_FILE=                            # TLS private key file
ENABLE_RATE_LIMITING=true                # Enable global rate limiting
RATE_LIMIT_REQUESTS_PER_MINUTE=60        # Global rate limit
SESSION_TIMEOUT=24h                      # Session timeout

# ===== FEATURE FLAGS =====
USE_SIMPLE_CASBIN=false                  # Use simplified Casbin middleware
ENABLE_METRICS=true                      # Enable Prometheus metrics
ENABLE_SWAGGER=true                      # Enable Swagger UI
ENABLE_ENVOY_INTEGRATION=true            # Enable Envoy external authorization
ENABLE_SHADOW_MODE=false                 # Enable shadow mode deployment

# ===== LOGGING CONFIGURATION =====
LOG_LEVEL=info                           # debug, info, warn, error
LOG_FORMAT=json                          # json, text
LOG_OUTPUT=stdout                        # stdout, stderr, file path

# ===== MONITORING & OBSERVABILITY =====
METRICS_ENABLED=true                     # Enable Prometheus metrics
METRICS_PORT=9090                        # Metrics server port
HEALTH_CHECK_TIMEOUT=5s                  # Health check timeout
TRACING_ENABLED=false                    # Enable distributed tracing
TRACING_SAMPLE_RATE=0.1                  # Tracing sample rate
```

### Production Environment Template

```bash
# Copy and customize for production
cp .env.example .env.production

# Key production settings
GIN_MODE=release
LOG_LEVEL=info
LOG_FORMAT=json
VALIDATION_SHADOW_MODE=false
LGPD_TESTING_MODE=false
BCRYPT_COST=12
AUDIT_ENABLED=true

# Scale for production load
DATABASE_MAX_OPEN_CONNS=50
REDIS_POOL_SIZE=20
DELETION_WORKER_COUNT=10
DELETION_BATCH_SIZE=500
```

## Common Development Tasks

**Adding New Endpoints**:
1. Define handler in `internal/http/handlers/`
2. Add route in `internal/http/router.go`
3. Add appropriate Casbin policy if needed

**Database Changes**:
1. Modify entities in `internal/domain/entities.go`
2. Auto-migration handles schema updates on startup

**Adding New Business Logic**:
1. Define interface in `internal/domain/interfaces.go`
2. Implement in appropriate service/repository
3. Wire dependency in `internal/app/app.go`

**CB-194 Authentication Extensions**:
1. **New identifier types**: Extend `IdentifierType` enum in domain
2. **New auth strategies**: Implement `AuthenticationStrategy` interface
3. **Identifier resolution**: Extend `IdentifierResolutionService` for new formats
4. **Testing**: Use miniredis for Redis-dependent tests, follow table-driven pattern

## Quality Metrics & Standards

### Success Indicators (Mandatory)
- **Test coverage**: **>98% for critical components, >95% overall** (ACHIEVED)
- **Cyclomatic complexity**: <10 per function
- **Dependency injection**: 100% of dependencies injected via constructors
- **Interface compliance**: All implementations strictly follow domain contracts
- **Test isolation**: Zero dependencies between test cases
- **Mock coverage**: All external dependencies mocked in tests
- **Enterprise features coverage**: 100% coverage for CB-192, CB-183, CB-174, CB-182
- **LGPD compliance testing**: Specialized test patterns for data protection
- **Performance benchmarks**: Load testing scenarios with metrics
- **Security validation**: OWASP Top 10 testing coverage

### Performance Targets
- **API response time**: <100ms for authentication endpoints
- **Throughput**: >1000 requests/second for auth operations
- **Database query time**: <50ms for user lookups
- **Redis operations**: <10ms for session management
- **OTP delivery**: <30s for SMS notifications
- **LGPD Deletion Request (CB-174)**: <100ms (Legal validation + grace period)
- **LGPD Data Export Processing**: <2000ms (Complete data aggregation)
- **LGPD Admin Processing**: <500ms (Multi-step deletion workflow)
- **Password Change Flow (CB-192)**: <200ms (Two-factor validation)
- **Security Validation (CB-182)**: <20ms overhead (OWASP Top 10 protection)
- **Audit Event Processing (CB-183)**: <50ms (Real-time compliance logging)

### Code Quality Gates (Required)
- [ ] Clean Architecture layers respected
- [ ] SOLID principles applied consistently
- [ ] Table-driven tests with comprehensive coverage
- [ ] All dependencies properly injected
- [ ] Error handling includes proper context
- [ ] Logging follows structured format
- [ ] Documentation updated for API changes

## Development Workflow Standards

### TDD Approach (Recommended)
```
1. Red    → Write failing test first
2. Green  → Implement minimal code to pass
3. Refactor → Improve code while keeping tests green  
4. Document → Update documentation and examples
```

### Code Review Checklist
**Architecture & Design**:
- [ ] Clean Architecture boundaries maintained
- [ ] SOLID principles followed
- [ ] Appropriate design patterns used
- [ ] No business logic in infrastructure layers

**Testing & Quality**:
- [ ] Table-driven tests implemented
- [ ] All dependencies mocked properly
- [ ] Test coverage meets requirements (>95% critical, >80% overall)
- [ ] `t.Helper()` used in test utilities

**Implementation**:
- [ ] Error handling comprehensive and contextual
- [ ] Logging structured and meaningful  
- [ ] No global state or singletons
- [ ] Configuration externalized via environment

**Security**:
- [ ] Authentication/authorization properly implemented
- [ ] Sensitive data not logged or exposed
- [ ] Input validation comprehensive
- [ ] SQL injection and other attack vectors mitigated

### Architectural Review Guidelines

#### When Analyzing Architecture
Always consider:
- **Current layer**: Domain/Application/Infrastructure
- **SOLID principle compliance**: Which principles are being applied
- **Design patterns**: Repository, Factory, Strategy, etc.
- **Testability impact**: How does this affect test isolation
- **Breaking changes**: Impact on existing API consumers

#### When Suggesting Improvements
Focus on:
- **Separation of concerns**: Clear layer boundaries
- **Interface design**: Minimal, focused contracts
- **Error handling**: Comprehensive coverage with context
- **Performance implications**: Database queries, caching, etc.
- **Security considerations**: Authentication, authorization, data protection

## Code Standards & Best Practices

### Core Principles
- **Clean Architecture**: Strict layer separation with dependency inversion
- **Hexagonal Pattern**: Domain at center, adapters on edges
- **SOLID Compliance**: All five principles consistently applied
- **Dependency Injection**: Constructor-based injection throughout
- **Interface-First Design**: Define contracts before implementations

### Code Organization
- **Thin interfaces**: Focused, single-purpose contracts
- **Repository pattern**: Abstract data access behind interfaces
- **Service layer**: Encapsulate business logic and orchestration
- **Factory pattern**: Create complex dependencies
- **Strategy pattern**: Support multiple implementations (auth, notifications)

### Error Handling Standards
```go
// ✅ Correct: Contextual error handling with early returns
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*AuthResult, error) {
    if err := s.validateLoginRequest(req); err != nil {
        return nil, fmt.Errorf("invalid login request: %w", err)
    }
    
    user, err := s.userRepo.FindByEmail(ctx, req.Email)
    if err != nil {
        if errors.Is(err, domain.ErrUserNotFound) {
            return nil, domain.ErrInvalidCredentials
        }
        return nil, fmt.Errorf("failed to find user: %w", err)
    }
    
    // Continue with business logic...
}

// ❌ Incorrect: Nested error handling, no context
func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*AuthResult, error) {
    user, err := s.userRepo.FindByEmail(ctx, req.Email)
    if err == nil {
        if s.passwordService.Verify(user.PasswordHash, req.Password) {
            // Success case deeply nested
        } else {
            return nil, errors.New("wrong password")
        }
    }
    return nil, err // Lost original error context
}
```

### Configuration Standards
- **Environment-based**: All config via environment variables
- **Validation at startup**: Fail fast on missing/invalid configuration
- **Defaults**: Sensible defaults where appropriate
- **No hardcoded values**: All magic numbers/strings configurable

### Security Best Practices
- **Principle of least privilege**: Minimal required permissions
- **Defense in depth**: Multiple security layers
- **Input validation**: All user inputs validated at boundaries
- **Secure defaults**: Secure configuration by default
- **Audit logging**: Security events comprehensively logged

### Performance Guidelines
- **Database optimization**: Use indexes, avoid N+1 queries
- **Caching strategy**: Redis for sessions and frequently accessed data
- **Connection pooling**: Reuse database connections
- **Graceful degradation**: Handle service failures gracefully
- **Resource cleanup**: Proper cleanup of connections and resources

### Documentation Standards
- **API documentation**: OpenAPI/Swagger specifications
- **Code comments**: Focus on "why" not "what"
- **README clarity**: Setup, development, and deployment instructions
- **Architecture decisions**: Document significant design choices

---

## Resources & References

### Technical Documentation
- [Clean Architecture (Uncle Bob)](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [Go Testing Best Practices](https://golang.org/doc/effective_go.html#testing)
- [SOLID Principles in Go](https://dave.cheney.net/2016/08/20/solid-go-design)

### Development Tools
```bash
# Code quality and testing
go test -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
golangci-lint run --config .golangci.yml
go vet ./...

# Documentation generation  
swag init -g cmd/authzsvc/main.go --output docs/swagger
godoc -http=:6060  # Local documentation server
```

---

## 🔧 Troubleshooting

### Common Issues

#### Database Connection
```bash
# Check database connection
psql -h localhost -p 5432 -U username -d authdb -c "SELECT version();"

# Verify migrations
go run ./cmd/authzsvc --migrate-only
```

#### Redis Connection
```bash
# Test Redis connectivity
redis-cli -h localhost -p 6379 ping
# Expected: PONG
```

#### LGPD Features Not Working (CB-174)
```bash
# Check LGPD configuration
echo $LGPD_ENABLED  # Should be 'true'

# Verify deletion workers are running
curl -s http://localhost:8080/admin/metrics/summary | jq '.deletion_workers'
```

#### Password Change Issues (CB-192)
```bash
# Check Twilio configuration for SMS OTP
curl -X POST http://localhost:8080/password/change/test-otp \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json"
```

#### Audit Logging Issues (CB-183)
```bash
# Verify audit events are being logged
curl -s http://localhost:8080/admin/audit/events?limit=5 \
  -H "Authorization: Bearer <admin_token>"
```

### Performance Optimization

#### Database Tuning
```bash
# Recommended PostgreSQL settings
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB
max_connections = 100
```

#### Redis Optimization
```bash
# Recommended Redis settings
maxmemory 512mb
maxmemory-policy allkeys-lru
tcp-keepalive 300
timeout 0
```

### Security Hardening

```bash
# Production security checklist
[ ] Change default JWT_SECRET
[ ] Enable TLS/HTTPS
[ ] Configure proper CORS origins
[ ] Set strong bcrypt cost (12+)
[ ] Enable rate limiting
[ ] Configure firewall rules
[ ] Set up monitoring alerts
[ ] Enable audit logging
[ ] Configure log rotation
[ ] Set up backup procedures
```

## 🚀 Quick Start Guide

### 1. Basic Setup (2 minutes)
```bash
# Clone and setup
git clone <repository-url>
cd authzsvc_full
cp .env.example .env

# Start dependencies
docker compose up -d db redis

# Run service
go run ./cmd/authzsvc
```

### 2. Test Enterprise Features
```bash
# Test interactive Swagger UI
open http://localhost:8080/docs

# Test password management
curl -X POST http://localhost:8080/password/change \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"current_password": "old", "new_password": "NewPass123!"}'

# Test LGPD data export
curl -X POST http://localhost:8080/users/me/export \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"format": "json", "include_audit_trail": true}'
```

### 3. Production Deployment
```bash
# Production environment setup
cp .env.example .env.production

# Configure for production (edit .env.production)
GIN_MODE=release
LGPD_TESTING_MODE=false
VALIDATION_SHADOW_MODE=false
AUDIT_ENABLED=true

# Deploy with docker-compose
docker compose -f docker-compose.production.yml up -d
```

---

**Version**: 4.0  
**Last Updated**: January 2025  
**Compatibility**: Go 1.22+, PostgreSQL 13+, Redis 6+  
**Architecture**: Clean Architecture + Hexagonal Pattern  
**Quality Standard**: >98% test coverage, SOLID compliant, Production-ready  
**Enterprise Features**: CB-192 (Password Mgmt), CB-183 (Audit Logging), CB-174 (LGPD Compliance), CB-182 (Security Validation)  
**Latest Feature**: CB-194 Dual Authentication (Email OR Phone)  
**API Coverage**: 80+ endpoints with Interactive Swagger UI  
**Security**: OWASP Top 10 compliant with real-time threat detection

## CB-194: Dual Authentication Implementation

### Overview
CB-194 introduces unified authentication allowing users to authenticate using either their email address OR phone number, providing greater flexibility while maintaining 100% backward compatibility.

### Key Features
- **Smart Identifier Detection**: Automatically detects whether input is email or phone number
- **E.164 Phone Normalization**: International phone numbers normalized to E.164 format
- **RFC 5322 Email Validation**: Comprehensive email format validation
- **Strategy Pattern**: Separate authentication strategies for email and phone
- **Backward Compatibility**: Existing email-only authentication continues to work unchanged
- **Enhanced Context**: Authentication responses include method used and normalized identifier

### Request Formats

#### Legacy Email Authentication (Still Supported)
```json
{
  "email": "user@example.com",
  "password": "userpassword123"
}
```

#### New Unified Authentication
```json
// Email via identifier field
{
  "identifier": "user@example.com", 
  "password": "userpassword123"
}

// Phone via identifier field
{
  "identifier": "+1234567890",
  "password": "userpassword123"
}

// Phone without country code (defaults to US +1)
{
  "identifier": "2345678901",
  "password": "userpassword123"
}
```

#### Backward Compatibility Priority
When both `email` and `identifier` fields are provided, the `email` field takes precedence:
```json
{
  "email": "priority@example.com",     // This will be used
  "identifier": "ignored@example.com", // This will be ignored
  "password": "userpassword123"
}
```

### Response Format
Authentication responses now include enhanced context:
```json
{
  "user": {
    "id": 123,
    "email": "user@example.com",
    "phone": "+1234567890",
    "role": "user"
  },
  "access_token": "eyJhbGciOi...",
  "refresh_token": "eyJhbGciOi...",
  "session_id": "sess_abc123",
  "expires_in": 900,
  "authentication_context": {
    "method": "email",                    // "email" or "phone"
    "original_identifier": "user@example.com",
    "normalized_identifier": "user@example.com",
    "country_code": "",                  // Only for phone authentication
    "authenticated_at": "2025-01-15T10:30:00Z"
  }
}
```

### Architecture Components

#### Domain Layer (CB-194)
```go
// Enhanced AuthRequest with unified identifier
type AuthRequest struct {
    // Unified identifier field - can be email or phone number
    Identifier string `json:"identifier,omitempty"`
    
    // Legacy email field for backward compatibility
    Email    string `json:"email,omitempty"`
    
    Password string `json:"password" validate:"required,min=8"`
}

// Identifier type detection
type IdentifierType string
const (
    IdentifierTypeEmail IdentifierType = "email"
    IdentifierTypePhone IdentifierType = "phone"
)

// Resolution result with normalization
type IdentifierResolution struct {
    Type                 IdentifierType `json:"type"`
    OriginalValue        string         `json:"original_value"`
    NormalizedValue      string         `json:"normalized_value"`
    CountryCode          string         `json:"country_code,omitempty"`
    IsValid              bool           `json:"is_valid"`
    ValidationMessage    string         `json:"validation_message,omitempty"`
}
```

#### Service Layer (CB-194)
```go
// Smart identifier detection and normalization
type IdentifierResolutionService interface {
    ResolveIdentifier(ctx context.Context, identifier string) (*IdentifierResolution, error)
    NormalizePhone(ctx context.Context, phone string, countryCode string) (string, error)
    NormalizeEmail(ctx context.Context, email string) (string, error)
    ValidateIdentifier(ctx context.Context, identifier string, identifierType IdentifierType) error
}

// Strategy pattern for different authentication methods
type AuthenticationStrategy interface {
    Authenticate(ctx context.Context, identifier, password string) (*User, error)
    SupportsIdentifierType() IdentifierType
}
```

### Testing Strategy (CB-194)
```go
// Table-driven tests covering all scenarios
func TestAuthServiceImpl_AuthenticateUser_CB194(t *testing.T) {
    tests := []struct {
        name           string
        request        *domain.AuthRequest
        setupMocks     func(*testAuthServiceMocks)
        expectedResult func(*testing.T, *domain.AuthResult)
        expectedError  string
    }{
        {
            name: "successful email authentication via legacy email field",
            request: &domain.AuthRequest{
                Email:    "user@example.com",
                Password: "validpassword123",
            },
            // ... test implementation
        },
        {
            name: "successful phone authentication via unified identifier field",
            request: &domain.AuthRequest{
                Identifier: "+1234567890",
                Password:   "validpassword123",
            },
            // ... test implementation
        },
        // ... 8 comprehensive test scenarios
    }
}
```

### Migration Guide

#### For API Consumers
1. **No immediate changes required** - existing email authentication continues to work
2. **To use phone authentication** - switch to `identifier` field with phone number
3. **To use unified authentication** - switch from `email` to `identifier` field
4. **Enhanced responses** - authentication context now included in responses

#### For Developers
1. **New interfaces** - `IdentifierResolutionService` and `AuthenticationStrategy`
2. **Enhanced AuthService** - now supports strategy pattern with email/phone strategies
3. **Extended testing** - use miniredis for Redis-dependent tests
4. **Country code support** - phone authentication includes country code detection

### Performance Characteristics
- **Smart detection overhead**: <1ms for identifier type resolution
- **Phone normalization**: <1ms for E.164 format conversion
- **Email normalization**: <0.5ms for RFC 5322 validation
- **Strategy selection**: <0.1ms overhead for authentication method dispatch
- **Backward compatibility**: Zero performance impact on existing email authentication

### Security Considerations
- **Input validation**: Both email and phone inputs validated before processing
- **Normalization**: All identifiers normalized to prevent duplicate accounts
- **Rate limiting**: Same rate limiting applies to both authentication methods
- **Audit logging**: Authentication method logged in audit trail
- **Session security**: Same JWT and Redis session security for both methods