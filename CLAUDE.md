# CLAUDE.md

This file provides comprehensive guidance for Claude Code (claude.ai/code) when working with Go projects in this repository, ensuring architectural consistency and quality standards across all services.

## Overview

Authentication and authorization service built with Go 1.22, featuring SMS OTP verification, JWT tokens, and role-based access control using Casbin. The service follows **Clean Architecture with Hexagonal (Ports & Adapters) pattern** for maximum testability, maintainability, and business logic isolation.

**Tech Stack:** Go 1.22+ · Gin · Casbin · GORM · JWT · PostgreSQL · Redis · Twilio

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
│   └── Role, Permission structures
├── 🔌 Ports (domain/interfaces.go)
│   ├── UserRepository, SessionRepository
│   ├── OTPService, AuthService
│   ├── PolicyRepository, TokenService
│   └── NotificationService
└── 📏 Business Rules
    ├── Authentication logic
    ├── Authorization policies
    └── OTP validation rules

🔧 Application Layer (Use Cases)
├── 🎯 Services (internal/services/)
│   ├── AuthService (Authentication orchestrator)
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

**Authentication Flow**:
1. User registers with email/phone (`POST /auth/register`)
2. OTP sent via SMS for phone verification (`POST /auth/otp/verify`)
3. Login with credentials (`POST /auth/login`)
4. JWT access/refresh token issued
5. Session stored in Redis with unique session ID

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
- **Coverage target**: 95%+ for critical components, 80%+ overall
- **Test isolation**: Each component tested independently
- **Mock strategy**: Manual mocks with configurable functions
- **Zero external dependencies**: Pure Go testing without frameworks

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

## Database Schema

**Users Table**:
- ID, email (unique), phone, password hash
- Role, is_active, phone_verified flags
- Standard GORM timestamps and soft delete

**Casbin Policies**: Managed by Casbin GORM adapter
- Subject (role), Object (resource), Action (method) tuples

**Sessions**: Stored in Redis with TTL
- Key format: `sess:{sessionID}`
- Value: User ID

## API Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/otp/verify` - OTP verification for phone
- `POST /auth/login` - User login
- `POST /auth/refresh` - Token refresh
- `POST /auth/logout` - Session termination
- `GET /auth/me` - Current user info

### Administration (requires admin role)
- `GET /admin/policies` - List Casbin policies
- `POST /admin/policies` - Add policy
- `DELETE /admin/policies` - Remove policy

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

## Environment Variables

Key configuration in `.env`:
```bash
# Application
APP_PORT=8080
GIN_MODE=release

# Database
DATABASE_DSN=postgres://...

# Redis
REDIS_ADDR=redis:6379

# JWT
JWT_SECRET=supersecretchangeme
JWT_ACCESS_TTL=900s
JWT_REFRESH_TTL=168h

# OTP
OTP_TTL=5m
OTP_LENGTH=6
OTP_MAX_ATTEMPTS=5

# Twilio
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
TWILIO_FROM_NUMBER=

# Casbin
CASBIN_MODEL=/app/casbin/model.conf
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

## Quality Metrics & Standards

### Success Indicators (Mandatory)
- **Test coverage**: >95% for critical components, >80% overall
- **Cyclomatic complexity**: <10 per function
- **Dependency injection**: 100% of dependencies injected via constructors
- **Interface compliance**: All implementations strictly follow domain contracts
- **Test isolation**: Zero dependencies between test cases
- **Mock coverage**: All external dependencies mocked in tests

### Performance Targets
- **API response time**: <100ms for authentication endpoints
- **Throughput**: >1000 requests/second for auth operations
- **Database query time**: <50ms for user lookups
- **Redis operations**: <10ms for session management
- **OTP delivery**: <30s for SMS notifications

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

**Version**: 3.0  
**Last Updated**: January 2025  
**Compatibility**: Go 1.22+, PostgreSQL 13+, Redis 6+  
**Architecture**: Clean Architecture + Hexagonal Pattern  
**Quality Standard**: >95% test coverage, SOLID compliant, Production-ready