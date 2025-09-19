# AuthzSvc - Enterprise Authentication & Authorization Service

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![Architecture](https://img.shields.io/badge/Architecture-Clean%20%2B%20Hexagonal-green.svg)](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
[![Coverage](https://img.shields.io/badge/Coverage-95%25-brightgreen.svg)](./docs/TESTING.md)
[![SOLID](https://img.shields.io/badge/SOLID-Compliant-blue.svg)](./docs/ARCHITECTURE.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](./docker-compose.yml)
[![Envoy](https://img.shields.io/badge/Envoy-External%20AuthZ-orange.svg)](./examples/envoy/README.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

A **production-ready** authentication and authorization service built with **Clean Architecture** and **Hexagonal Pattern** principles. Features JWT-based authentication, SMS OTP verification, sophisticated field-level RBAC using Casbin, and native **Envoy Proxy** integration for zero-trust microservices architecture.

> **Built for Enterprise**: Battle-tested clean architecture, 95%+ test coverage, comprehensive field validation, and production-grade security features.

## 🚀 Quick Start

Get the service running in under **2 minutes**:

```bash
# 1. Clone and setup
git clone <repository-url>
cd authzsvc_full
cp .env.example .env

# 2. Start dependencies
docker compose up -d db redis

# 3. Run the service
go run ./cmd/authzsvc
```

**Service available at**: `http://localhost:8080`

### ⚡ Health Check
```bash
curl http://localhost:8080/health
# Response: {"status":"ok","timestamp":"2024-01-15T10:30:00Z"}
```

### 🔥 Complete Stack (with Envoy)
```bash
# Full stack with Envoy external authorization
docker compose -f examples/envoy/docker-compose.envoy.yaml up --build

# Access through Envoy proxy
curl http://localhost:8000/health
```

## 📋 Table of Contents

- [🏗 Architecture Overview](#-architecture-overview)
- [✨ Key Features](#-key-features)
- [🔄 Authentication Flow](#-authentication-flow)
- [🛡️ Authorization System](#️-authorization-system)
- [📚 API Reference](#-api-reference)
- [🔗 Envoy Integration](#-envoy-integration)
- [⚙️ Configuration](#️-configuration)
- [🛠 Development](#-development)
- [🚀 Production Deployment](#-production-deployment)
- [🔒 Security](#-security)
- [🔧 Troubleshooting](#-troubleshooting)
- [📊 Performance & Benchmarks](#-performance--benchmarks)

## 🏗 Architecture Overview

AuthzSvc follows **Clean Architecture** with **Hexagonal (Ports & Adapters)** pattern for maximum testability, maintainability, and business logic isolation:

```
🏢 Domain Layer (Business Core)
├── 📋 Entities: User, Session, OTP, Policies
├── 🔌 Ports: Repository & Service Interfaces  
├── 📏 Business Rules: Auth Logic, Validation
└── 🚫 Zero External Dependencies

🎯 Application Layer (Use Cases)
├── AuthService: Authentication orchestration
├── PolicyService: RBAC management
├── OTPService: SMS verification & rate limiting
├── UserService: User lifecycle management
└── PhoneVerificationUseCase: Complex verification workflows

🔌 Infrastructure Layer (Adapters)
├── 🗄️ GORM Repositories (PostgreSQL)
├── 🔴 Redis Sessions & Caching
├── 📱 Twilio SMS Integration
├── 🔐 JWT Token Management
├── 🛡️ Casbin Policy Engine
└── 🌐 Gin HTTP Handlers

🌐 Presentation Layer
├── 🌐 REST API (Gin Framework)
├── 🔗 Envoy External AuthZ
├── 🏥 Health & Metrics Endpoints
└── 📊 Admin Management Interface
```

### Tech Stack

| Component | Technology | Version | Purpose |
|-----------|------------|---------|---------|
| **Language** | Go | 1.22+ | High-performance backend |
| **Framework** | Gin | v1.10+ | HTTP router & middleware |
| **ORM** | GORM | v2.0+ | Database abstraction |
| **Database** | PostgreSQL | 13+ | Primary data store |
| **Cache** | Redis | 6+ | Sessions & rate limiting |
| **Authorization** | Casbin | v2.100+ | Policy-based RBAC |
| **Authentication** | JWT | RS256/HS256 | Stateless tokens |
| **SMS Provider** | Twilio | v1.20+ | OTP delivery |
| **Container** | Docker | 20+ | Deployment & dev environment |

## ✨ Key Features

### 🔐 Authentication
- **JWT-based authentication** with access/refresh token rotation
- **SMS OTP verification** via Twilio with rate limiting and retry logic
- **Session management** with Redis-based distributed storage
- **Password security** with bcrypt hashing (configurable cost)
- **Multi-factor authentication** support with extensible providers
- **Token rotation** on refresh for enhanced security (CB-179)

### 🛡️ Authorization
- **Role-Based Access Control (RBAC)** with Casbin policy engine
- **Field-level authorization** with dynamic validation rules
- **Wildcard path matching** supporting complex patterns (`/api/users/*`)
- **Method-specific permissions** with regex support (`(GET|POST)`)
- **Runtime policy management** via REST API with hot reloading
- **Ownership validation** ensuring users can only access their own data

### 🔗 Integration
- **Native Envoy Proxy support** for external authorization
- **Microservices ready** with service discovery patterns
- **Docker-ready** with multi-stage builds and health checks
- **Kubernetes native** with full deployment manifests
- **Observability** with structured logging, metrics, and tracing
- **Development tooling** with hot reload and testing utilities

### 🧪 Testing & Quality
- **95%+ test coverage** with comprehensive table-driven tests
- **Manual mocks** for all dependencies (no code generation)
- **E2E test suite** with real database and Redis integration
- **Performance benchmarks** with load testing scenarios
- **SOLID principles** enforced throughout codebase
- **Clean Architecture** with strict layer separation

## 🔄 Authentication Flow

### 1. User Registration & Phone Verification

```bash
# Step 1: Register user with email and phone
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "phone": "+1234567890",
    "role": "user"
  }'

# Response:
{
  "data": {
    "message": "User registered successfully. Please verify your phone number.",
    "user_id": 1
  }
}

# Step 2: Send OTP to phone
curl -X POST http://localhost:8080/auth/otp/send \
  -H "Content-Type: application/json" \
  -d '{
    "phone": "+1234567890",
    "user_id": 1
  }'

# Response:
{
  "data": {
    "message": "OTP sent successfully"
  }
}

# Step 3: Verify OTP code
curl -X POST http://localhost:8080/auth/otp/verify \
  -H "Content-Type: application/json" \
  -d '{
    "phone": "+1234567890",
    "code": "123456",
    "user_id": 1
  }'

# Response:
{
  "data": {
    "message": "Phone number verified and activated successfully",
    "user_id": 1
  }
}
```

### 2. Login & Token Management

```bash
# Login and get JWT tokens
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com", 
    "password": "SecurePass123!"
  }'

# Response:
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": 1,
      "email": "user@example.com",
      "role": "user"
    }
  }
}

# Refresh tokens (with automatic rotation)
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'

# Response (new tokens for security):
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}

# Logout (invalidate session)
curl -X POST http://localhost:8080/auth/logout \
  -H "Authorization: Bearer <access_token>"

# Response:
{
  "data": {
    "message": "Logged out successfully"
  }
}
```

### 3. Accessing Protected Resources

```bash
# Get current user profile
curl -X GET http://localhost:8080/auth/me \
  -H "Authorization: Bearer <access_token>"

# Response:
{
  "data": {
    "id": 1,
    "email": "user@example.com",
    "phone": "+1234567890",
    "role": "user",
    "is_active": true,
    "phone_verified": true,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:35:00Z"
  }
}

# Access user-specific data (with field validation)
curl -X GET http://localhost:8080/users/1 \
  -H "Authorization: Bearer <access_token>"
# ✅ Allowed: User can access their own data (path.id==token.user_id)

curl -X GET http://localhost:8080/users/999 \
  -H "Authorization: Bearer <access_token>"
# ❌ Denied: Field validation fails (999 != token.user_id)
```

## 🛡️ Authorization System

AuthzSvc uses **Casbin** for sophisticated RBAC with advanced field-level validation and ownership enforcement:

### Policy Structure

Policies use a **4-column format**: `subject, object, action, validation_rule`

```csv
# Basic role permissions
role_admin, /admin/*, *, *
role_user, /auth/me, GET, *
role_user, /auth/logout, POST, *

# Field-level validation (ownership enforcement)
role_user, /users/:id, GET, path.id==token.user_id
role_user, /users/:id, PUT, path.id==token.user_id
role_user, /api/orders/*, GET, query.user_id==token.user_id

# Complex validation rules
role_user, /api/posts/*, POST, body.author_id==token.user_id
role_user, /api/documents/*, GET, header.tenant==token.tenant
```

### Wildcard & Pattern Support

| Pattern | Matches | Example |
|---------|---------|---------|
| `/api/users/*` | All paths under users | `/api/users/123`, `/api/users/123/posts` |
| `*` | All methods/resources | Universal access |
| `(GET\|POST)` | Specific methods | Only GET and POST allowed |
| `/users/:id` | Path parameters | Extracted for validation |

### Field Validation Rules

Enforce **ownership** and **data access control** with sophisticated validation:

```yaml
# Path parameter validation
- rule: "path.id==token.user_id"
  description: "User can only access their own profile"

# Query parameter validation  
- rule: "query.user_id==token.user_id"
  description: "Filter results by user ownership"

# Request body validation
- rule: "body.owner_id==token.user_id"
  description: "User can only create resources they own"

# Header validation
- rule: "header.tenant==token.tenant"
  description: "Multi-tenant access control"

# Complex rules
- rule: "path.user_id==token.user_id || token.role==admin"
  description: "Users access own data OR admin access all"
```

### Policy Management API

Complete runtime policy management for dynamic authorization:

```bash
# List all policies (admin only)
curl -X GET http://localhost:8080/admin/policies \
  -H "Authorization: Bearer <admin_token>"

# Response:
{
  "data": {
    "policies": [
      ["role_admin", "/admin/*", "*", "*"],
      ["role_user", "/users/:id", "GET", "path.id==token.user_id"],
      ["role_user", "/auth/me", "GET", "*"]
    ]
  }
}

# Add new policy with field validation
curl -X POST http://localhost:8080/admin/policies \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "role_user",
    "object": "/api/posts/*", 
    "action": "GET",
    "rule": "query.author_id==token.user_id"
  }'

# Remove specific policy
curl -X DELETE http://localhost:8080/admin/policies \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "role_user",
    "object": "/api/posts/*",
    "action": "GET"
  }'
```

### Advanced Policy Examples

```bash
# Multi-tenant with ownership
role_user, /tenant/:tid/users/:id, GET, path.tid==token.tenant && path.id==token.user_id

# Time-based access
role_user, /api/reports/*, GET, query.date>=token.start_date && query.date<=token.end_date

# Resource quantity limits
role_user, /api/uploads/*, POST, body.file_count<=token.max_uploads

# Conditional admin access
role_manager, /team/:id/*, *, path.id==token.managed_team || token.role==admin
```

## 📚 API Reference

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required | Request Body | Response |
|--------|----------|-------------|---------------|--------------|----------|
| `POST` | `/auth/register` | Register new user | No | `RegisterRequest` | User ID |
| `POST` | `/auth/login` | User login | No | `LoginRequest` | JWT tokens + user info |
| `POST` | `/auth/refresh` | Refresh tokens | Refresh Token | `RefreshRequest` | New JWT tokens |
| `POST` | `/auth/logout` | Logout user | Access Token | None | Success message |
| `GET` | `/auth/me` | Get current user | Access Token | None | User profile |
| `POST` | `/auth/otp/send` | Send OTP SMS | No | Phone + User ID | Success message |
| `POST` | `/auth/otp/verify` | Verify OTP code | No | `OTPVerifyRequest` | Verification status |

### Administration Endpoints

| Method | Endpoint | Description | Auth Required | Request Body | Response |
|--------|----------|-------------|---------------|--------------|----------|
| `GET` | `/admin/policies` | List all policies | Admin Token | None | Policy list |
| `POST` | `/admin/policies` | Add new policy | Admin Token | Policy data | Success message |
| `DELETE` | `/admin/policies` | Remove policy | Admin Token | Policy identifier | Success message |
| `GET` | `/admin/users` | List users | Admin Token | Query params | Paginated users |
| `PUT` | `/admin/users/:id` | Update user | Admin Token | User updates | Updated user |

### External Authorization (Envoy)

| Method | Endpoint | Description | Usage |
|--------|----------|-------------|-------|
| `POST` | `/external/authz` | Envoy authorization check | Envoy Only |
| `GET` | `/external/health` | External authz health | Monitoring |

### Health & Monitoring

| Method | Endpoint | Description | Response |
|--------|----------|-------------|----------|
| `GET` | `/health` | Service health | `{"status":"ok","timestamp":"..."}`|
| `GET` | `/health/db` | Database health | Connection status |
| `GET` | `/metrics` | Prometheus metrics | Metrics data |

### Request/Response Schemas

#### Registration Request
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "phone": "+1234567890",
  "role": "user"
}
```

#### Login Response
```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIs...", 
    "token_type": "Bearer",
    "expires_in": 900,
    "user": {
      "id": 1,
      "email": "user@example.com",
      "role": "user",
      "phone_verified": true
    }
  }
}
```

#### Error Response Format
```json
{
  "error": "invalid_credentials",
  "message": "Invalid email or password",
  "code": 401,
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_abc123"
}
```

#### Policy Management
```json
{
  "subject": "role_user",
  "object": "/api/posts/*",
  "action": "GET", 
  "rule": "query.author_id==token.user_id"
}
```

## 🔗 Envoy Integration

AuthzSvc provides **native support** for **Envoy Proxy External Authorization**, enabling zero-trust architecture at the proxy layer:

### Quick Setup

```bash
# Complete stack with Envoy
cd examples/envoy
docker-compose -f docker-compose.envoy.yaml up --build

# Access services through Envoy (port 8000)
curl http://localhost:8000/health
```

### Envoy Configuration

```yaml
# envoy.yaml - External Authorization Filter
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.HttpService
      http_service:
        server_uri:
          uri: http://authzsvc:8080
          cluster: authz_cluster
          timeout: 5s
        authorization_request:
          allowed_headers:
            patterns:
              - exact: authorization
              - exact: content-type
              - exact: x-forwarded-for
        authorization_response:
          allowed_upstream_headers:
            patterns:
              - exact: x-user-id
              - exact: x-user-role
              - exact: x-session-id
        path_prefix: /external/authz

# Bypass auth for public endpoints
routes:
  - match:
      prefix: "/health"
    route:
      cluster: backend
    typed_per_filter_config:
      envoy.filters.http.ext_authz:
        "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute
        disabled: true
```

### External Authorization Flow

```mermaid
sequenceDiagram
    participant Client
    participant Envoy
    participant AuthzSvc
    participant Backend
    
    Client->>Envoy: Request with JWT
    Envoy->>AuthzSvc: /external/authz
    AuthzSvc->>AuthzSvc: Validate JWT
    AuthzSvc->>AuthzSvc: Check Casbin policies
    AuthzSvc->>AuthzSvc: Field validation
    AuthzSvc->>Envoy: 200 OK + headers
    Envoy->>Backend: Forward with user headers
    Backend->>Client: Response
```

### Integration Testing

```bash
# Test external authorization endpoint directly
curl -X POST http://localhost:8080/external/authz \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "request": {
        "http": {
          "method": "GET",
          "path": "/users/123", 
          "headers": {
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIs..."
          }
        }
      }
    }
  }'

# Expected response for authorized request:
{
  "status": {"code": 200},
  "headers": {
    "x-user-id": "123",
    "x-user-role": "user",
    "x-session-id": "sess_abc123"
  }
}

# Expected response for denied request:
{
  "status": {"code": 403},
  "body": "Access denied: field validation failed"
}
```

### Production Envoy Setup

```yaml
# docker-compose.prod.yaml
version: '3.9'
services:
  envoy:
    image: envoyproxy/envoy:v1.28-latest
    ports:
      - "80:8080"
      - "443:8443"
    volumes:
      - ./envoy.yaml:/etc/envoy/envoy.yaml
      - ./certs:/etc/certs
    depends_on:
      - authzsvc
    restart: unless-stopped
    
  authzsvc:
    image: authzsvc:production
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - DATABASE_DSN=${DATABASE_DSN}
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

## ⚙️ Configuration

### Environment Variables

Complete configuration via environment variables:

```bash
# Application Configuration
APP_PORT=8080                    # HTTP port
GIN_MODE=release                 # gin mode: debug, release, test

# Database Configuration  
DATABASE_DSN=postgres://user:pass@localhost:5432/authdb?sslmode=disable
DATABASE_MAX_OPEN_CONNS=25      # Connection pool size
DATABASE_MAX_IDLE_CONNS=5       # Idle connections
DATABASE_CONN_MAX_LIFETIME=5m   # Connection lifetime

# Redis Configuration
REDIS_ADDR=localhost:6379       # Redis server address
REDIS_PASSWORD=                 # Redis password (if required)
REDIS_DB=0                      # Redis database number
REDIS_POOL_SIZE=10              # Connection pool size
REDIS_MIN_IDLE_CONNS=5          # Minimum idle connections

# JWT Configuration
JWT_SECRET=your-super-secret-key-change-in-production
JWT_ISSUER=authzsvc             # Token issuer
JWT_ACCESS_TTL=900s             # Access token TTL (15 minutes)
JWT_REFRESH_TTL=168h            # Refresh token TTL (7 days)

# OTP Configuration
OTP_TTL=5m                      # OTP validity period
OTP_LENGTH=6                    # OTP code length
OTP_MAX_ATTEMPTS=5              # Maximum verification attempts
OTP_RESEND_WINDOW=60s           # Minimum time between OTP sends

# Twilio SMS Configuration
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_FROM_NUMBER=+1234567890

# Casbin Configuration
CASBIN_MODEL=/app/casbin/model.conf  # Casbin model file path

# Feature Flags
USE_SIMPLE_CASBIN=false         # Use simplified Casbin middleware
ENABLE_RATE_LIMITING=true       # Enable rate limiting
ENABLE_METRICS=true             # Enable Prometheus metrics

# Security Configuration
BCRYPT_COST=12                  # bcrypt hashing cost
CORS_ALLOWED_ORIGINS=*          # CORS allowed origins
TLS_CERT_FILE=                  # TLS certificate file
TLS_KEY_FILE=                   # TLS private key file

# Logging Configuration
LOG_LEVEL=info                  # debug, info, warn, error
LOG_FORMAT=json                 # json, text
LOG_OUTPUT=stdout               # stdout, stderr, file path
```

### YAML Configuration (Alternative)

```yaml
# config/config.yml
app:
  port: 8080
  gin_mode: release
  cors_allowed_origins: ["*"]

database:
  dsn: "postgres://user:pass@localhost:5432/authdb?sslmode=disable"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime: "5m"

redis:
  addr: "localhost:6379"
  password: ""
  db: 0
  pool_size: 10
  min_idle_conns: 5

jwt:
  secret: "your-super-secret-key"
  issuer: "authzsvc"
  access_ttl: "900s"
  refresh_ttl: "168h"

otp:
  ttl: "5m"
  length: 6
  max_attempts: 5
  resend_window: "60s"

twilio:
  account_sid: ""
  auth_token: ""
  from_number: ""

casbin:
  model_path: "casbin/model.conf"

security:
  bcrypt_cost: 12
  enable_rate_limiting: true

logging:
  level: "info"
  format: "json"
  output: "stdout"
```

### Casbin Model Configuration

```ini
# casbin/model.conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, rule

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
```

### Default Policies

Seeded automatically on first startup:

```csv
# Default RBAC policies
role_admin, *, *, *
role_user, /auth/me, GET, *
role_user, /auth/logout, POST, *
role_user, /users/:id, GET, path.id==token.user_id
role_user, /users/:id, PUT, path.id==token.user_id
```

### Database Migration

Automatic migration on startup, or manual:

```bash
# Automatic migration (default)
go run ./cmd/authzsvc  # Migrates on startup

# Manual migration
go run ./cmd/migrate

# Test database connectivity
go run ./cmd/test-db

# Database health check
curl http://localhost:8080/health/db
```

## 🛠 Development

### Prerequisites

- **Go 1.22+** - Latest stable version
- **PostgreSQL 13+** - Primary database
- **Redis 6+** - Session store & caching
- **Docker & Docker Compose** - Development environment
- **Git** - Version control

### Local Development Setup

```bash
# 1. Clone repository
git clone <repository-url>
cd authzsvc_full

# 2. Install dependencies
go mod download

# 3. Setup environment
cp .env.example .env
# Edit .env with your configuration

# 4. Start dependencies
docker compose up -d db redis

# 5. Initialize database
go run ./cmd/authzsvc  # Auto-migrates

# 6. Start development server
go run ./cmd/authzsvc
```

### Development Commands

```bash
# Hot reload development (install air: go install github.com/cosmtrek/air@latest)
air

# Run tests with coverage
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
open coverage.html

# Run specific test suites
go test -v ./internal/services/...           # Unit tests
go test -v ./internal/tests/e2e/...          # E2E tests
go test -bench=. ./internal/services/...     # Benchmarks
go test -short ./...                         # Skip long-running tests

# Static analysis & linting
golangci-lint run
go vet ./...
go fmt ./...

# Security scanning
gosec ./...

# Build optimized binary
CGO_ENABLED=0 GOOS=linux go build -o bin/authz ./cmd/authzsvc

# Docker development
docker compose up --build              # Full stack
docker compose up -d db redis         # Dependencies only
docker compose logs -f authzsvc       # Follow logs
```

### Project Structure

```
authzsvc_full/
├── cmd/                    # Application entry points
│   ├── authzsvc/          # Main service
│   ├── migrate/           # Database migration tool
│   └── test-db/           # Database connectivity test
├── internal/              # Private application code
│   ├── app/              # Application wiring & startup
│   ├── config/           # Configuration management
│   ├── http/             # HTTP handlers & middleware
│   ├── infrastructure/   # External service adapters
│   ├── services/         # Business logic services
│   ├── mocks/            # Manual test mocks
│   └── tests/            # Integration & E2E tests
├── domain/               # Business entities & interfaces
├── pkg/                  # Public reusable packages
├── docs/                 # Documentation
├── examples/             # Integration examples
│   └── envoy/           # Envoy proxy configuration
├── casbin/              # Casbin model & policies
├── config/              # Configuration files
└── docker-compose.yml   # Development environment
```

### Testing Standards

**Required**: 95%+ test coverage with comprehensive table-driven tests

#### Table-Driven Test Pattern

```go
func TestAuthService_Login(t *testing.T) {
    tests := []struct {
        name           string
        input          *domain.AuthRequest
        setupMocks     func(*mocks.MockUserRepository, *mocks.MockPasswordService)
        expectedResult *domain.AuthResult
        expectedError  string
    }{
        {
            name: "successful login with verified phone",
            input: &domain.AuthRequest{
                Email:    "user@example.com",
                Password: "validpass123",
            },
            setupMocks: func(userRepo *mocks.MockUserRepository, pwdSvc *mocks.MockPasswordService) {
                userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
                    return &domain.User{
                        ID:            1,
                        Email:         email,
                        PasswordHash:  "hashedpass",
                        IsActive:      true,
                        PhoneVerified: true,
                        Role:          "user",
                    }, nil
                }
                pwdSvc.VerifyFunc = func(hash, password string) bool {
                    return hash == "hashedpass" && password == "validpass123"
                }
            },
            expectedResult: &domain.AuthResult{
                User: &domain.User{ID: 1, Email: "user@example.com"},
            },
            expectedError: "",
        },
        {
            name: "login fails with unverified phone",
            input: &domain.AuthRequest{
                Email:    "user@example.com",
                Password: "validpass123",
            },
            setupMocks: func(userRepo *mocks.MockUserRepository, pwdSvc *mocks.MockPasswordService) {
                userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
                    return &domain.User{
                        ID:            1,
                        Email:         email,
                        IsActive:      true,
                        PhoneVerified: false, // Not verified
                        Role:          "user",
                    }, nil
                }
                pwdSvc.VerifyFunc = func(hash, password string) bool { return true }
            },
            expectedResult: nil,
            expectedError:  "phone not verified",
        },
        // Additional test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Setup
            userRepo := mocks.NewMockUserRepository()
            pwdSvc := mocks.NewMockPasswordService()
            tt.setupMocks(userRepo, pwdSvc)
            
            service := services.NewAuthService(userRepo, pwdSvc)
            
            // Execute
            result, err := service.Login(context.Background(), tt.input)
            
            // Assert
            if tt.expectedError != "" {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.expectedError)
            } else {
                assert.NoError(t, err)
                assert.Equal(t, tt.expectedResult.User.ID, result.User.ID)
            }
        })
    }
}
```

#### Manual Mock Pattern

```go
// MockUserRepository implements domain.UserRepository
type MockUserRepository struct {
    CreateFunc      func(context.Context, *domain.User) error
    FindByEmailFunc func(context.Context, string) (*domain.User, error)
    FindByIDFunc    func(context.Context, uint) (*domain.User, error)
    UpdateFunc      func(context.Context, *domain.User) error
    ActivatePhoneFunc func(context.Context, uint) error
}

func NewMockUserRepository() *MockUserRepository {
    return &MockUserRepository{}
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
    if m.FindByEmailFunc != nil {
        return m.FindByEmailFunc(ctx, email)
    }
    return nil, domain.ErrUserNotFound // Default behavior
}

func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
    if m.CreateFunc != nil {
        return m.CreateFunc(ctx, user)
    }
    return nil
}

// ... implement all interface methods
```

### Code Quality Standards

- **Clean Architecture**: Strict layer separation with dependency inversion
- **SOLID Principles**: Applied consistently throughout codebase
- **Interface-First Design**: Define contracts before implementations
- **Dependency Injection**: Constructor-based injection only
- **Error Handling**: Comprehensive with proper error wrapping
- **Documentation**: Self-documenting code with meaningful names

### Contributing Guidelines

1. **Fork & Branch**: Create feature branch from main
2. **Follow Standards**: Adhere to code quality standards
3. **Write Tests**: Maintain 95%+ test coverage
4. **Document Changes**: Update documentation as needed
5. **Submit PR**: Include comprehensive description and tests

## 🚀 Production Deployment

### Docker Deployment

#### Multi-Stage Production Dockerfile

```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -o authzsvc ./cmd/authzsvc

# Production stage
FROM gcr.io/distroless/static-debian12

COPY --from=builder /app/authzsvc /
COPY --from=builder /app/casbin/model.conf /app/casbin/model.conf
COPY --from=builder /app/config/ /app/config/

# Security: Run as non-root user
USER 65534:65534

ENV CASBIN_MODEL=/app/casbin/model.conf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/authzsvc", "healthcheck"]

ENTRYPOINT ["/authzsvc"]
```

#### Production Docker Compose

```yaml
version: '3.9'

services:
  authzsvc:
    image: authzsvc:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - DATABASE_DSN=${DATABASE_DSN}
      - REDIS_ADDR=redis:6379
      - REDIS_PASSWORD=${REDIS_PASSWORD}
      - JWT_SECRET=${JWT_SECRET}
      - TWILIO_ACCOUNT_SID=${TWILIO_ACCOUNT_SID}
      - TWILIO_AUTH_TOKEN=${TWILIO_AUTH_TOKEN}
      - GIN_MODE=release
      - LOG_LEVEL=info
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
      
  db:
    image: postgres:16-alpine
    restart: unless-stopped
    environment:
      POSTGRES_DB: ${DB_NAME:-authdb}
      POSTGRES_USER: ${DB_USER:-authuser}
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/db-init.sql:/docker-entrypoint-initdb.d/init.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${DB_USER:-authuser} -d ${DB_NAME:-authdb}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1'
      
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    command: redis-server --appendonly yes --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    deploy:
      resources:
        limits:
          memory: 256M
          cpus: '0.25'

  # Optional: Nginx reverse proxy
  nginx:
    image: nginx:alpine
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - authzsvc

volumes:
  postgres_data:
    driver: local
  redis_data:
    driver: local

networks:
  default:
    name: authz_network
```

### Kubernetes Deployment

#### Namespace & ConfigMap

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: authzsvc
  labels:
    app: authzsvc

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: authzsvc-config
  namespace: authzsvc
data:
  config.yml: |
    app:
      port: 8080
      gin_mode: release
    database:
      max_open_conns: 25
      max_idle_conns: 5
      conn_max_lifetime: "5m"
    redis:
      pool_size: 10
      min_idle_conns: 5
    jwt:
      access_ttl: "900s"
      refresh_ttl: "168h"
    otp:
      ttl: "5m"
      length: 6
      max_attempts: 5
    logging:
      level: "info"
      format: "json"
```

#### Secrets

```yaml
# k8s/secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: authzsvc-secrets
  namespace: authzsvc
type: Opaque
data:
  database-dsn: <base64-encoded-dsn>
  redis-password: <base64-encoded-password>
  jwt-secret: <base64-encoded-jwt-secret>
  twilio-account-sid: <base64-encoded-sid>
  twilio-auth-token: <base64-encoded-token>
```

#### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: authzsvc
  namespace: authzsvc
  labels:
    app: authzsvc
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app: authzsvc
  template:
    metadata:
      labels:
        app: authzsvc
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65534
        fsGroup: 65534
      containers:
      - name: authzsvc
        image: authzsvc:v1.0.0
        imagePullPolicy: Always
        ports:
        - containerPort: 8080
          name: http
          protocol: TCP
        env:
        - name: DATABASE_DSN
          valueFrom:
            secretKeyRef:
              name: authzsvc-secrets
              key: database-dsn
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: authzsvc-secrets
              key: redis-password
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: authzsvc-secrets
              key: jwt-secret
        - name: TWILIO_ACCOUNT_SID
          valueFrom:
            secretKeyRef:
              name: authzsvc-secrets
              key: twilio-account-sid
        - name: TWILIO_AUTH_TOKEN
          valueFrom:
            secretKeyRef:
              name: authzsvc-secrets
              key: twilio-auth-token
        - name: REDIS_ADDR
          value: "redis-service:6379"
        volumeMounts:
        - name: config
          mountPath: /app/config
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 2
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: authzsvc-config
      restartPolicy: Always
      terminationGracePeriodSeconds: 30
```

#### Service & Ingress

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: authzsvc-service
  namespace: authzsvc
  labels:
    app: authzsvc
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: authzsvc

---
# k8s/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: authzsvc-ingress
  namespace: authzsvc
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - auth.yourdomain.com
    secretName: authzsvc-tls
  rules:
  - host: auth.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: authzsvc-service
            port:
              number: 8080
```

### Horizontal Pod Autoscaler

```yaml
# k8s/hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: authzsvc-hpa
  namespace: authzsvc
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: authzsvc
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Pods
        value: 1
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 60
      policies:
      - type: Pods
        value: 2
        periodSeconds: 60
```

### Performance Tuning

```bash
# Database optimization
DATABASE_MAX_OPEN_CONNS=25
DATABASE_MAX_IDLE_CONNS=5
DATABASE_CONN_MAX_LIFETIME=5m

# Redis optimization
REDIS_POOL_SIZE=10
REDIS_MIN_IDLE_CONNS=5
REDIS_MAX_RETRIES=3

# Application tuning
GOMAXPROCS=4                    # CPU cores
GOMEMLIMIT=512MiB              # Memory limit
GOGC=100                       # GC target percentage

# JWT optimization
JWT_ACCESS_TTL=900s            # Balance security vs performance
JWT_REFRESH_TTL=168h           # Longer for better UX

# Rate limiting
RATE_LIMIT_REQUESTS=1000
RATE_LIMIT_WINDOW=1h
RATE_LIMIT_BURST=100
```

### Monitoring & Observability

#### Prometheus Metrics

```go
// Key metrics exposed at /metrics
http_requests_total{method="POST",endpoint="/auth/login",status="200"}
http_request_duration_seconds{method="POST",endpoint="/auth/login"}
jwt_tokens_generated_total{type="access"}
jwt_tokens_generated_total{type="refresh"}
otp_requests_total{status="sent"}
otp_verifications_total{status="success"}
casbin_policy_evaluations_total{result="allow"}
redis_operations_total{operation="get",status="hit"}
database_connections_active
database_connections_idle
```

#### Health Checks

```bash
# Application health
curl http://localhost:8080/health
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00Z",
  "version": "v1.0.0",
  "uptime": "2h15m30s"
}

# Database health
curl http://localhost:8080/health/db
{
  "status": "ok",
  "ping_time": "2ms",
  "open_connections": 5,
  "idle_connections": 3
}

# Redis health
curl http://localhost:8080/health/redis
{
  "status": "ok",
  "ping_time": "1ms",
  "pool_size": 10,
  "active_connections": 2
}
```

#### Logging Configuration

```yaml
# Structured JSON logging for production
logging:
  level: "info"
  format: "json"
  output: "stdout"
  fields:
    service: "authzsvc"
    version: "v1.0.0"
    environment: "production"
```

## 🔒 Security

### Security Features

#### Authentication Security
- **JWT Tokens**: HS256/RS256 signing with configurable secrets
- **Token Rotation**: Automatic refresh token rotation on use
- **Session Validation**: Redis-based session verification
- **Password Hashing**: bcrypt with configurable cost (default: 12)
- **OTP Security**: Time-limited codes with attempt limiting and rate limiting
- **Multi-Factor Authentication**: Extensible MFA framework

#### Authorization Security
- **Principle of Least Privilege**: Default deny, explicit allow policies
- **Field-Level Security**: Validate request data against token claims
- **Ownership Enforcement**: Users can only access their own data
- **Policy Auditing**: All authorization decisions logged with context
- **Dynamic Policies**: Runtime policy updates without service restart

#### Infrastructure Security
- **TLS Encryption**: HTTPS/TLS for all communications
- **Secrets Management**: Environment-based configuration
- **Rate Limiting**: Prevent brute force and DoS attacks
- **Input Validation**: Comprehensive request validation
- **SQL Injection Prevention**: Parameterized queries via GORM
- **XSS Protection**: Proper input sanitization and output encoding

### Security Best Practices

#### Production Secrets Management

```bash
# Generate secure JWT secret (32+ bytes)
JWT_SECRET=$(openssl rand -base64 32)

# Strong database passwords
DB_PASSWORD=$(openssl rand -base64 24)

# Secure Redis password
REDIS_PASSWORD=$(openssl rand -base64 16)

# Store secrets securely (example: AWS Secrets Manager)
aws secretsmanager create-secret \
  --name "authzsvc/jwt-secret" \
  --secret-string "${JWT_SECRET}"
```

#### Network Security

```yaml
# Security groups / firewall rules
ingress_rules:
  - port: 443
    protocol: tcp
    cidr_blocks: ["0.0.0.0/0"]  # HTTPS from internet
  - port: 8080
    protocol: tcp
    cidr_blocks: ["10.0.0.0/8"]  # Internal traffic only
  - port: 5432
    protocol: tcp
    cidr_blocks: ["10.0.1.0/24"]  # Database access from app subnet only
  - port: 6379
    protocol: tcp
    cidr_blocks: ["10.0.1.0/24"]  # Redis access from app subnet only

# TLS Configuration
tls:
  min_version: "1.2"
  ciphers:
    - ECDHE-RSA-AES256-GCM-SHA384
    - ECDHE-RSA-AES128-GCM-SHA256
    - ECDHE-RSA-AES256-SHA384
  protocols:
    - TLSv1.2
    - TLSv1.3
```

#### Security Headers (Nginx/Envoy)

```nginx
# nginx.conf - Security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;

# Remove server information
server_tokens off;
```

#### Rate Limiting Configuration

```yaml
# Rate limiting rules
rate_limits:
  login:
    requests: 5
    window: "5m"
    burst: 2
  otp_send:
    requests: 3
    window: "1h"
    burst: 1
  register:
    requests: 10
    window: "1h"
    burst: 3
  password_reset:
    requests: 3
    window: "15m"
    burst: 1
```

### Vulnerability Management

#### Security Scanning

```bash
# Go security scanner
go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
gosec ./...

# Dependency vulnerability scanning
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...

# Docker image scanning
docker scout cves authzsvc:latest

# OWASP dependency check
dependency-check --project authzsvc --scan . --format JSON
```

#### Security Checklist

- [ ] **Secrets**: All secrets in environment variables or secret management
- [ ] **TLS**: HTTPS enforced with strong cipher suites
- [ ] **Authentication**: MFA enabled for admin accounts
- [ ] **Authorization**: Principle of least privilege enforced
- [ ] **Logging**: Security events logged and monitored
- [ ] **Updates**: Dependencies regularly updated
- [ ] **Scanning**: Regular vulnerability scans
- [ ] **Backup**: Encrypted backups with tested recovery
- [ ] **Monitoring**: Real-time security monitoring
- [ ] **Incident Response**: Security incident response plan

#### Security Monitoring

```yaml
# Security alerts and monitoring
alerts:
  - name: "High Failed Login Rate"
    condition: "login_failures > 100 in 5m"
    action: "alert security team"
    
  - name: "JWT Token Anomaly"
    condition: "token_generation_rate > 1000/min"
    action: "investigate and potentially rate limit"
    
  - name: "Admin Access Pattern"
    condition: "admin_endpoint_access outside business_hours"
    action: "immediate security review"
    
  - name: "Database Access Anomaly"
    condition: "database_connections > 50"
    action: "check for potential attack"
```

## 🔧 Troubleshooting

### Common Issues & Solutions

#### Database Connection Issues

```bash
# Issue: "connection refused"
# Solution: Check PostgreSQL is running and accessible
docker compose ps db
docker compose logs db

# Test connection manually
psql "postgres://user:pass@localhost:5432/authdb"

# Issue: "too many connections"
# Solution: Adjust connection pool settings
export DATABASE_MAX_OPEN_CONNS=10
export DATABASE_MAX_IDLE_CONNS=5
```

#### Redis Connection Issues

```bash
# Issue: "no route to host"
# Solution: Check Redis connectivity
redis-cli -h localhost -p 6379 ping

# Issue: Session validation failing
# Solution: Check Redis data and TTL
redis-cli -h localhost -p 6379
> KEYS sess:*
> TTL sess:your_session_id
> GET sess:your_session_id

# Issue: Redis memory issues
# Solution: Monitor Redis memory usage
redis-cli -h localhost -p 6379 INFO memory
```

#### JWT Token Issues

```bash
# Issue: "token expired"
# Response: Use refresh endpoint
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'

# Issue: "invalid signature"
# Solution: Check JWT_SECRET consistency
echo $JWT_SECRET
# Ensure same secret across all instances

# Issue: "token format invalid"
# Solution: Check Authorization header format
# Correct: "Authorization: Bearer <token>"
# Incorrect: "Authorization: <token>"
```

#### OTP Issues

```bash
# Issue: SMS not received
# Check: Twilio credentials and phone format
curl -X POST https://api.twilio.com/2010-04-01/Accounts/$TWILIO_ACCOUNT_SID/Messages.json \
  -u $TWILIO_ACCOUNT_SID:$TWILIO_AUTH_TOKEN \
  -d "From=$TWILIO_FROM_NUMBER" \
  -d "To=+1234567890" \
  -d "Body=Test message"

# Issue: "OTP expired"
# Solution: Check OTP_TTL configuration (default 5 minutes)
export OTP_TTL=10m  # Increase if needed

# Issue: "max attempts exceeded"
# Solution: Wait for reset window or adjust limits
export OTP_MAX_ATTEMPTS=3
export OTP_RESEND_WINDOW=120s
```

#### Authorization Issues

```bash
# Issue: "access denied" for valid user
# Debug: Check Casbin policies
curl -X GET http://localhost:8080/admin/policies \
  -H "Authorization: Bearer <admin_token>"

# Issue: Field validation failing
# Debug: Enable debug logging
export GIN_MODE=debug
export LOG_LEVEL=debug

# Check token claims
echo "<jwt_token>" | base64 -d

# Issue: Policy not taking effect
# Solution: Check policy syntax and reload
# Policies are auto-reloaded, but check for syntax errors
```

#### Performance Issues

```bash
# Issue: Slow response times
# Debug: Check database query performance
export LOG_LEVEL=debug  # Enable query logging

# Monitor database connections
curl http://localhost:8080/health/db

# Issue: High memory usage
# Debug: Check Go runtime stats
curl http://localhost:8080/debug/pprof/heap
go tool pprof http://localhost:8080/debug/pprof/heap

# Issue: Redis performance
# Debug: Check Redis slowlog
redis-cli -h localhost -p 6379 SLOWLOG GET 10
```

### Debugging Tools

#### Enable Debug Mode

```bash
# Development debugging
export GIN_MODE=debug
export LOG_LEVEL=debug

# Check logs for detailed information
docker compose logs -f authzsvc | jq '.'

# Enable SQL query logging
export DB_LOG_LEVEL=info
```

#### Health Check Diagnostics

```bash
# Comprehensive health check
curl -s http://localhost:8080/health | jq '.'

# Database connectivity
curl -s http://localhost:8080/health/db | jq '.'

# Redis connectivity
curl -s http://localhost:8080/health/redis | jq '.'

# Component status check
go run ./cmd/test-db
redis-cli -h localhost -p 6379 ping
```

#### Performance Profiling

```bash
# CPU profiling
go test -cpuprofile=cpu.prof ./internal/services/...
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof ./internal/services/...
go tool pprof mem.prof

# Live profiling (if enabled)
curl http://localhost:8080/debug/pprof/profile?seconds=30 > profile.prof
go tool pprof profile.prof

# Benchmark tests
go test -bench=. -benchmem ./internal/services/...
```

#### Network Diagnostics

```bash
# Test external authorization directly
curl -X POST http://localhost:8080/external/authz \
  -H "Content-Type: application/json" \
  -d '{
    "attributes": {
      "request": {
        "http": {
          "method": "GET",
          "path": "/users/123",
          "headers": {"authorization": "Bearer <token>"}
        }
      }
    }
  }' | jq '.'

# Test through Envoy proxy
curl -v http://localhost:8000/auth/me \
  -H "Authorization: Bearer <token>"

# Check Envoy admin interface
curl http://localhost:8001/stats | grep ext_authz
curl http://localhost:8001/config_dump | jq '.configs[].dynamic_listeners'
```

## 📊 Performance & Benchmarks

### Performance Targets

| Operation | Target Latency | Throughput | Notes |
|-----------|---------------|------------|-------|
| JWT Token Generation | < 10ms | 5,000 ops/sec | HS256 signing |
| JWT Token Validation | < 5ms | 10,000 ops/sec | Cached validation |
| Database User Lookup | < 20ms | 2,000 ops/sec | Indexed queries |
| Redis Session Check | < 5ms | 15,000 ops/sec | In-memory cache |
| OTP Generation | < 50ms | 500 ops/sec | Twilio API call |
| Authorization Check | < 15ms | 5,000 ops/sec | Casbin + cache |

### Benchmark Results

```bash
# Run benchmark tests
go test -bench=. -benchmem ./internal/services/

# Sample results:
BenchmarkAuthService_Login-8                    1000    1.2ms/op    256 B/op    4 allocs/op
BenchmarkTokenService_Generate-8               10000    0.8ms/op    128 B/op    2 allocs/op
BenchmarkTokenService_Validate-8               20000    0.3ms/op     64 B/op    1 allocs/op
BenchmarkCasbinEnforcer_Enforce-8               5000    0.6ms/op     96 B/op    2 allocs/op
BenchmarkRedisSessionRepository_Get-8          50000    0.1ms/op     32 B/op    1 allocs/op
```

### Load Testing

```bash
# Install k6 for load testing
curl https://github.com/grafana/k6/releases/download/v0.45.0/k6-v0.45.0-linux-amd64.tar.gz -L | tar xvz --strip-components 1

# Load test authentication flow
k6 run --vus 100 --duration 30s loadtest/auth_flow.js

# Load test external authorization
k6 run --vus 200 --duration 60s loadtest/envoy_authz.js
```

#### Load Test Script Example

```javascript
// loadtest/auth_flow.js
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  vus: 100,
  duration: '30s',
  thresholds: {
    http_req_duration: ['p(95)<100'], // 95% under 100ms
    http_req_failed: ['rate<0.01'],   // Less than 1% failures
  },
};

export default function() {
  // Register user
  let registerRes = http.post('http://localhost:8080/auth/register', {
    email: `user${Math.random()}@example.com`,
    password: 'password123',
    phone: '+1234567890',
  });
  
  check(registerRes, {
    'register status is 201': (r) => r.status === 201,
  });
  
  // Login user
  let loginRes = http.post('http://localhost:8080/auth/login', {
    email: 'existing@example.com',
    password: 'password123',
  });
  
  check(loginRes, {
    'login status is 200': (r) => r.status === 200,
    'has access token': (r) => r.json().data.access_token !== undefined,
  });
}
```

### Monitoring & Metrics

#### Key Performance Indicators

```bash
# Application metrics (Prometheus format)
# Authentication success rate
auth_requests_total{status="success"} / auth_requests_total * 100

# Token validation rate
jwt_validations_total{status="valid"} / jwt_validations_total * 100

# Database query performance
histogram_quantile(0.95, database_query_duration_seconds_bucket)

# Redis operation performance
histogram_quantile(0.95, redis_operation_duration_seconds_bucket)

# Authorization success rate
authz_decisions_total{result="allow"} / authz_decisions_total * 100
```

#### Grafana Dashboard Queries

```promql
# Request rate
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])

# Response time percentiles
histogram_quantile(0.50, rate(http_request_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))
histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))

# Database connection pool
database_connections_active
database_connections_idle

# Redis memory usage
redis_memory_used_bytes / redis_memory_max_bytes * 100
```

### Optimization Tips

#### Database Optimization

```sql
-- Create indexes for frequently queried fields
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_users_phone ON users(phone);
CREATE INDEX CONCURRENTLY idx_users_active ON users(is_active) WHERE is_active = true;

-- Optimize policy queries
CREATE INDEX CONCURRENTLY idx_casbin_rule_ptype ON casbin_rule(ptype);
CREATE INDEX CONCURRENTLY idx_casbin_rule_v0 ON casbin_rule(v0);
```

#### Redis Optimization

```bash
# Redis configuration optimizations
redis-cli CONFIG SET maxmemory-policy allkeys-lru
redis-cli CONFIG SET timeout 300
redis-cli CONFIG SET tcp-keepalive 60

# Monitor Redis performance
redis-cli --latency-history -i 1
redis-cli --stat
```

#### Application Optimization

```go
// Connection pool tuning
db.SetMaxOpenConns(25)
db.SetMaxIdleConns(5)
db.SetConnMaxLifetime(5 * time.Minute)

// Redis pool optimization
&redis.Options{
    PoolSize:     10,
    MinIdleConns: 5,
    MaxRetries:   3,
    DialTimeout:  5 * time.Second,
    ReadTimeout:  3 * time.Second,
    WriteTimeout: 3 * time.Second,
}

// JWT optimization
// Use cached claims validation
// Pre-compile regex patterns
// Optimize token size
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Code of Conduct
- Development Process  
- Pull Request Process
- Coding Standards
- Testing Requirements
- Documentation Standards

### Quick Contribution Setup

```bash
# Fork and clone
git clone https://github.com/your-username/authzsvc_full.git
cd authzsvc_full

# Create feature branch
git checkout -b feature/your-feature-name

# Setup development environment
make dev-setup

# Run tests before submitting
make test-all

# Submit pull request
git push origin feature/your-feature-name
```

## 🏆 Acknowledgments

- **Clean Architecture** principles by Robert C. Martin
- **Hexagonal Architecture** by Alistair Cockburn
- **Casbin** authorization library
- **Gin** web framework
- **GORM** ORM library
- **Go** programming language community

---

## 📞 Support & Community

- **Documentation**: [Full documentation](./docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/authzsvc/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-org/authzsvc/discussions)
- **Security**: [Security Policy](./SECURITY.md)

---

**Built with ❤️ using Clean Architecture principles, SOLID design patterns, and Go best practices.**

*Ready for enterprise production deployment with 95%+ test coverage, comprehensive security, and battle-tested performance.*