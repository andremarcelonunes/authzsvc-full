# Mock System Documentation

This directory contains comprehensive mocks for all domain interfaces in the authentication service, following Clean Architecture and CLAUDE.md standards.

## Overview

All mocks implement their respective domain interfaces and follow the configurable function fields pattern, enabling flexible testing scenarios with minimal setup.

## Available Mocks

### Phase 1 - Core Authentication Mocks
- **MockUserRepository** - `domain.UserRepository` interface
- **MockPasswordService** - `domain.PasswordService` interface  
- **MockTokenService** - `domain.TokenService` interface
- **MockSessionRepository** - `domain.SessionRepository` interface

### Phase 2 - Additional Service Mocks
- **MockAuthService** - `domain.AuthService` interface
- **MockNotificationService** - `domain.NotificationService` interface
- **MockPolicyService** - `domain.PolicyService` interface
- **MockOTPService** - `domain.OTPService` interface
- **MockCasbinEnforcer** - Casbin enforcer methods for authorization testing

## Usage Patterns

### 1. Basic Mock Creation
```go
// Create mock with default behaviors
userRepo := mocks.NewMockUserRepository()
```

### 2. Configuring Mock Behavior
```go
// Configure specific method behavior
userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
    return &domain.User{ID: 1, Email: email}, nil
}
```

### 3. Table-Driven Test Pattern
```go
func TestAuthService_Login(t *testing.T) {
    tests := []struct {
        name       string
        email      string
        password   string
        setupMocks func(*mocks.MockUserRepository, *mocks.MockPasswordService)
        expected   *domain.AuthResult
        expectErr  string
    }{
        {
            name:     "successful login",
            email:    "user@example.com", 
            password: "validpassword",
            setupMocks: func(userRepo *mocks.MockUserRepository, pwdSvc *mocks.MockPasswordService) {
                userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
                    return &domain.User{ID: 1, Email: email, IsActive: true}, nil
                }
                pwdSvc.VerifyFunc = func(hash, password string) bool {
                    return true
                }
            },
            expected: &domain.AuthResult{/* ... */},
        },
        // Additional test cases...
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            userRepo := mocks.NewMockUserRepository()
            pwdSvc := mocks.NewMockPasswordService()
            
            if tt.setupMocks != nil {
                tt.setupMocks(userRepo, pwdSvc)
            }
            
            service := NewAuthService(userRepo, pwdSvc, /* other deps */)
            result, err := service.Login(context.Background(), tt.email, tt.password)
            
            // Assertions...
        })
    }
}
```

## Default Behaviors

All mocks provide sensible default behaviors:

### MockUserRepository
- `Create`: Returns success
- `FindByEmail`: Returns `domain.ErrUserNotFound`
- `FindByID`: Returns `domain.ErrUserNotFound`
- `Update`: Returns success
- `ActivatePhone`: Returns success

### MockPasswordService
- `Hash`: Returns `"hashed_" + password`
- `Verify`: Checks if hash equals `"hashed_" + password`

### MockTokenService
- `GenerateAccessToken`: Returns formatted mock token
- `GenerateRefreshToken`: Returns formatted mock token
- `ValidateAccessToken`: Returns valid claims for non-empty tokens
- `ValidateRefreshToken`: Returns valid claims for non-empty tokens

### MockAuthService
- `Register`: Returns mock user with provided details
- `Login`: Returns successful auth result
- `RefreshToken`: Returns new auth result
- `Logout`: Returns success
- `GetUserProfile`: Returns mock user profile

### MockOTPService
- `Generate`: Returns OTP request with code "123456"
- `Verify`: Returns true if code equals "123456"
- `CanResend`: Returns true with no wait time

### MockCasbinEnforcer
- `Enforce`: Admin role allowed for all, user role allowed for `/auth/*`
- `AddPolicy`: Adds to internal policy list
- `RemovePolicy`: Removes from internal policy list
- `GetPolicy`: Returns mock policies

## Quality Standards

### Interface Compliance
All mocks include compile-time interface verification:
```go
var _ domain.UserRepository = (*MockUserRepository)(nil)
```

### Test Isolation
- Each test creates fresh mock instances
- No shared state between tests
- Configurable behaviors per test case

### Error Simulation
Mocks can simulate any error condition:
```go
userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
    return nil, domain.ErrUserNotFound
}
```

## Best Practices

1. **Use t.Helper()** in test utility functions
2. **Create fresh mocks** for each test case
3. **Configure only necessary behaviors** - rely on defaults when possible
4. **Test error paths** by configuring mocks to return errors
5. **Isolate tests** - no dependencies between test cases

## Example Files

See `example_usage_test.go` for comprehensive examples of:
- Table-driven test patterns
- Mock configuration strategies
- Test helper functions
- Error simulation techniques

## Architecture Benefits

This mock system enables:
- **Pure unit testing** without external dependencies
- **Fast test execution** with no I/O operations
- **Deterministic results** through controlled mock behaviors
- **Easy error simulation** for comprehensive test coverage
- **Clean test code** following CLAUDE.md standards