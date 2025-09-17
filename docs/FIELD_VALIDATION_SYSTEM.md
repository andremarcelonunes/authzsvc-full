# Enhanced Field Validation System

This document describes the flexible cross-field validation system that extends your existing authorization infrastructure to support complex validation rules between request data and JWT token claims.

## Overview

The new validation system allows you to define declarative YAML rules that compare values from different parts of an HTTP request (headers, path parameters, query strings, body fields) against JWT token claims, enabling sophisticated authorization scenarios while maintaining clean separation of concerns.

## Key Features

- **Flexible Field Sources**: Extract values from path, query, headers, body (including nested fields), or token claims
- **Multiple Operators**: Support for equals, notEquals, in, notIn, contains, exists comparisons
- **Logical Combinations**: AND/OR logic for combining multiple validation conditions
- **Backward Compatibility**: Works alongside existing ownership rules system
- **Configuration-Driven**: Define rules in YAML without code changes
- **Performance Optimized**: Pre-parses request bodies and caches validation engines

## Architecture Integration

```
HTTP Request
     ↓
JWT Authentication Middleware (existing)
     ↓ (sets user_id, role in context)
Enhanced Casbin Authorization Middleware
     ├─ Legacy x-user-id header check
     ├─ NEW: Enhanced field validation rules
     ├─ Legacy ownership rules (backward compatibility)
     └─ Casbin RBAC enforcement
     ↓
Handler (unchanged)
```

## Configuration Format

### validation_rules.yml

```yaml
validationRules:
  - name: "UserIDHeaderMatch"                    # Unique rule name
    method: "GET"                                # HTTP method
    path: "/users/:user_id"                      # Route pattern
    description: "Header must match token"       # Optional description
    logic: "all"                                 # "all" (AND) or "any" (OR)
    enabled: true                                # Enable/disable rule
    conditions:
      - requestField:                            # Field from request
          source: "header"                       # path|query|header|body|token
          name: "x-user-id"                      # Field name
        tokenField:                              # Field from JWT token
          source: "token"
          name: "user_id"
        operator: "equals"                       # equals|notEquals|in|notIn|contains|exists
        description: "Header user ID must match token user ID"
```

## Field Sources

### Request Fields (`requestField`)

1. **`path`**: URL path parameters
   ```yaml
   source: "path"
   name: "user_id"              # /users/:user_id → extracts user_id
   ```

2. **`query`**: Query string parameters  
   ```yaml
   source: "query"
   name: "tenant_id"            # ?tenant_id=123 → extracts "123"
   ```

3. **`header`**: HTTP headers
   ```yaml
   source: "header"
   name: "x-user-id"            # Header: x-user-id: 456 → extracts "456"
   ```

4. **`body`**: JSON body fields (supports nested access)
   ```yaml
   source: "body"
   name: "tenant_id"            # {"tenant_id": "789"} → extracts "789"
   name: "user.profile.id"      # {"user":{"profile":{"id":"999"}}} → extracts "999"
   ```

### Token Fields (`tokenField`)

Always use `source: "token"` with the JWT claim name:

```yaml
tokenField:
  source: "token"
  name: "user_id"              # Standard claim
  name: "tenant_id"            # Custom claim
  name: "project_ids"          # Array claim
```

## Comparison Operators

### Basic Equality
- **`equals`**: Direct string comparison
- **`notEquals`**: Inverse of equals

```yaml
operator: "equals"
# "123" equals "123" → true
# "123" equals "456" → false
```

### Array Operations
- **`in`**: Check if value exists in array
- **`notIn`**: Check if value does NOT exist in array

```yaml
operator: "in"
# "project-1" in ["project-1", "project-2"] → true
# "project-3" in ["project-1", "project-2"] → false
```

### String Operations
- **`contains`**: Substring search
- **`exists`**: Check if field has a non-empty value

```yaml
operator: "contains"
# "hello world" contains "world" → true

operator: "exists"
# "some-value" exists → true
# "" exists → false
```

## Logic Combinations

### AND Logic (`logic: "all"`)
All conditions must be true:

```yaml
logic: "all"
conditions:
  - # User must be team member
  - # AND operation must be in their org
```

### OR Logic (`logic: "any"`)
At least one condition must be true:

```yaml
logic: "any" 
conditions:
  - # User has admin role
  - # OR user owns the resource
```

## Real-World Examples

### 1. User Profile Access Control
```yaml
- name: "UserProfileAccess"
  method: "GET"
  path: "/users/:user_id/profile"
  description: "Users can only access their own profile"
  logic: "all"
  enabled: true
  conditions:
    - requestField:
        source: "path"
        name: "user_id"
      tokenField:
        source: "token"
        name: "user_id"
      operator: "equals"
```

### 2. Multi-Tenant Data Isolation
```yaml
- name: "TenantDataIsolation"
  method: "POST"
  path: "/projects"
  description: "Projects must be created within user's tenant"
  logic: "all"
  enabled: true
  conditions:
    - requestField:
        source: "body"
        name: "tenant_id"
      tokenField:
        source: "token"
        name: "tenant_id"
      operator: "equals"
```

### 3. Project-Based Access Control
```yaml
- name: "ProjectAccess"
  method: "GET"
  path: "/projects/:project_id/data"
  description: "User must have access to requested project"
  logic: "all"
  enabled: true
  conditions:
    - requestField:
        source: "path"
        name: "project_id"
      tokenField:
        source: "token"
        name: "project_ids"
      operator: "in"
```

### 4. Complex Multi-Condition Validation
```yaml
- name: "TeamResourceModification"
  method: "PUT"
  path: "/teams/:team_id/resources"
  description: "User must be team member AND resource must be in their org"
  logic: "all"
  enabled: true
  conditions:
    - requestField:
        source: "path"
        name: "team_id"
      tokenField:
        source: "token"
        name: "team_ids"
      operator: "in"
      description: "User must be member of the team"
    - requestField:
        source: "body"
        name: "organization_id"
      tokenField:
        source: "token"
        name: "organization_id"
      operator: "equals"
      description: "Resource must belong to user's organization"
```

### 5. Admin OR Owner Access Pattern
```yaml
- name: "AdminOrOwnerDelete"
  method: "DELETE"
  path: "/documents/:doc_id"
  description: "User must be admin OR document owner"
  logic: "any"
  enabled: true
  conditions:
    - requestField:
        source: "token"
        name: "role"
      tokenField:
        source: "token"
        name: "admin_role"
      operator: "equals"
      description: "User has admin privileges"
    - requestField:
        source: "query"
        name: "owner_id"
      tokenField:
        source: "token"
        name: "user_id"
      operator: "equals"
      description: "User owns the document"
```

## Integration Guide

### Step 1: Update Configuration Loading

Your existing `config/config.go` already supports loading validation rules:

```go
func Load() (*Config, error) {
    // ... existing config loading ...
    
    // Load new validation rules
    validationRules, err := loadValidationRules("config/validation_rules.yml")
    if err != nil {
        // Backward compatibility - continue without validation rules
        validationRules = []ValidationRule{}
    }
    
    return &Config{
        // ... existing fields ...
        ValidationRules: validationRules,
    }, nil
}
```

### Step 2: Update Middleware Chain

Replace existing `CasbinMW` with `EnhancedCasbinMW`:

```go
// OLD:
casbinMW := middleware.NewCasbinMW(enforcer, cfg.OwnershipRules)

// NEW:
enhancedCasbinMW := middleware.NewEnhancedCasbinMW(
    enforcer,
    cfg.OwnershipRules,    // Legacy rules for backward compatibility
    cfg.ValidationRules,   // New flexible validation rules
)

// Apply middleware
protected.Use(authMW.WithJWT())
protected.Use(enhancedCasbinMW.Enforce())
```

### Step 3: Enhanced JWT Claims

Extend your JWT tokens to include additional claims needed for validation:

```go
type EnhancedJWTClaims struct {
    UserID         string   `json:"user_id"`
    Role           string   `json:"role"`
    TenantID       string   `json:"tenant_id,omitempty"`
    OrganizationID string   `json:"organization_id,omitempty"`
    ProjectIDs     []string `json:"project_ids,omitempty"`
    TeamIDs        []string `json:"team_ids,omitempty"`
}
```

### Step 4: Update JWT Middleware

Ensure additional claims are available in the Gin context:

```go
// In auth_middleware.go, after token validation:
c.Set("user_id", claims.UserID)
c.Set("user_role", claims.Role)

// Add custom claims for validation
if claims.TenantID != "" {
    c.Set("tenant_id", claims.TenantID)
}
if claims.OrganizationID != "" {
    c.Set("organization_id", claims.OrganizationID)
}
if len(claims.ProjectIDs) > 0 {
    c.Set("project_ids", claims.ProjectIDs)
}
```

## Migration Strategy

### Phase 1: Parallel Operation
- Keep existing ownership rules system running
- Add validation rules alongside legacy system
- Start with simple rules that duplicate existing logic

### Phase 2: Enhanced Rules
- Add complex multi-field validation rules
- Implement tenant isolation and project access control
- Begin using advanced operators (in, contains)

### Phase 3: Legacy Deprecation
- Set `enabled: false` on legacy ownership rules
- Monitor for any broken functionality
- Eventually remove legacy system (optional)

## Testing Strategy

### Unit Tests
```go
func TestFieldValidation(t *testing.T) {
    rules := []config.ValidationRule{
        {
            Name: "UserAccess",
            Method: "GET", 
            Path: "/users/:user_id",
            Logic: "all",
            Enabled: true,
            Conditions: []config.ValidationCondition{
                {
                    RequestField: config.FieldSource{Source: "path", Name: "user_id"},
                    TokenField: config.FieldSource{Source: "token", Name: "user_id"},
                    Operator: "equals",
                },
            },
        },
    }
    
    engine := NewValidationEngine(rules)
    
    // Test valid case
    tokenClaims := map[string]interface{}{"user_id": "123"}
    err := engine.ValidateRequest(ctx, tokenClaims)
    assert.NoError(t, err)
    
    // Test invalid case  
    tokenClaims = map[string]interface{}{"user_id": "456"}
    err = engine.ValidateRequest(ctx, tokenClaims)
    assert.Error(t, err)
}
```

### Integration Tests
```bash
# Test with actual HTTP requests
curl -H "Authorization: Bearer $TOKEN" \
     -H "x-user-id: 123" \
     GET /api/v1/users/123/profile
     
# Should return 200 if token user_id matches header and path
```

## Performance Considerations

- **Request Body Parsing**: Bodies are parsed once and cached in the adapter
- **Rule Matching**: Rules are filtered by method and path before evaluation
- **Memory Usage**: Validation engines can be reused across requests
- **Caching**: Consider caching compiled validation rules in production

## Error Handling

### Configuration Errors
```yaml
# Invalid operator
operator: "invalid_operator"
# Results in: "unsupported operator: invalid_operator"

# Missing required fields
conditions: []
# Results in: Rule passes (no conditions means allow)
```

### Runtime Errors
```go
// Field extraction errors
"failed to extract request field body.missing_field: field not found"

// Type comparison errors  
"comparison failed for condition 0: cannot compare string to array"

// Validation failures
"validation failed for rule 'TenantCheck': Tenant must match user's tenant"
```

## Monitoring and Observability

### Logging
The validation engine logs detailed information about rule evaluation:

```
INFO: Validating request GET /users/123 against 3 rules
DEBUG: Rule 'UserIDMatch' passed: path.user_id(123) equals token.user_id(123)
ERROR: Rule 'TenantCheck' failed: body.tenant_id(tenant-1) != token.tenant_id(tenant-2)
```

### Metrics
Consider adding metrics for:
- Rule evaluation count by rule name
- Validation failure rate by endpoint
- Performance metrics (evaluation time)

## Best Practices

### 1. Rule Design
- **Start Simple**: Begin with basic equality checks
- **Descriptive Names**: Use clear, descriptive rule names and descriptions
- **Single Responsibility**: Each rule should validate one logical concept

### 2. Performance
- **Minimize Rules**: Only add rules for endpoints that need them
- **Order Conditions**: Put faster conditions first in AND logic
- **Use Specific Paths**: Match exact route patterns, not wildcards

### 3. Security
- **Fail Secure**: Rules should fail closed (deny by default)
- **Validate Inputs**: Ensure all rule conditions are necessary
- **Regular Audits**: Review rules regularly for correctness

### 4. Maintenance
- **Version Control**: Track rule changes in git
- **Documentation**: Document complex business rules
- **Testing**: Maintain comprehensive test coverage

## Troubleshooting

### Common Issues

1. **Rules Not Matching**
   - Verify `method` and `path` exactly match route definition
   - Check that `path` uses route pattern (e.g., `/users/:user_id`), not actual URL

2. **Field Extraction Failures**
   - Ensure field names match exactly (case-sensitive)
   - For nested body fields, use dot notation: `user.profile.id`

3. **Type Mismatches**
   - JWT claims are typically strings - ensure comparison values match
   - Array claims should use `in`/`notIn` operators

4. **Logic Errors**
   - `logic: "all"` requires ALL conditions to be true
   - `logic: "any"` requires at least ONE condition to be true

### Debug Mode

Enable detailed logging:
```go
gin.SetMode(gin.DebugMode)
// Shows detailed rule evaluation in logs
```

## Conclusion

The enhanced field validation system provides a powerful, flexible foundation for implementing complex authorization rules while maintaining clean architecture and backward compatibility. It enables declarative, configuration-driven security policies that can evolve with your application's needs without requiring code changes.