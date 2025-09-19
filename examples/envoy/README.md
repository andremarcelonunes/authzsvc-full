# Envoy Proxy External Authorization Integration

This directory contains configuration and examples for integrating the authzsvc with Envoy Proxy's external authorization filter (ext_authz).

## Overview

The external authorization integration allows Envoy to delegate authentication and authorization decisions to the authzsvc before forwarding requests to backend services. This provides:

- **Centralized auth**: All services behind Envoy benefit from the same auth logic
- **Zero-trust architecture**: Every request is validated before reaching backends
- **Policy enforcement**: Casbin policies are enforced at the proxy level
- **Field validation**: Support for path.id==token.user_id validation patterns

## Architecture

```
Client Request
      ↓
   Envoy Proxy (8000)
      ↓
External Auth Service (authzsvc:8080/external/authz)
      ↓ (if authorized)
   Backend Service
```

## Files

- `envoy-external-authz.yaml` - Envoy configuration with ext_authz filter
- `docker-compose.envoy.yaml` - Complete setup with Envoy + authzsvc
- `README.md` - This documentation

## Quick Start

1. **Start the complete stack:**
   ```bash
   cd examples/envoy
   docker-compose -f docker-compose.envoy.yaml up --build
   ```

2. **Register a user (direct to authzsvc):**
   ```bash
   curl -X POST http://localhost:8080/auth/register \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "phone": "+1234567890",
       "password": "password123",
       "role": "user"
     }'
   ```

3. **Verify phone (if using real Twilio):**
   ```bash
   curl -X POST http://localhost:8080/otp/verify \
     -H "Content-Type: application/json" \
     -d '{
       "phone": "+1234567890",
       "code": "123456",
       "user_id": 1
     }'
   ```

4. **Login to get JWT token:**
   ```bash
   curl -X POST http://localhost:8080/auth/login \
     -H "Content-Type: application/json" \
     -d '{
       "email": "user@example.com",
       "password": "password123"
     }'
   ```

5. **Test authorized request through Envoy:**
   ```bash
   # This will go through Envoy -> External Auth -> Backend
   curl -X GET http://localhost:8000/auth/me \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
   ```

6. **Test unauthorized request:**
   ```bash
   # This should be blocked by external auth
   curl -X GET http://localhost:8000/admin/policies \
     -H "Authorization: Bearer YOUR_USER_JWT_TOKEN"
   ```

## Configuration Details

### Envoy External Authorization Filter

The `envoy-external-authz.yaml` configures Envoy to:

1. **Forward auth requests** to `http://authzsvc:8080/external/authz`
2. **Include original headers** (authorization, content-type, etc.)
3. **Forward response headers** from auth service to backend
4. **Bypass auth** for public endpoints (health, login, register)
5. **Fail closed** if auth service is unavailable

### Request Flow

1. **Client sends request** to Envoy (port 8000)
2. **Envoy checks route** - bypass auth for public endpoints
3. **For protected routes**:
   - Extract request metadata (method, path, headers, body)
   - Send to `/external/authz` endpoint
   - Wait for authorization response
4. **Auth service validates**:
   - JWT token from Authorization header
   - Session exists in Redis
   - Casbin policies allow access
   - Field validation (if configured)
5. **Response handling**:
   - `200 OK`: Forward request to backend with additional headers
   - `401/403`: Return error to client
   - `5xx`: Fail closed (deny request)

### Authorization Policies

The external auth service uses the same Casbin policies as the internal middleware:

```
role_admin, /admin/*, (GET|POST|PUT|DELETE), *
role_user, /auth/me, GET, *
role_user, /users/*, GET, path.id==token.user_id
```

### Headers Added to Backend Requests

When authorization succeeds, these headers are added:

- `x-user-id`: User ID from JWT token
- `x-user-role`: User role from JWT token

## Testing the Integration

### 1. Health Checks

```bash
# Envoy health
curl http://localhost:8001/ready

# Auth service health (through Envoy)
curl http://localhost:8000/health

# External auth endpoint health
curl http://localhost:8000/external/health
```

### 2. Authentication Flow

```bash
# Register user
TOKEN=$(curl -s -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","phone":"+1234567890","password":"test123","role":"user"}' \
  | jq -r '.data.user_id')

# Login to get JWT
JWT=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}' \
  | jq -r '.data.access_token')

# Test authorized request through Envoy
curl -H "Authorization: Bearer $JWT" http://localhost:8000/auth/me
```

### 3. Authorization Testing

```bash
# Should succeed (user can access own profile)
curl -H "Authorization: Bearer $JWT" http://localhost:8000/auth/me

# Should fail (user cannot access admin endpoints)
curl -H "Authorization: Bearer $JWT" http://localhost:8000/admin/policies

# Should succeed with field validation (user can access own user data)
curl -H "Authorization: Bearer $JWT" http://localhost:8000/users/1

# Should fail field validation (user cannot access other user data)
curl -H "Authorization: Bearer $JWT" http://localhost:8000/users/999
```

## Monitoring & Debugging

### Envoy Admin Interface

Access Envoy admin at http://localhost:8001:

- `/stats` - Request statistics and auth metrics
- `/config_dump` - Current configuration
- `/clusters` - Backend cluster health
- `/ready` - Readiness check

### Log Analysis

```bash
# View Envoy logs
docker-compose -f docker-compose.envoy.yaml logs envoy

# View authzsvc logs
docker-compose -f docker-compose.envoy.yaml logs authzsvc

# Follow external auth requests
docker-compose -f docker-compose.envoy.yaml logs -f authzsvc | grep "external/authz"
```

### Key Metrics to Monitor

- **ext_authz.denied**: Authorization denials
- **ext_authz.error**: Auth service errors
- **ext_authz.timeout**: Auth service timeouts
- **ext_authz.ok**: Successful authorizations

## Production Considerations

### Security

1. **TLS/HTTPS**: Use HTTPS between all components
2. **Secrets management**: Store JWT secrets securely
3. **Network policies**: Restrict access between services
4. **Rate limiting**: Add rate limiting to auth endpoints

### Performance

1. **Connection pooling**: Configure appropriate pool sizes
2. **Timeouts**: Set reasonable timeouts (5s for auth checks)
3. **Caching**: Consider caching auth decisions (with care)
4. **Health checks**: Monitor auth service health

### Reliability

1. **Circuit breaker**: Add circuit breaker to auth service
2. **Retries**: Configure retries for transient failures
3. **Graceful degradation**: Plan for auth service unavailability
4. **Monitoring**: Set up comprehensive monitoring and alerting

### Scaling

1. **Multiple auth instances**: Scale authzsvc horizontally
2. **Load balancing**: Use appropriate load balancing strategies
3. **Session storage**: Ensure Redis is highly available
4. **Database**: Scale PostgreSQL as needed

## Troubleshooting

### Common Issues

1. **"Authorization header required"**
   - Check that JWT token is included in Authorization header
   - Verify header format: `Bearer <token>`

2. **"Invalid token"**
   - Check JWT token is not expired
   - Verify JWT_SECRET matches between services
   - Ensure token was issued by the correct service

3. **"Session invalid or expired"**
   - Check Redis connectivity
   - Verify session wasn't manually deleted
   - Check session TTL configuration

4. **"Access denied"**
   - Verify Casbin policies are correctly configured
   - Check user role matches policy requirements
   - Review policy syntax and patterns

5. **"Field validation failed"**
   - Check path parameter extraction
   - Verify token claims contain required fields
   - Review validation rule syntax

### Debug Steps

1. **Check Envoy configuration**:
   ```bash
   curl http://localhost:8001/config_dump | jq '.configs[].dynamic_listeners'
   ```

2. **Test auth service directly**:
   ```bash
   curl -X POST http://localhost:8080/external/authz \
     -H "Content-Type: application/json" \
     -d '{"attributes":{"request":{"http":{"method":"GET","path":"/auth/me","headers":{"authorization":"Bearer TOKEN"}}}}}'
   ```

3. **Check policy enforcement**:
   ```bash
   curl http://localhost:8080/admin/policies \
     -H "Authorization: Bearer ADMIN_TOKEN"
   ```

## Advanced Configuration

### Custom Headers

To forward additional headers from auth service to backend:

```yaml
authorization_response:
  allowed_upstream_headers:
    patterns:
    - exact: "x-user-id"
    - exact: "x-user-role"
    - exact: "x-user-permissions"  # Custom header
    - prefix: "x-auth-"
```

### Request Body Inspection

To analyze request body in authorization decisions:

```yaml
with_request_body:
  max_request_bytes: 8192
  allow_partial_message: true
```

### Failure Mode

To allow requests when auth service is down (NOT recommended for production):

```yaml
failure_mode_allow: true
```

## Next Steps

1. **Integrate with service mesh** (Istio, Linkerd)
2. **Add rate limiting** at proxy level
3. **Implement request tracing** for better observability
4. **Add more sophisticated caching** strategies
5. **Integrate with external identity providers** (OIDC, SAML)

For more information, see the main authzsvc documentation and Envoy's ext_authz filter documentation.