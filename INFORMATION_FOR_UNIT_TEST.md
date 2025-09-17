# INFORMATION FOR UNIT TESTS

This document contains all verified information from manual endpoint testing to fix unit tests without searching for configuration details.

## Database Configuration

```yaml
database:
  dsn: "postgres://auth:123456@localhost:5432/authdb?sslmode=disable"
```

**Database Access Command:**
```bash
PGPASSWORD=123456 psql -h localhost -U auth -d authdb
```

## Redis Configuration

```yaml
redis:
  addr: "localhost:6379"
  password: ""
  db: 0
```

**Redis Access Command:**
```bash
redis-cli
```

## JWT Configuration

```yaml
jwt:
  secret: "supersecretchangeme"
  issuer: "authzsvc"
  access_ttl: "900s"  # 15 minutes
  refresh_ttl: "168h" # 7 days
```

## OTP Configuration

```yaml
otp:
  ttl: "5m"           # 5 minutes
  length: 6
  max_attempts: 5
  resend_window: "60s" # 60 seconds
```

## Server Configuration

- **Port:** 8080
- **Base URL:** http://localhost:8080
- **Health Endpoint:** GET /health

## Database Schema - Users Table

| Column | Type | Constraints | Notes |
|--------|------|-------------|-------|
| id | SERIAL | PRIMARY KEY | Auto-increment |
| email | VARCHAR(255) | UNIQUE, NOT NULL | |
| phone | VARCHAR(32) | INDEX | |
| password | VARCHAR | NOT NULL | GORM maps PasswordHash field to this column |
| role | VARCHAR(64) | INDEX | "user" or "admin" |
| is_active | BOOLEAN | INDEX | Default true |
| phone_verified | BOOLEAN | INDEX | Default false |
| created_at | TIMESTAMP | INDEX | |
| updated_at | TIMESTAMP | INDEX | |
| deleted_at | TIMESTAMP | INDEX | Soft delete |

**Critical Note:** The application uses `PasswordHash` field in Go structs but maps to `password` column in database via GORM tag: `gorm:"column:password"`

## Redis Key Formats

### Session Keys
- **Format:** `session:sess_{userID}_{timestamp}`
- **Example:** `session:sess_434_1758057895273402000`
- **Value:** JSON object with session data
- **TTL:** 7 days (refresh token TTL)

### OTP Keys
- **Main OTP:** `otp:{phone}:{userID}`
- **Attempts:** `otp:att:{phone}:{userID}`
- **Resend:** `otp:res:{phone}`
- **Example:** `otp:+1555123456:434`
- **Value:** 6-digit numeric code
- **TTL:** 5 minutes

## API Endpoints Testing Results

### 1. Health Check
```http
GET /health
```

**Response:**
```json
{
  "ok": true
}
```

### 2. User Registration

```http
POST /auth/register
Content-Type: application/json

{
  "email": "test.ultrathink@example.com",
  "phone": "+1555123456",
  "password": "Test123!@#",
  "role": "user"
}
```

**Response (201):**
```json
{
  "data": {
    "message": "User registered successfully. Please verify your phone number.",
    "user_id": 434
  }
}
```

**Database Effect:**
- User created with ID 434
- phone_verified = false
- is_active = true
- role = "user"

**Redis Effect:**
- OTP code stored: `otp:+1555123456:434` = "441674"
- Attempts counter: `otp:att:+1555123456:434` = 0
- Resend window: `otp:res:+1555123456`

### 3. Admin Registration

```http
POST /auth/register
Content-Type: application/json

{
  "email": "admin.ultrathink@example.com",
  "phone": "+1555999999",
  "password": "Admin123!@#",
  "role": "admin"
}
```

**Response (201):**
```json
{
  "data": {
    "message": "User registered successfully. Please verify your phone number.",
    "user_id": 435
  }
}
```

**Database Effect:**
- User created with ID 435
- phone_verified = false
- is_active = true
- role = "admin"

### 4. OTP Verification

```http
POST /auth/otp/verify
Content-Type: application/json

{
  "phone": "+1555123456",
  "code": "441674",
  "user_id": 434
}
```

**Response (200):**
```json
{
  "data": {
    "message": "Phone number verified and activated successfully",
    "user_id": 434
  }
}
```

**Database Effect:**
- phone_verified = true for user ID 434
- updated_at timestamp updated

**Redis Effect:**
- OTP keys removed after successful verification

### 5. User Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "test.ultrathink@example.com",
  "password": "Test123!@#"
}
```

**Response (200):**
```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTgwNTg3OTUsImlhdCI6MTc1ODA1Nzg5NSwiaXNzIjoiYXV0aHpzdmMiLCJqdGkiOiI1YjIwYzA3N2Y1ZWIyMjkwZTE3ZTJjZDkzOTU5YWMxOCIsInJvbGUiOiJ1c2VyIiwic2Vzc2lvbl9pZCI6InNlc3NfNDM0XzE3NTgwNTc4OTUyNzM0MDIwMDAiLCJ1c2VyX2lkIjo0MzR9.WhogUn2CK_1g0ZhYEJY1iGT1UTNlwvf9dQgIUc4KTvY",
    "expires_in": 900,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTg2NjI2OTUsImlhdCI6MTc1ODA1Nzg5NSwiaXNzIjoiYXV0aHpzdmMiLCJqdGkiOiJiYTQ2ZjVmYTNmZmFjODRhOThkYjZiZTk2YTI2OTNhOSIsInJvbGUiOiJ1c2VyIiwic2Vzc2lvbl9pZCI6InNlc3NfNDM0XzE3NTgwNTc4OTUyNzM0MDIwMDAiLCJ1c2VyX2lkIjo0MzR9.9Je7vYZrXMnBW3BuaTe8M1kwz-TN0TG6GnAlFt7ufMo",
    "token_type": "Bearer",
    "user": {
      "email": "test.ultrathink@example.com",
      "id": 434,
      "role": "user"
    }
  }
}
```

**Redis Effect:**
- Session created: `session:sess_434_1758057895273402000`
- Session value: Full JSON object with UserID, ExpiresAt, CreatedAt

### 6. Admin Login

```http
POST /auth/login
Content-Type: application/json

{
  "email": "admin.ultrathink@example.com",
  "password": "Admin123!@#"
}
```

**Response (200):**
```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTgwNTkwNDQsImlhdCI6MTc1ODA1ODE0NCwiaXNzIjoiYXV0aHpzdmMiLCJqdGkiOiI3NGNjZDZmYmJmZDgzNTJjNDcyZTA4MWZlN2ZlMzA4YSIsInJvbGUiOiJhZG1pbiIsInNlc3Npb25faWQiOiJzZXNzXzQzNV8xNzU4MDU4MTQ0OTQwNjA3MDAwIiwidXNlcl9pZCI6NDM1fQ.B8J7ylGJScgbRPl-A0pLcxgplacal1MikFkyPZE5rak",
    "expires_in": 900,
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTg2NjI5NDQsImlhdCI6MTc1ODA1ODE0NCwiaXNzIjoiYXV0aHpzdmMiLCJqdGkiOiIwMmExNDIxMWE0NTZiZTg0NWQ1NTFiN2QxZGNhYmM2ZiIsInJvbGUiOiJhZG1pbiIsInNlc3Npb25faWQiOiJzZXNzXzQzNV8xNzU4MDU4MTQ0OTQwNjA3MDAwIiwidXNlcl9pZCI6NDM1fQ.jRLyfWpav3HP2pzVytkqMCregTw-v1yi8kpCOaGIVZs",
    "token_type": "Bearer",
    "user": {
      "email": "admin.ultrathink@example.com",
      "id": 435,
      "role": "admin"
    }
  }
}
```

### 7. Protected Endpoint - Get User Profile

```http
GET /auth/me
Authorization: Bearer {access_token}
```

**Response (200):**
```json
{
  "data": {
    "created_at": "2025-09-16T18:22:56.571148-03:00",
    "email": "test.ultrathink@example.com",
    "id": 434,
    "is_active": true,
    "phone": "+1555123456",
    "phone_verified": true,
    "role": "user",
    "updated_at": "2025-09-16T18:24:16.036383-03:00"
  }
}
```

### 8. Token Refresh

```http
POST /auth/refresh
Content-Type: application/json

{
  "refresh_token": "{refresh_token_from_login}"
}
```

**Response (200):**
```json
{
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTgwNTg5MTcsImlhdCI6MTc1ODA1ODAxNywiaXNzIjoiYXV0aHpzdmMiLCJqdGkiOiIwMzc2NDc2NDg3YmM5YTllOWI3ODQ1ZWUyNzRlZGFiNiIsInJvbGUiOiJ1c2VyIiwic2Vzc2lvbl9pZCI6InNlc3NfNDM0XzE3NTgwNTc4OTUyNzM0MDIwMDAiLCJ1c2VyX2lkIjo0MzR9.dwVopSvUhagm3PSb7uFz2twQLToMRin7UEG5jxQpdGM",
    "expires_in": 900,
    "token_type": "Bearer"
  }
}
```

**Note:** Each refresh generates a new access token with unique `jti` field to prevent token reuse.

### 9. Logout

```http
POST /auth/logout
Authorization: Bearer {access_token}
```

**Response (200):**
```json
{
  "data": {
    "message": "Logged out successfully"
  }
}
```

**Redis Effect:**
- Session key removed from Redis
- User must login again to get new tokens

### 10. Admin Endpoints - Get Policies

```http
GET /admin/policies
Authorization: Bearer {admin_access_token}
```

**Response (200):**
```json
[
  [
    "role_admin",
    "/admin/*",
    "(GET|POST|PUT|DELETE)"
  ],
  [
    "role_user",
    "/auth/me",
    "GET"
  ],
  [
    "role_user",
    "/auth/otp/*",
    "POST"
  ],
  [
    "role_user",
    "/auth/logout",
    "POST"
  ],
  [
    "role_admin",
    "/*",
    "(GET|POST|PUT|DELETE)"
  ]
]
```

### 11. Admin Endpoints - Add Policy

```http
POST /admin/policies
Authorization: Bearer {admin_access_token}
Content-Type: application/json

{
  "sub": "role_user",
  "obj": "/test/endpoint",
  "act": "GET"
}
```

**Response (200):** Success (no body content)

**Database Effect:**
- New policy added to casbin_rule table
- Policy: `role_user,/test/endpoint,GET`

### 12. Admin Endpoints - Remove Policy

```http
DELETE /admin/policies
Authorization: Bearer {admin_access_token}
Content-Type: application/json

{
  "sub": "role_user",
  "obj": "/test/endpoint",
  "act": "GET"
}
```

**Response (200):** Success (no body content)

**Database Effect:**
- Policy removed from casbin_rule table

## JWT Token Structure

**Access Token Claims:**
```json
{
  "exp": 1758058795,
  "iat": 1758057895,
  "iss": "authzsvc",
  "jti": "5b20c077f5eb2290e17e2cd939559ac18",
  "role": "user",
  "session_id": "sess_434_1758057895273402000",
  "user_id": 434
}
```

**Refresh Token Claims:**
```json
{
  "exp": 1758662695,
  "iat": 1758057895,
  "iss": "authzsvc",
  "jti": "ba46f5fa3ffac84a98db6be96a2693a9",
  "role": "user",
  "session_id": "sess_434_1758057895273402000",
  "user_id": 434
}
```

**Key Points:**
- `jti` (JWT ID) is unique for each token to prevent reuse
- `role` field contains user role ("user" or "admin")
- `session_id` links to Redis session
- `user_id` is the database user ID
- Access tokens expire in 15 minutes (900s)
- Refresh tokens expire in 7 days (168h)

## Error Response Formats

### Registration with Existing Email (409)
```json
{
  "error": "User already exists"
}
```

### Invalid Credentials (401)
```json
{
  "error": "Invalid credentials"
}
```

### Validation Error (400)
```json
{
  "error": "Key: 'RegisterRequest.Email' Error:Field validation for 'Email' failed on the 'email' tag"
}
```

### Unauthorized Access (401)
```json
{
  "error": "Unauthorized"
}
```

### Forbidden Access (403)
```json
{
  "error": "Forbidden"
}
```

## Mock Services for Testing

### Mock Notification Service
- **SMS Function:** Always returns success
- **Message Storage:** Stores sent messages for verification
- **OTP Codes:** Generated as 6-digit numbers
- **Mock SMS Format:** `[MOCK SMS] To: {phone}, Message: Your verification code is: {code}. Valid for 5 minutes.`

## Test User Templates

### Regular User
```json
{
  "email": "test.user@e2etest.local",
  "phone": "+15551234567",
  "password": "Test123!@#",
  "role": "user"
}
```

### Admin User
```json
{
  "email": "admin.user@e2etest.local",
  "phone": "+15559999999",
  "password": "Admin123!@#",
  "role": "admin"
}
```

## RBAC (Role-Based Access Control) Rules

### User Role Permissions
- `GET /auth/me` - Get own profile
- `POST /auth/logout` - Logout
- `POST /auth/otp/*` - OTP operations

### Admin Role Permissions
- All user permissions PLUS:
- `GET /admin/policies` - List Casbin policies
- `POST /admin/policies` - Add new policy
- `DELETE /admin/policies` - Remove policy
- `/* (GET|POST|PUT|DELETE)` - Full access to all endpoints

## Test Environment Differences

### E2E Tests vs Manual Testing
1. **Test Server:** Uses `httptest.Server` with random ports
2. **Test Prefix:** Redis keys prefixed with `e2e_test_{timestamp}`
3. **Mock Services:** Uses mock notification service instead of real Twilio
4. **Database:** Uses same PostgreSQL database but with test data cleanup
5. **Session Format:** Tests expect `sess:` but app uses `session:`

### Common Test Issues
1. **JSON Response Structure:** API returns nested `{"data": {...}}` format
2. **JWT Claims Types:** Numbers returned as float64, not strings
3. **Redis Key Namespacing:** Tests use prefixed keys, app uses unprefixed
4. **Phone Verification:** Login requires phone_verified = true
5. **Token Uniqueness:** Each token must have unique `jti` field

## Service Dependencies

### AuthService Dependencies
- UserRepository
- SessionRepository  
- PasswordService
- TokenService
- OTPService
- PolicyService

### Test Mock Implementations
- MockNotificationService (replaces Twilio)
- All other services use real implementations

## Configuration Files

### Main Config: `/config/config.yml`
- Used by production server
- Contains actual database credentials
- Contains JWT secrets and timeouts

### Test Config: Programmatically generated
- Uses same database connection
- Uses same Redis connection
- May have different timeouts for testing

---

**Last Updated:** September 16, 2025  
**Tested Against:** Server running on port 8080  
**Database:** PostgreSQL (authdb)  
**Redis:** localhost:6379  
**All endpoints verified working with role-based access control**