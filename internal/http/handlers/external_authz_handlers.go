package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/middleware"
)

// ExternalAuthzHandlers handles external authorization requests from Envoy
type ExternalAuthzHandlers struct {
	tokenSvc       domain.TokenService
	sessionRepo    domain.SessionRepository
	enforcer       *casbin.Enforcer
	fieldExtractor *middleware.FieldExtractor
	// backendIdentity translates the token's user id into the id used by the
	// other services. nil means "not configured".
	backendIdentity domain.BackendIdentityResolver
}

// NewExternalAuthzHandlers creates new external authorization handlers
func NewExternalAuthzHandlers(
	tokenSvc domain.TokenService,
	sessionRepo domain.SessionRepository,
	enforcer *casbin.Enforcer,
	backendIdentity domain.BackendIdentityResolver,
) *ExternalAuthzHandlers {
	// Create a temporary SimpleCasbinMW for field extraction utilities
	tempCasbinMW := middleware.NewSimpleCasbinMW(enforcer)

	return &ExternalAuthzHandlers{
		tokenSvc:        tokenSvc,
		sessionRepo:     sessionRepo,
		enforcer:        enforcer,
		fieldExtractor:  middleware.NewFieldExtractor(tempCasbinMW),
		backendIdentity: backendIdentity,
	}
}

// EnvoyRequest represents the request format sent by Envoy ext_authz
type EnvoyRequest struct {
	Attributes struct {
		Request struct {
			HTTP struct {
				Method  string            `json:"method"`
				Path    string            `json:"path"`
				Headers map[string]string `json:"headers"`
				Body    string            `json:"body,omitempty"` // Base64 encoded
				Query   string            `json:"query,omitempty"`
			} `json:"http"`
		} `json:"request"`
		Source struct {
			Address struct {
				SocketAddress struct {
					Address   string `json:"address"`
					PortValue int    `json:"portValue"`
				} `json:"socketAddress"`
			} `json:"address"`
		} `json:"source"`
	} `json:"attributes"`
}

// AuthzResponse represents the response format for Envoy
type AuthzResponse struct {
	Status struct {
		Code int `json:"code"`
	} `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// authzOutcome is the result of the shared authorization decision used by both
// the JSON endpoint (Authorize) and the Envoy-native endpoint (Check).
type authzOutcome struct {
	status  int                 // 200, 401, 403 or 500
	message string              // client-safe message (error text for non-200)
	detail  string              // internal detail, only set for 500; never sent by Check
	claims  *domain.TokenClaims // set when status == 200
	// backendUserID is the caller's id in the other services; empty when the
	// user is not mapped or cannot be resolved. Only meaningful when status == 200.
	backendUserID string
}

// decide holds the authentication + authorization logic shared by all
// external authorization endpoints: Bearer token, token validation, Redis
// session check, Casbin permission for role_<role> on (path, method) and the
// policy's field rule (4th column).
func (h *ExternalAuthzHandlers) decide(ctx context.Context, envoyReq EnvoyRequest) authzOutcome {
	unauthorized := func(msg string) authzOutcome {
		return authzOutcome{status: http.StatusUnauthorized, message: msg}
	}

	// Extract JWT token from authorization header
	authHeader, exists := envoyReq.Attributes.Request.HTTP.Headers["authorization"]
	if !exists {
		// Try lowercase header name (Envoy normalizes headers)
		authHeader, exists = envoyReq.Attributes.Request.HTTP.Headers["Authorization"]
	}

	if !exists {
		return unauthorized("Authorization header required")
	}

	// Parse Bearer token
	tokenParts := strings.SplitN(authHeader, " ", 2)
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return unauthorized("Invalid authorization header format")
	}

	token := tokenParts[1]

	// Validate JWT token
	claims, err := h.tokenSvc.ValidateAccessToken(token)
	if err != nil {
		switch err {
		case domain.ErrTokenExpired:
			return unauthorized("Token expired")
		case domain.ErrTokenInvalid, domain.ErrTokenMalformed:
			return unauthorized("Invalid token")
		default:
			return unauthorized("Token validation failed")
		}
	}

	// Validate session exists in Redis (critical security check)
	if claims.SessionID != "" {
		session, err := h.sessionRepo.FindByID(ctx, claims.SessionID)
		if err != nil || session == nil {
			return unauthorized("Session invalid or expired")
		}

		// Ensure session belongs to the same user
		if session.UserID != claims.UserID {
			return unauthorized("Session user mismatch")
		}
	}

	// Create token claims map for field validation
	tokenClaims := map[string]interface{}{
		"user_id": fmt.Sprintf("%d", claims.UserID),
		"role":    claims.Role,
		// "true" / "false" (rules compare strings); tokens without the claim are "false"
		"phone_verified": strconv.FormatBool(claims.PhoneVerified),
	}

	// Apply Casbin authorization logic
	path := envoyReq.Attributes.Request.HTTP.Path
	method := envoyReq.Attributes.Request.HTTP.Method
	casbinRole := "role_" + claims.Role
	lookup := &backendLookup{resolver: h.backendIdentity, userID: claims.UserID}

	// Every policy of the role (own first, then inherited) matching path+method.
	policies, err := h.matchingPolicies(casbinRole, path, method)
	if err != nil {
		return authzOutcome{status: http.StatusInternalServerError, message: "Authorization check failed", detail: err.Error()}
	}
	if len(policies) == 0 {
		return authzOutcome{status: http.StatusForbidden, message: "Access denied"}
	}

	// Allowed when ANY matching policy's rule is satisfied. Internal failures
	// (e.g. identity resolver) fail closed unless another policy allows.
	var internalErr error
	for _, policy := range policies {
		valid, err := h.validateFields(ctx, envoyReq, policy.pattern, policy.rule, tokenClaims, lookup)
		if err != nil {
			if internalErr == nil {
				internalErr = err
			}
			continue
		}
		if valid {
			return authzOutcome{status: http.StatusOK, claims: claims, backendUserID: h.backendIDForHeader(ctx, lookup)}
		}
	}
	if internalErr != nil {
		return authzOutcome{status: http.StatusInternalServerError, message: "Field validation failed", detail: internalErr.Error()}
	}
	return authzOutcome{status: http.StatusForbidden, message: "Field validation failed: Request values do not match token claims"}
}

// Authorize handles external authorization requests from Envoy
func (h *ExternalAuthzHandlers) Authorize(c *gin.Context) {
	var envoyReq EnvoyRequest
	if err := c.ShouldBindJSON(&envoyReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	out := h.decide(c.Request.Context(), envoyReq)
	switch out.status {
	case http.StatusUnauthorized:
		h.respondUnauthorized(c, out.message)
	case http.StatusForbidden:
		h.respondForbidden(c, out.message)
	case http.StatusOK:
		// Authorization successful - return allowed response
		c.JSON(http.StatusOK, AuthzResponse{
			Status: struct {
				Code int `json:"code"`
			}{Code: http.StatusOK},
			Headers: map[string]string{
				"x-user-id":         fmt.Sprintf("%d", out.claims.UserID),
				"x-user-role":       out.claims.Role,
				"x-user-phone":      out.claims.Phone,
				"x-backend-user-id": out.backendUserID,
			},
		})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   out.message,
			"details": out.detail,
		})
	}
}

// maxCheckBodyBytes caps how much of the request body Check reads. Envoy only
// sends up to with_request_body.max_request_bytes anyway.
const maxCheckBodyBytes = 1 << 20

// Check is the Envoy HTTP ext_authz compatible endpoint:
//
//	ANY /external/authz/check/*path
//
// Envoy calls it with the ORIGINAL method and path_prefix + original path
// (+ query string). The request being authorized is therefore described by the
// incoming HTTP request itself:
//   - method  = request method (no special treatment for HEAD/OPTIONS)
//   - path    = c.Param("path"), i.e. the wildcard remainder as Gin gives it
//     (always starts with "/", percent-escapes already decoded, trailing slash
//     preserved; a call to .../check/ authorizes "/")
//   - query   = raw query string
//   - headers = request headers (names lower-cased)
//   - body    = request body, base64 encoded (may be empty/partial)
//
// The decision is taken from the status code (200 allow, 401/403/500 deny);
// identity is returned only in the x-user-id / x-user-role / x-user-phone / x-backend-user-id response headers,
// taken from the validated token (never from request headers).
func (h *ExternalAuthzHandlers) Check(c *gin.Context) {
	var envoyReq EnvoyRequest
	httpReq := &envoyReq.Attributes.Request.HTTP
	httpReq.Method = c.Request.Method
	httpReq.Path = c.Param("path")
	httpReq.Query = c.Request.URL.RawQuery
	httpReq.Headers = make(map[string]string, len(c.Request.Header))
	for name, values := range c.Request.Header {
		httpReq.Headers[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	if c.Request.Body != nil {
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxCheckBodyBytes))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization check failed"})
			return
		}
		if len(body) > 0 {
			httpReq.Body = base64.StdEncoding.EncodeToString(body)
		}
	}

	out := h.decide(c.Request.Context(), envoyReq)
	if out.status != http.StatusOK {
		// Internal details (out.detail) are intentionally not exposed.
		c.JSON(out.status, gin.H{"error": out.message})
		return
	}

	c.Header("x-user-id", fmt.Sprintf("%d", out.claims.UserID))
	c.Header("x-user-role", out.claims.Role)
	// Always present (possibly empty, for tokens issued without the claim) so the proxy
	// overwrites a client-supplied value.
	c.Writer.Header().Set("x-user-phone", out.claims.Phone)
	// Always present (possibly empty) so the proxy overwrites a client-supplied
	// value. c.Header would drop an empty value, hence the direct Set.
	c.Writer.Header().Set("x-backend-user-id", out.backendUserID)
	c.Status(http.StatusOK)
	c.Writer.WriteHeaderNow()
}

// Health handles health check requests from Envoy
func (h *ExternalAuthzHandlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "external-authz",
		"version": "1.0.0",
	})
}

// matchedPolicy is a stored policy whose path pattern and method match the request.
type matchedPolicy struct {
	pattern string // policy path pattern (column 2), e.g. /api/v1/users/client/:client_id/contacts
	rule    string // 4th column; "" when absent
}

// matchingPolicies returns every policy matching path and method for the role
// itself and for every role it inherits (transitively, via grouping policies).
// The role's own policies come first.
func (h *ExternalAuthzHandlers) matchingPolicies(role, path, method string) ([]matchedPolicy, error) {
	inherited, err := h.enforcer.GetImplicitRolesForUser(role)
	if err != nil {
		return nil, fmt.Errorf("failed to get inherited roles for %s: %w", role, err)
	}
	roles := []string{role}
	seen := map[string]bool{role: true}
	for _, r := range inherited {
		if !seen[r] {
			seen[r] = true
			roles = append(roles, r)
		}
	}

	var matched []matchedPolicy
	for _, r := range roles {
		policies, err := h.enforcer.GetFilteredPolicy(0, r)
		if err != nil {
			return nil, fmt.Errorf("failed to get policies for role %s: %w", r, err)
		}
		for _, policy := range policies {
			if len(policy) < 3 {
				continue // Invalid policy format
			}
			if h.pathMatches(path, policy[1]) && h.methodMatches(method, policy[2]) {
				mp := matchedPolicy{pattern: policy[1]}
				if len(policy) > 3 {
					mp.rule = policy[3]
				}
				matched = append(matched, mp)
			}
		}
	}
	return matched, nil
}

// errBackendIdentityNotConfigured is returned by backendLookup when a rule (or
// nothing else) needs the backend id but no resolver was wired.
var errBackendIdentityNotConfigured = errors.New("backend identity resolver not configured")

// backendLookup resolves the caller's backend user id at most once per request.
type backendLookup struct {
	resolver domain.BackendIdentityResolver
	userID   uint

	done   bool
	id     string
	found  bool
	err    error
	logged bool // a failure was already logged for this request
}

func (l *backendLookup) get(ctx context.Context) (string, bool, error) {
	if !l.done {
		l.done = true
		if l.resolver == nil {
			l.err = errBackendIdentityNotConfigured
		} else {
			l.id, l.found, l.err = l.resolver.ResolveBackendUserID(ctx, l.userID)
			if l.err == nil && l.id == "" {
				l.found = false
			}
		}
	}
	return l.id, l.found, l.err
}

// backendIDForHeader resolves the backend id for the x-backend-user-id response
// header. It never fails the request: unmapped or unresolvable users get "".
func (h *ExternalAuthzHandlers) backendIDForHeader(ctx context.Context, l *backendLookup) string {
	id, found, err := l.get(ctx)
	if err != nil {
		if !errors.Is(err, errBackendIdentityNotConfigured) && !l.logged {
			l.logged = true
			log.Printf("external authz: WARNING backend identity lookup failed for user %d; allowing with empty x-backend-user-id: %v", l.userID, err)
		}
		return ""
	}
	if !found {
		return ""
	}
	return id
}

// validateFields evaluates a policy's rule (4th column). It returns (false, nil)
// when the rule is not satisfied, including when a referenced request value is
// missing or the stored rule is malformed; it returns an error only for
// internal failures (identity resolver).
func (h *ExternalAuthzHandlers) validateFields(ctx context.Context, envoyReq EnvoyRequest, policyPattern, validationRule string, tokenClaims map[string]interface{}, lookup *backendLookup) (bool, error) {
	if validationRule == "" || validationRule == "*" {
		return true, nil // No validation required
	}

	// Parse multiple conditions separated by &&
	conditions := strings.Split(validationRule, "&&")

	for _, condition := range conditions {
		condition = strings.TrimSpace(condition)
		if condition == "" {
			continue
		}

		valid, err := h.validateSingleCondition(ctx, envoyReq, policyPattern, condition, tokenClaims, lookup)
		if err != nil {
			return false, fmt.Errorf("validation condition '%s' failed: %w", condition, err)
		}

		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// validateSingleCondition evaluates one "left==right" condition.
func (h *ExternalAuthzHandlers) validateSingleCondition(ctx context.Context, envoyReq EnvoyRequest, policyPattern, condition string, tokenClaims map[string]interface{}, lookup *backendLookup) (bool, error) {
	// Only the == operator is supported; anything else is a configuration error.
	parts := strings.Split(condition, "==")
	if len(parts) != 2 {
		log.Printf("external authz: CONFIG ERROR unsupported rule condition %q in policy %q (only 'left==right' is supported); policy treated as not satisfied", condition, policyPattern)
		return false, nil
	}

	leftSide := strings.TrimSpace(parts[0])  // e.g., "path.id"
	rightSide := strings.TrimSpace(parts[1]) // e.g., "token.user_id"

	// Left side (from the request). Unavailable values make the condition false.
	leftValue, found, err := h.extractRequestValue(envoyReq, policyPattern, leftSide)
	if err != nil {
		log.Printf("external authz: CONFIG ERROR invalid rule condition %q in policy %q: %v; policy treated as not satisfied", condition, policyPattern, err)
		return false, nil
	}
	if !found {
		return false, nil
	}

	// Handle wildcard on right side (always matches if left side exists)
	if rightSide == "*" {
		return true, nil
	}

	// Right side (token claim or backend id).
	rightValue, ok, err := h.extractTokenValue(ctx, rightSide, tokenClaims, lookup)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	return leftValue == rightValue, nil
}

// extractRequestValue extracts a value from the Envoy request as a string.
// found=false means the request does not carry the value; err is only set for
// an invalid source expression (configuration error).
func (h *ExternalAuthzHandlers) extractRequestValue(envoyReq EnvoyRequest, policyPattern, source string) (string, bool, error) {
	parts := strings.SplitN(source, ".", 2)
	if len(parts) != 2 {
		return "", false, fmt.Errorf("invalid source format: %s (expected source.field)", source)
	}

	sourceType := parts[0]
	fieldName := parts[1]
	httpReq := envoyReq.Attributes.Request.HTTP

	switch sourceType {
	case "path":
		// Named parameters of the matched policy pattern first, legacy
		// hard-coded names (id, user_id) otherwise.
		if v, ok := pathParamsFromPattern(policyPattern, httpReq.Path)[fieldName]; ok {
			return v, true, nil
		}
		v, err := h.extractPathParam(httpReq.Path, fieldName)
		if err != nil {
			return "", false, nil
		}
		return fmt.Sprintf("%v", v), true, nil

	case "query":
		if httpReq.Query == "" {
			return "", false, nil
		}
		values, err := url.ParseQuery(httpReq.Query)
		if err != nil {
			return "", false, nil
		}
		// A repeated parameter is ambiguous: the upstream may read a different
		// occurrence than the one compared here, so it never satisfies a rule.
		occurrences := values[fieldName]
		if len(occurrences) != 1 || occurrences[0] == "" {
			return "", false, nil
		}
		return occurrences[0], true, nil

	case "header":
		value, exists := httpReq.Headers[fieldName]
		if !exists {
			value, exists = httpReq.Headers[strings.ToLower(fieldName)]
		}
		return value, exists, nil

	case "body":
		if httpReq.Body == "" {
			return "", false, nil
		}
		bodyBytes, err := base64.StdEncoding.DecodeString(httpReq.Body)
		if err != nil {
			return "", false, nil
		}
		dec := json.NewDecoder(bytes.NewReader(bodyBytes))
		dec.UseNumber() // keep large ids exact: 58 compares equal to "58"
		var bodyData map[string]interface{}
		if err := dec.Decode(&bodyData); err != nil {
			return "", false, nil
		}
		raw, exists := bodyData[fieldName]
		if !exists {
			return "", false, nil
		}
		switch v := raw.(type) {
		case string:
			return v, true, nil
		case json.Number:
			return v.String(), true, nil
		case bool:
			return fmt.Sprintf("%v", v), true, nil
		default: // null, object, array: not comparable
			return "", false, nil
		}

	default:
		return "", false, fmt.Errorf("unsupported source type: %s", sourceType)
	}
}

// pathParamsFromPattern aligns the segments of a policy path pattern with those
// of the request path and returns the values of the ":name" segments. Alignment
// stops at the first wildcard segment, after which positions are not reliable.
func pathParamsFromPattern(pattern, requestPath string) map[string]string {
	params := map[string]string{}
	patternParts := strings.Split(pattern, "/")
	requestParts := strings.Split(requestPath, "/")
	for i, part := range patternParts {
		if strings.Contains(part, "*") || i >= len(requestParts) {
			break
		}
		if strings.HasPrefix(part, ":") && len(part) > 1 {
			params[part[1:]] = requestParts[i]
		}
	}
	return params
}

// extractPathParam is the legacy fallback for path.<name> when <name> is not a
// ":name" parameter of the matched policy pattern.
func (h *ExternalAuthzHandlers) extractPathParam(path, paramName string) (interface{}, error) {
	pathParts := strings.Split(strings.Trim(path, "/"), "/")

	// Handle common patterns based on parameter names and path structure
	switch {
	case paramName == "id":
		// Extract last segment as ID for patterns like /users/:id, /posts/:id
		if len(pathParts) >= 2 {
			return pathParts[len(pathParts)-1], nil
		}
	case paramName == "user_id":
		// For /profile/:user_id pattern, extract the second segment
		// /profile/1875 -> parts = ["profile", "1875"] -> return "1875"
		if len(pathParts) >= 2 && pathParts[0] == "profile" {
			return pathParts[1], nil
		}
		// For /users/:user_id pattern
		if len(pathParts) >= 2 && pathParts[0] == "users" {
			return pathParts[1], nil
		}
		// For /api/orders/:user_id pattern
		// /api/orders/1875 -> parts = ["api", "orders", "1875"] -> return "1875"
		if len(pathParts) >= 3 && pathParts[0] == "api" && pathParts[1] == "orders" {
			return pathParts[2], nil
		}
	}

	return nil, fmt.Errorf("path parameter '%s' not found in path '%s'", paramName, path)
}

// extractTokenValue resolves the right-hand side of a condition. ok=false means
// the condition cannot be true (unknown claim, user without backend id); err is
// an internal failure (identity resolver unavailable).
func (h *ExternalAuthzHandlers) extractTokenValue(ctx context.Context, source string, tokenClaims map[string]interface{}, lookup *backendLookup) (string, bool, error) {
	parts := strings.SplitN(source, ".", 2)
	// Only token.<claim> is accepted. Anything else is a configuration error and
	// never satisfies the rule: comparing against the raw text would let a caller
	// pass a mistyped rule by sending that same text.
	if len(parts) != 2 || parts[0] != "token" || parts[1] == "" {
		log.Printf("external authz: CONFIG ERROR unsupported rule value %q (expected token.<claim> or *); policy treated as not satisfied", source)
		return "", false, nil
	}

	claimName := parts[1]

	if claimName == "backend_user_id" {
		id, found, err := lookup.get(ctx)
		if err != nil {
			if !lookup.logged {
				lookup.logged = true
				if errors.Is(err, errBackendIdentityNotConfigured) {
					log.Printf("external authz: rule needs token.backend_user_id but the backend identity resolver is not configured (IDENTITY_BACKEND_URL empty); failing closed for user %d", lookup.userID)
				} else {
					log.Printf("external authz: backend identity lookup failed for user %d; failing closed: %v", lookup.userID, err)
				}
			}
			return "", false, err
		}
		return id, found, nil
	}

	value, exists := tokenClaims[claimName]
	if !exists {
		return "", false, nil
	}
	return fmt.Sprintf("%v", value), true, nil
}

// Helper methods for path and method matching (reused from SimpleCasbinMW)
func (h *ExternalAuthzHandlers) pathMatches(requestPath, policyPath string) bool {
	// Use Casbin's keyMatch2 function to support parameterized paths
	// keyMatch2(key1, key2) - key1 is request path, key2 is policy pattern
	return util.KeyMatch2(requestPath, policyPath)
}

func (h *ExternalAuthzHandlers) methodMatches(requestMethod, policyMethod string) bool {
	// Exact match
	if requestMethod == policyMethod {
		return true
	}

	// Wildcard match
	if policyMethod == "*" {
		return true
	}

	// Regex pattern matching (simplified for this example)
	if strings.HasPrefix(policyMethod, "(") && strings.HasSuffix(policyMethod, ")") {
		pattern := strings.Trim(policyMethod, "()")
		methods := strings.Split(pattern, "|")
		for _, method := range methods {
			if requestMethod == strings.TrimSpace(method) {
				return true
			}
		}
	}

	return false
}

// Response helper methods
func (h *ExternalAuthzHandlers) respondUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, AuthzResponse{
		Status: struct {
			Code int `json:"code"`
		}{Code: http.StatusUnauthorized},
		Body: fmt.Sprintf(`{"error": "%s"}`, message),
	})
}

func (h *ExternalAuthzHandlers) respondForbidden(c *gin.Context, message string) {
	c.JSON(http.StatusForbidden, AuthzResponse{
		Status: struct {
			Code int `json:"code"`
		}{Code: http.StatusForbidden},
		Body: fmt.Sprintf(`{"error": "%s"}`, message),
	})
}
