// Package identity resolves the backend user id of an AuthzSvc user through the
// backend's internal translation API.
package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout is used when no (or a non-positive) timeout is configured.
const DefaultTimeout = 2 * time.Second

const maxResponseBytes = 1 << 20

// HTTPResolver implements domain.BackendIdentityResolver over
//
//	GET {base}/api/v1/internal/users/authz/{authz_user_id}/backend   (X-API-Key)
type HTTPResolver struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

// NewHTTPResolver builds the resolver. A non-positive timeout means DefaultTimeout.
func NewHTTPResolver(baseURL, apiKey string, timeout time.Duration) *HTTPResolver {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &HTTPResolver{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client:  &http.Client{Timeout: timeout},
	}
}

type translationResponse struct {
	BackendUserID json.Number `json:"backend_user_id"`
}

// ResolveBackendUserID: 200 -> found, 404 -> not found (nil error), anything
// else (including network failures and timeouts) -> error. Errors never contain
// the API key.
func (r *HTTPResolver) ResolveBackendUserID(ctx context.Context, authzUserID uint) (string, bool, error) {
	endpoint := fmt.Sprintf("%s/api/v1/internal/users/authz/%d/backend", r.baseURL, authzUserID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false, fmt.Errorf("identity: build request: %w", err)
	}
	req.Header.Set("X-API-Key", r.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("identity: request failed: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var body translationResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body); err != nil {
			return "", false, fmt.Errorf("identity: invalid response body: %w", err)
		}
		id := body.BackendUserID.String()
		if id == "" {
			return "", false, fmt.Errorf("identity: response without backend_user_id")
		}
		return id, true, nil
	case http.StatusNotFound:
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return "", false, nil
	default:
		io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return "", false, fmt.Errorf("identity: unexpected status %d", resp.StatusCode)
	}
}
