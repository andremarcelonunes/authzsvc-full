package domain

import "time"

// Defaults of the public registration rate limit per client IP. They are the values that were
// hard-coded in the request validator and in the HTTP validation middleware before the limit
// became configurable (REGISTRATION_RATE_LIMIT_PER_IP / REGISTRATION_RATE_LIMIT_WINDOW).
const (
	DefaultRegistrationRateLimitPerIP = 2
	DefaultRegistrationRateWindow     = 30 * time.Second
)

// RegistrationRequestsPerMinute converts the per-window limit into the per-minute budget the
// HTTP middleware applies to POST /auth/register (it counts in a fixed one-minute window). With
// the defaults (2 per 30s) it is 4, the value the middleware always used. The result is at least 1.
func RegistrationRequestsPerMinute(limit int, window time.Duration) int {
	if limit <= 0 || window <= 0 {
		limit, window = DefaultRegistrationRateLimitPerIP, DefaultRegistrationRateWindow
	}
	perMinute := (int64(limit)*int64(time.Minute) + int64(window) - 1) / int64(window)
	if perMinute < 1 {
		return 1
	}
	return int(perMinute)
}
