package httpx

import "github.com/gin-gonic/gin"

// ApplyClientIPPolicy decides what c.ClientIP() means for the whole engine (rate limits, audit, the
// SMS budget). No proxy is ever trusted, so X-Forwarded-For and X-Real-IP written by a client are
// ignored. header is the one request header the trusted gateway writes with the caller address
// (CLIENT_IP_HEADER, e.g. X-Envoy-External-Address); empty means the TCP peer.
func ApplyClientIPPolicy(r *gin.Engine, header string) {
	_ = r.SetTrustedProxies(nil)
	r.TrustedPlatform = header
}
