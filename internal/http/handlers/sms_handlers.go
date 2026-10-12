package handlers

import (
	"errors"
	"math"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// SMS limit answers, in Portuguese for the app.
const (
	smsLimitMessage       = "Limite de envio de códigos atingido. Tente novamente mais tarde."
	smsUnavailableMessage = "Envio de códigos indisponível no momento. Tente novamente mais tarde."
)

// respondSMSError answers the SMS budget errors and reports whether it did:
//   - per-phone / interval / per-address limit: 429 {"error":"sms_limit","message":...,"retry_after_seconds":N} + Retry-After;
//   - installation cap or budget store failure: 503 {"error":"sms_unavailable","message":...}.
func respondSMSError(c *gin.Context, err error) bool {
	var limit *domain.SMSLimitError
	switch {
	case errors.As(err, &limit):
		seconds := int(math.Ceil(limit.RetryAfter.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		c.Header("Retry-After", strconv.Itoa(seconds))
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":               "sms_limit",
			"message":             smsLimitMessage,
			"retry_after_seconds": seconds,
		})
		return true
	case errors.Is(err, domain.ErrSMSUnavailable):
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "sms_unavailable", "message": smsUnavailableMessage})
		return true
	}
	return false
}

// SMSUsageHandler serves GET /admin/sms/usage.
type SMSUsageHandler struct {
	budget domain.SMSBudget
}

// NewSMSUsageHandler builds the handler over the budget.
func NewSMSUsageHandler(budget domain.SMSBudget) *SMSUsageHandler {
	return &SMSUsageHandler{budget: budget}
}

// Usage returns {"data":{"today","month","daily_cap","monthly_cap"}}: SMS accepted by the provider and
// the installation caps. It carries no phone numbers.
func (h *SMSUsageHandler) Usage(c *gin.Context) {
	usage, err := h.budget.Usage(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "sms_usage_unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": usage})
}
