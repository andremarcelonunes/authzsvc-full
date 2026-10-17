package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/you/authzsvc/domain"
)

const (
	defaultVerifyBaseURL = "https://verify.twilio.com"
	// verifySendWindow is Twilio's window for the send-attempt limit (60203).
	verifySendWindow = 10 * time.Minute
)

// Twilio Verify error codes the adapter maps.
const (
	verifyErrInvalidParameter  = 60200
	verifyErrMaxCheckAttempts  = 60202
	verifyErrMaxSendAttempts   = 60203
	verifyErrVerificationGone  = 20404
	maxVerifyResponseBodyBytes = 1 << 16
)

// TwilioVerify implements domain.PhoneCodeVerifier over the Twilio Verify v2 REST API.
// It never returns or logs a Twilio message: errors are mapped to domain errors and the log line
// carries only the HTTP status, the Twilio code and the masked phone.
type TwilioVerify struct {
	httpClient *http.Client
	baseURL    string
	accountSID string
	authToken  string
	serviceSID string
}

// VerifyOption configures TwilioVerify.
type VerifyOption func(*TwilioVerify)

// WithVerifyHTTPClient replaces the HTTP client (tests, timeouts).
func WithVerifyHTTPClient(c *http.Client) VerifyOption {
	return func(v *TwilioVerify) { v.httpClient = c }
}

// WithVerifyBaseURL replaces https://verify.twilio.com (tests).
func WithVerifyBaseURL(u string) VerifyOption {
	return func(v *TwilioVerify) { v.baseURL = u }
}

// NewTwilioVerify builds the adapter with the account credentials and the Verify Service SID.
func NewTwilioVerify(accountSID, authToken, serviceSID string, opts ...VerifyOption) *TwilioVerify {
	v := &TwilioVerify{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		baseURL:    defaultVerifyBaseURL,
		accountSID: accountSID,
		authToken:  authToken,
		serviceSID: serviceSID,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

type verifyResponse struct {
	Status string `json:"status"`
	Code   int    `json:"code"`
}

func (v *TwilioVerify) post(ctx context.Context, path string, form url.Values) (int, verifyResponse, error) {
	var out verifyResponse
	endpoint := fmt.Sprintf("%s/v2/Services/%s/%s", v.baseURL, v.serviceSID, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return 0, out, fmt.Errorf("%w: %v", domain.ErrSMSNotSent, err) // nothing reached the network
	}
	req.SetBasicAuth(v.accountSID, v.authToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := v.httpClient.Do(req)
	if err != nil {
		// Transport error: the request may or may not have arrived. No URL, no body in the error.
		return 0, out, fmt.Errorf("twilio verify request failed")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxVerifyResponseBodyBytes))
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out, nil
}

// StartVerification sends a code (Channel=sms) to phone.
func (v *TwilioVerify) StartVerification(ctx context.Context, phone string) error {
	if phone == "" {
		return fmt.Errorf("%w: empty destination", domain.ErrSMSNotSent)
	}
	status, body, err := v.post(ctx, "Verifications", url.Values{"To": {phone}, "Channel": {"sms"}})
	if err != nil {
		log.Printf("TWILIO_VERIFY_START_FAILED: phone=%s error=%v", maskPhone(phone), err)
		return err
	}
	if status >= 200 && status < 300 {
		return nil
	}
	log.Printf("TWILIO_VERIFY_START_REFUSED: phone=%s http=%d twilio_code=%d", maskPhone(phone), status, body.Code)
	switch body.Code {
	case verifyErrInvalidParameter:
		return domain.ErrSMSInvalidPhone
	case verifyErrMaxSendAttempts:
		return &domain.SMSLimitError{Kind: domain.SMSLimitPhoneInterval, RetryAfter: verifySendWindow}
	}
	return fmt.Errorf("twilio verify start refused (http %d, code %d)", status, body.Code)
}

// CheckVerification checks code for phone: approved is true only for status "approved".
func (v *TwilioVerify) CheckVerification(ctx context.Context, phone, code string) (bool, error) {
	status, body, err := v.post(ctx, "VerificationCheck", url.Values{"To": {phone}, "Code": {code}})
	if err != nil {
		log.Printf("TWILIO_VERIFY_CHECK_FAILED: phone=%s error=%v", maskPhone(phone), err)
		return false, err
	}
	if status >= 200 && status < 300 {
		switch body.Status {
		case "approved":
			return true, nil
		case "pending":
			return false, nil
		case "max_attempts_reached":
			return false, domain.ErrOTPMaxAttempts
		case "expired", "canceled", "deleted":
			return false, domain.ErrOTPExpired
		}
		log.Printf("TWILIO_VERIFY_CHECK_UNEXPECTED: phone=%s status=%q", maskPhone(phone), body.Status)
		return false, fmt.Errorf("twilio verify check: unexpected status")
	}
	log.Printf("TWILIO_VERIFY_CHECK_REFUSED: phone=%s http=%d twilio_code=%d", maskPhone(phone), status, body.Code)
	switch body.Code {
	case verifyErrMaxCheckAttempts:
		return false, domain.ErrOTPMaxAttempts
	case verifyErrVerificationGone:
		return false, domain.ErrOTPExpired
	case verifyErrInvalidParameter:
		return false, domain.ErrOTPInvalid
	}
	return false, fmt.Errorf("twilio verify check refused (http %d, code %d)", status, body.Code)
}

var _ domain.PhoneCodeVerifier = (*TwilioVerify)(nil)

// WithTwilioVerifyIfConfigured turns Twilio Verify on when the account credentials and the Verify
// Service SID are all set; otherwise it changes nothing (direct SMS keeps working as before).
func WithTwilioVerifyIfConfigured(accountSID, authToken, serviceSID string) NotifierOption {
	return func(b *BudgetedNotifier) {
		if accountSID == "" || authToken == "" || serviceSID == "" {
			return
		}
		b.verifier = NewTwilioVerify(accountSID, authToken, serviceSID)
		log.Printf("SMS codes go through Twilio Verify (service %s)", maskPhone(serviceSID))
	}
}
