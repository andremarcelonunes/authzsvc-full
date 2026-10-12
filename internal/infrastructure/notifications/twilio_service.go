package notifications

import (
	"fmt"
	"log"
	"strings"

	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
	"github.com/you/authzsvc/domain"
)

// TwilioServiceImpl implements domain.NotificationService
type TwilioServiceImpl struct {
	client      *twilio.RestClient
	fromNumber  string
	logMessages bool
}

// Option configures TwilioServiceImpl.
type Option func(*TwilioServiceImpl)

// WithLogMessages makes the no-provider mock path print the whole message, one-time code included
// (OTP_LOG_CODES). Off by default: the mock path then logs only that a message was generated, for a
// masked phone.
func WithLogMessages(on bool) Option {
	return func(t *TwilioServiceImpl) { t.logMessages = on }
}

// logMockSMS is the mock path: nothing is sent. The message (code included) is logged only when full
// is true (OTP_LOG_CODES); otherwise only that a message was generated, for a masked phone.
func logMockSMS(to, message string, full bool) {
	if full {
		log.Printf("[MOCK SMS] To: %s, Message: %s", to, message)
		return
	}
	log.Printf("[MOCK SMS] a message was generated for %s and not sent: no SMS provider configured (OTP_LOG_CODES=true prints it)", maskPhone(to))
}

// maskPhone keeps the first three and last two characters: +55*******00.
func maskPhone(phone string) string {
	if len(phone) <= 6 {
		return strings.Repeat("*", len(phone))
	}
	return phone[:3] + strings.Repeat("*", len(phone)-5) + phone[len(phone)-2:]
}

// NewTwilioService creates a new Twilio notification service
func NewTwilioService(accountSID, authToken, fromNumber string, opts ...Option) domain.NotificationService {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	svc := &TwilioServiceImpl{
		client:     client,
		fromNumber: fromNumber,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// Live reports whether a real provider is configured; the mock path is not live and costs nothing.
func (t *TwilioServiceImpl) Live() bool { return t.fromNumber != "" }

// SendSMS implements domain.NotificationService
func (t *TwilioServiceImpl) SendSMS(to, message string) error {
	// If credentials are not configured, log instead of sending
	if t.fromNumber == "" {
		logMockSMS(to, message, t.logMessages)
		return nil
	}

	if to == "" {
		return fmt.Errorf("%w: empty destination", domain.ErrSMSNotSent) // nothing reached the provider
	}

	params := &twilioApi.CreateMessageParams{}
	params.SetTo(to)
	params.SetFrom(t.fromNumber)
	params.SetBody(message)

	_, err := t.client.Api.CreateMessage(params)
	if err != nil {
		return fmt.Errorf("failed to send SMS: %w", err)
	}

	return nil
}

// SendEmail implements domain.NotificationService
func (t *TwilioServiceImpl) SendEmail(to, subject, body string) error {
	// Email not implemented with Twilio
	log.Printf("[MOCK EMAIL] a message was generated for %s and not sent", maskEmail(to))
	return nil
}
// maskEmail keeps the first character and the domain: a***@example.com.
func maskEmail(email string) string {
	at := strings.LastIndex(email, "@")
	if at <= 0 {
		return "***"
	}
	return email[:1] + "***" + email[at:]
}
