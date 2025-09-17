package notifications

import (
	"fmt"

	"github.com/twilio/twilio-go"
	twilioApi "github.com/twilio/twilio-go/rest/api/v2010"
	"github.com/you/authzsvc/domain"
)

// TwilioServiceImpl implements domain.NotificationService
type TwilioServiceImpl struct {
	client     *twilio.RestClient
	fromNumber string
}

// NewTwilioService creates a new Twilio notification service
func NewTwilioService(accountSID, authToken, fromNumber string) domain.NotificationService {
	client := twilio.NewRestClientWithParams(twilio.ClientParams{
		Username: accountSID,
		Password: authToken,
	})

	return &TwilioServiceImpl{
		client:     client,
		fromNumber: fromNumber,
	}
}

// SendSMS implements domain.NotificationService
func (t *TwilioServiceImpl) SendSMS(to, message string) error {
	// If credentials are not configured, log instead of sending
	if t.fromNumber == "" {
		fmt.Printf("[MOCK SMS] To: %s, Message: %s\n", to, message)
		return nil
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
	fmt.Printf("[MOCK EMAIL] To: %s, Subject: %s, Body: %s\n", to, subject, body)
	return nil
}