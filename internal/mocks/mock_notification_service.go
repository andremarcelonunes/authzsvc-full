package mocks

import "github.com/you/authzsvc/domain"

// MockNotificationService implements domain.NotificationService interface for testing
type MockNotificationService struct {
	SendSMSFunc   func(to, message string) error
	SendEmailFunc func(to, subject, body string) error
}

// NewMockNotificationService creates a new MockNotificationService with default behaviors
func NewMockNotificationService() *MockNotificationService {
	return &MockNotificationService{}
}

// SendSMS sends an SMS message
func (m *MockNotificationService) SendSMS(to, message string) error {
	if m.SendSMSFunc != nil {
		return m.SendSMSFunc(to, message)
	}
	// Default behavior: success (no actual SMS sent in tests)
	return nil
}

// SendEmail sends an email message
func (m *MockNotificationService) SendEmail(to, subject, body string) error {
	if m.SendEmailFunc != nil {
		return m.SendEmailFunc(to, subject, body)
	}
	// Default behavior: success (no actual email sent in tests)
	return nil
}

// Compile-time interface compliance verification
var _ domain.NotificationService = (*MockNotificationService)(nil)