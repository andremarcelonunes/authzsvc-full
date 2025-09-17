package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockOTPService implements domain.OTPService interface for testing
type MockOTPService struct {
	GenerateFunc  func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error)
	VerifyFunc    func(ctx context.Context, phone, code string, userID uint) (bool, error)
	CanResendFunc func(ctx context.Context, phone string) (bool, int64, error)
}

// NewMockOTPService creates a new MockOTPService with default behaviors
func NewMockOTPService() *MockOTPService {
	return &MockOTPService{}
}

// Generate generates a new OTP for the given phone number
func (m *MockOTPService) Generate(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
	if m.GenerateFunc != nil {
		return m.GenerateFunc(ctx, phone, userID)
	}
	// Default behavior: return a mock OTP request
	return &domain.OTPRequest{
		Phone:     phone,
		Code:      "123456", // Mock OTP code for testing
		UserID:    userID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Attempts:  0,
	}, nil
}

// Verify verifies an OTP code for the given phone number
func (m *MockOTPService) Verify(ctx context.Context, phone, code string, userID uint) (bool, error) {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(ctx, phone, code, userID)
	}
	// Default behavior: accept "123456" as valid OTP
	return code == "123456", nil
}

// CanResend checks if an OTP can be resent for the given phone number
func (m *MockOTPService) CanResend(ctx context.Context, phone string) (bool, int64, error) {
	if m.CanResendFunc != nil {
		return m.CanResendFunc(ctx, phone)
	}
	// Default behavior: allow resend with no wait time
	return true, 0, nil
}

// Compile-time interface compliance verification
var _ domain.OTPService = (*MockOTPService)(nil)