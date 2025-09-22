package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockDataEncryptor implements domain.DataEncryptor interface for testing
type MockDataEncryptor struct {
	EncryptFunc       func(ctx context.Context, data []byte) ([]byte, error)
	DecryptFunc       func(ctx context.Context, encryptedData []byte) ([]byte, error)
	EncryptFieldsFunc func(ctx context.Context, data map[string]interface{}, sensitiveFields []string) (map[string]interface{}, error)
	DecryptFieldsFunc func(ctx context.Context, encryptedData map[string]interface{}, sensitiveFields []string) (map[string]interface{}, error)
	RotateKeysFunc    func(ctx context.Context) error
	GetKeyVersionFunc func(ctx context.Context) (string, error)
}

// NewMockDataEncryptor creates a new MockDataEncryptor with default behaviors
func NewMockDataEncryptor() *MockDataEncryptor {
	return &MockDataEncryptor{}
}

// Encrypt encrypts data
func (m *MockDataEncryptor) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	if m.EncryptFunc != nil {
		return m.EncryptFunc(ctx, data)
	}
	// Default behavior: return encrypted mock data
	prefix := []byte("encrypted_")
	return append(prefix, data...), nil
}

// Decrypt decrypts data
func (m *MockDataEncryptor) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	if m.DecryptFunc != nil {
		return m.DecryptFunc(ctx, encryptedData)
	}
	// Default behavior: return decrypted mock data
	prefix := []byte("encrypted_")
	if len(encryptedData) > len(prefix) && string(encryptedData[:len(prefix)]) == "encrypted_" {
		return encryptedData[len(prefix):], nil
	}
	return encryptedData, nil
}

// EncryptFields encrypts sensitive fields in a map
func (m *MockDataEncryptor) EncryptFields(ctx context.Context, data map[string]interface{}, sensitiveFields []string) (map[string]interface{}, error) {
	if m.EncryptFieldsFunc != nil {
		return m.EncryptFieldsFunc(ctx, data, sensitiveFields)
	}
	// Default behavior: return mock encrypted fields
	result := make(map[string]interface{})
	for _, field := range sensitiveFields {
		if value, exists := data[field]; exists {
			if strValue, ok := value.(string); ok {
				result[field] = "encrypted_" + strValue
			} else {
				result[field] = value
			}
		}
	}
	return result, nil
}

// DecryptFields decrypts sensitive fields in a map
func (m *MockDataEncryptor) DecryptFields(ctx context.Context, encryptedData map[string]interface{}, sensitiveFields []string) (map[string]interface{}, error) {
	if m.DecryptFieldsFunc != nil {
		return m.DecryptFieldsFunc(ctx, encryptedData, sensitiveFields)
	}
	// Default behavior: return mock decrypted fields
	result := make(map[string]interface{})
	for _, field := range sensitiveFields {
		if value, exists := encryptedData[field]; exists {
			if strValue, ok := value.(string); ok {
				if len(strValue) > 10 && strValue[:10] == "encrypted_" {
					result[field] = strValue[10:]
				} else {
					result[field] = strValue
				}
			} else {
				result[field] = value
			}
		}
	}
	return result, nil
}

// RotateKeys rotates encryption keys
func (m *MockDataEncryptor) RotateKeys(ctx context.Context) error {
	if m.RotateKeysFunc != nil {
		return m.RotateKeysFunc(ctx)
	}
	// Default behavior: success
	return nil
}

// GetKeyVersion gets current key version
func (m *MockDataEncryptor) GetKeyVersion(ctx context.Context) (string, error) {
	if m.GetKeyVersionFunc != nil {
		return m.GetKeyVersionFunc(ctx)
	}
	// Default behavior: return mock version
	return "v1.0.0", nil
}

// Compile-time interface compliance verification
var _ domain.DataEncryptor = (*MockDataEncryptor)(nil)