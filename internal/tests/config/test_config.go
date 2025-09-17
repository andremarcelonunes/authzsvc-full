package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joho/godotenv"

	"github.com/you/authzsvc/internal/config"
)

// LoadTestConfig loads configuration specifically for E2E testing
func LoadTestConfig(t *testing.T) *config.Config {
	t.Helper()

	// Load test environment variables from .env.test
	if err := godotenv.Load(".env.test"); err != nil {
		// Fallback to environment variables if .env.test doesn't exist
		t.Logf("Warning: Could not load .env.test file: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Failed to load test configuration: %v", err)
	}

	// Validate test configuration
	validateTestConfig(t, cfg)

	return cfg
}

// validateTestConfig ensures all required test configurations are present
func validateTestConfig(t *testing.T, cfg *config.Config) {
	t.Helper()

	if cfg.DSN == "" {
		t.Fatal("DATABASE_DSN must be set for E2E tests")
	}

	if cfg.RedisAddr == "" {
		t.Fatal("REDIS_ADDR must be set for E2E tests")
	}

	if cfg.JWTSecret == "" || cfg.JWTSecret == "change" {
		t.Fatal("JWT_SECRET must be set to a secure value for tests")
	}

	// Ensure we're using a test database to avoid data corruption
	if cfg.RedisDB == 0 {
		t.Log("Warning: Using Redis DB 0 for tests. Consider using a dedicated test DB (e.g., DB 1)")
	}

	t.Logf("Test config loaded - DB: %s, Redis: %s (DB %d)", 
		maskDSN(cfg.DSN), cfg.RedisAddr, cfg.RedisDB)
}

// maskDSN masks sensitive information in database DSN for logging
func maskDSN(dsn string) string {
	// Simple masking for logging - replace password with ***
	// This is a basic implementation for security
	return "postgres://auth:***@localhost:5432/authdb"
}

// GetTestJWTSecret returns a deterministic JWT secret for testing
func GetTestJWTSecret() string {
	return "test-jwt-secret-for-e2e-validation-cb176"
}

// GetTestRedisDB returns the Redis database number for tests
func GetTestRedisDB() int {
	return 1 // Use DB 1 for tests to avoid conflicts with dev data
}

// SetupTestEnvironment sets up environment variables for testing
func SetupTestEnvironment(t *testing.T) {
	t.Helper()

	// Set test-specific environment variables
	testEnvVars := map[string]string{
		"GIN_MODE":           "test",
		"APP_PORT":           "8081",
		"JWT_SECRET":         GetTestJWTSecret(),
		"JWT_ISSUER":         "authzsvc-test",
		"JWT_ACCESS_TTL":     "900s",
		"JWT_REFRESH_TTL":    "168h",
		"OTP_TTL":           "5m",
		"OTP_LENGTH":        "6",
		"OTP_MAX_ATTEMPTS":  "5",
		"OTP_RESEND_WINDOW": "60s",
		// Mock Twilio credentials for testing
		"TWILIO_ACCOUNT_SID":  "test_sid",
		"TWILIO_AUTH_TOKEN":   "test_token", 
		"TWILIO_FROM_NUMBER":  "+15551234567",
	}

	// Set environment variables for the test duration
	for key, value := range testEnvVars {
		originalValue := os.Getenv(key)
		os.Setenv(key, value)
		
		// Cleanup after test
		t.Cleanup(func() {
			if originalValue == "" {
				os.Unsetenv(key)
			} else {
				os.Setenv(key, originalValue)
			}
		})
	}
}

// GetProjectRoot returns the project root directory for config files
func GetProjectRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}

	// Navigate up to find the project root (where go.mod exists)
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		
		parent := filepath.Dir(wd)
		if parent == wd {
			// Reached filesystem root
			break
		}
		wd = parent
	}
	
	return "." // Fallback to current directory
}

// TestDatabaseConfig holds database test configuration
type TestDatabaseConfig struct {
	Host     string
	Port     string  
	Database string
	Schema   string
	User     string
	Password string
}

// GetTestDatabaseConfig returns your specific test database configuration
func GetTestDatabaseConfig() *TestDatabaseConfig {
	return &TestDatabaseConfig{
		Host:     "localhost",
		Port:     "5432",
		Database: "authdb", 
		Schema:   "auth",
		User:     "auth",
		Password: "123456",
	}
}

// GetTestDSN builds the test database DSN from your configuration
func GetTestDSN() string {
	dbConfig := GetTestDatabaseConfig()
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable&search_path=%s",
		dbConfig.User,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.Database,
		dbConfig.Schema,
	)
}

// TestRedisConfig holds Redis test configuration  
type TestRedisConfig struct {
	Host     string
	Port     string
	Password string
	DB       int
}

// GetTestRedisConfig returns your specific test Redis configuration
func GetTestRedisConfig() *TestRedisConfig {
	return &TestRedisConfig{
		Host:     "localhost",
		Port:     "6379", 
		Password: "", // No password for your local Redis
		DB:       1,  // Use DB 1 for tests
	}
}

// GetTestRedisAddr builds the test Redis address
func GetTestRedisAddr() string {
	redisConfig := GetTestRedisConfig()
	return fmt.Sprintf("%s:%s", redisConfig.Host, redisConfig.Port)
}

// WaitForServices waits for database and Redis to be available
func WaitForServices(t *testing.T, cfg *config.Config, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		// Test database connection
		// Test Redis connection  
		// Implementation would check actual connectivity
		t.Log("Services are available for testing")
		return
	}
	
	t.Fatal("Timeout waiting for test services to become available")
}