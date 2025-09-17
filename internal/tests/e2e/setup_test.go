package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/you/authzsvc/internal/config"
	testconfig "github.com/you/authzsvc/internal/tests/config"
	"github.com/you/authzsvc/domain"
)

// TestSuite holds the E2E test infrastructure
type TestSuite struct {
	Config     *config.Config
	DB         *gorm.DB
	RawDB      *sql.DB
	Redis      *redis.Client
	TestPrefix string
	StartTime  time.Time
}

var globalSuite *TestSuite

// TestMain sets up and tears down the test environment
func TestMain(m *testing.M) {
	var code int
	defer func() {
		if globalSuite != nil {
			globalSuite.TearDown()
		}
		os.Exit(code)
	}()

	// Setup test environment
	suite, err := SetupTestSuite()
	if err != nil {
		log.Fatalf("Failed to setup test suite: %v", err)
	}
	globalSuite = suite

	// Run tests
	code = m.Run()
}

// SetupTestSuite initializes the complete E2E test environment
func SetupTestSuite() (*TestSuite, error) {
	// Load test configuration
	cfg, err := loadTestConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load test config: %w", err)
	}

	// Generate unique test prefix for isolation
	testPrefix := fmt.Sprintf("e2e_test_%d", time.Now().Unix())

	// Initialize database connection
	db, rawDB, err := setupTestDatabase(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to setup test database: %w", err)
	}

	// Initialize Redis connection
	redisClient, err := setupTestRedis(cfg, testPrefix)
	if err != nil {
		return nil, fmt.Errorf("failed to setup test redis: %w", err)
	}

	// Test connections
	if err := testConnections(db, redisClient); err != nil {
		return nil, fmt.Errorf("connection test failed: %w", err)
	}

	suite := &TestSuite{
		Config:     cfg,
		DB:         db,
		RawDB:      rawDB,
		Redis:      redisClient,
		TestPrefix: testPrefix,
		StartTime:  time.Now(),
	}

	log.Printf("E2E Test Suite initialized successfully (prefix: %s)", testPrefix)
	return suite, nil
}

// loadTestConfig loads configuration with proper test environment setup
func loadTestConfig() (*config.Config, error) {
	// Set test environment variables
	// Get project root to build absolute paths for config files
	projectRoot := testconfig.GetProjectRoot()
	
	testEnvVars := map[string]string{
		"GIN_MODE":           "test",
		"APP_PORT":           "8081",
		"JWT_SECRET":         "test-secret-for-cb176-e2e-validation",
		"JWT_ISSUER":         "authzsvc-test",
		"JWT_ACCESS_TTL":     "900s",
		"JWT_REFRESH_TTL":    "168h",
		"OTP_TTL":           "5m",
		"OTP_LENGTH":        "6",
		"OTP_MAX_ATTEMPTS":  "5",
		"OTP_RESEND_WINDOW": "60s",
		"TWILIO_ACCOUNT_SID":  "test_twilio_sid",
		"TWILIO_AUTH_TOKEN":   "test_twilio_token",
		"TWILIO_FROM_NUMBER":  "+15551234567",
		"DATABASE_DSN":        testconfig.GetTestDSN(),
		"REDIS_ADDR":          testconfig.GetTestRedisAddr(),
		"REDIS_DB":           "1",
		"CASBIN_MODEL":       projectRoot + "/casbin/model.conf",
	}

	// Set environment variables
	for key, value := range testEnvVars {
		os.Setenv(key, value)
	}

	// Load configuration with test-specific paths
	cfg, err := loadConfigForTests(projectRoot)
	if err != nil {
		return nil, err
	}

	// Override Redis DB for testing
	cfg.RedisDB = testconfig.GetTestRedisDB()

	return cfg, nil
}

// setupTestDatabase initializes database connection with proper settings
func setupTestDatabase(dsn string) (*gorm.DB, *sql.DB, error) {
	// Configure GORM logger for test environment
	gormLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logger.Silent, // Reduce noise in tests
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	// Open database connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:         gormLogger,
		NowFunc:        func() time.Time { return time.Now().UTC() },
		TranslateError: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to test database: %w", err)
	}

	// Get underlying sql.DB for raw operations
	rawDB, err := db.DB()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get raw database connection: %w", err)
	}

	// Configure connection pool for testing
	rawDB.SetMaxIdleConns(10)
	rawDB.SetMaxOpenConns(20)
	rawDB.SetConnMaxLifetime(time.Hour)

	// Run auto-migration to ensure schema is up to date
	if err := db.AutoMigrate(
		&domain.User{},
		// Add other domain entities as they're created
	); err != nil {
		return nil, nil, fmt.Errorf("failed to run auto-migration: %w", err)
	}

	return db, rawDB, nil
}

// setupTestRedis initializes Redis connection for testing
func setupTestRedis(cfg *config.Config, testPrefix string) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB, // Use test database (1)
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to test Redis: %w", err)
	}

	return client, nil
}

// testConnections verifies that all required services are available
func testConnections(db *gorm.DB, redisClient *redis.Client) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test database connection
	rawDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("failed to get raw database connection: %w", err)
	}

	if err := rawDB.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	// Test Redis connection
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping failed: %w", err)
	}

	return nil
}

// TearDown cleans up test environment and resources
func (ts *TestSuite) TearDown() {
	log.Printf("Tearing down E2E test suite (prefix: %s)", ts.TestPrefix)

	// Cleanup Redis keys with test prefix
	if ts.Redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Find all keys with test prefix
		keys, err := ts.Redis.Keys(ctx, fmt.Sprintf("%s:*", ts.TestPrefix)).Result()
		if err == nil && len(keys) > 0 {
			if err := ts.Redis.Del(ctx, keys...).Err(); err != nil {
				log.Printf("Warning: Failed to cleanup Redis test keys: %v", err)
			} else {
				log.Printf("Cleaned up %d Redis test keys", len(keys))
			}
		}

		ts.Redis.Close()
	}

	// Close database connections
	if ts.RawDB != nil {
		ts.RawDB.Close()
	}

	duration := time.Since(ts.StartTime)
	log.Printf("E2E test suite completed in %v", duration)
}

// GetTestSuite returns the global test suite instance
func GetTestSuite() *TestSuite {
	if globalSuite == nil {
		panic("Test suite not initialized. Ensure TestMain is properly set up.")
	}
	return globalSuite
}

// WithTransaction runs a function within a database transaction that gets rolled back
func (ts *TestSuite) WithTransaction(fn func(*gorm.DB) error) error {
	tx := ts.DB.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	// Always rollback in tests for isolation
	tx.Rollback()
	return nil
}

// CleanupTestData removes all test data from database tables
func (ts *TestSuite) CleanupTestData() error {
	// Disable foreign key checks temporarily
	if err := ts.DB.Exec("SET session_replication_role = replica").Error; err != nil {
		return fmt.Errorf("failed to disable foreign key checks: %w", err)
	}

	// Cleanup tables in reverse dependency order
	tables := []string{
		"casbin_rule",
		"users",
		// Add other tables as needed
	}

	for _, table := range tables {
		if err := ts.DB.Exec(fmt.Sprintf("DELETE FROM %s", table)).Error; err != nil {
			log.Printf("Warning: Failed to cleanup table %s: %v", table, err)
		}
	}

	// Re-enable foreign key checks
	if err := ts.DB.Exec("SET session_replication_role = DEFAULT").Error; err != nil {
		return fmt.Errorf("failed to re-enable foreign key checks: %w", err)
	}

	return nil
}

// GetRedisKey generates a Redis key with test prefix for isolation
func (ts *TestSuite) GetRedisKey(key string) string {
	return fmt.Sprintf("%s:%s", ts.TestPrefix, key)
}

// WaitForServices ensures all required services are ready
func (ts *TestSuite) WaitForServices(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		if err := testConnections(ts.DB, ts.Redis); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("timeout waiting for services to become ready")
}

// loadConfigForTests loads configuration with test-specific absolute paths
func loadConfigForTests(projectRoot string) (*config.Config, error) {
	accTTL, _ := time.ParseDuration(os.Getenv("JWT_ACCESS_TTL"))
	if accTTL == 0 {
		accTTL = 15 * time.Minute
	}
	
	refTTL, _ := time.ParseDuration(os.Getenv("JWT_REFRESH_TTL"))
	if refTTL == 0 {
		refTTL = 168 * time.Hour
	}
	
	otpTTL, _ := time.ParseDuration(os.Getenv("OTP_TTL"))
	if otpTTL == 0 {
		otpTTL = 5 * time.Minute
	}
	
	resWnd, _ := time.ParseDuration(os.Getenv("OTP_RESEND_WINDOW"))
	if resWnd == 0 {
		resWnd = 60 * time.Second
	}

	// Load ownership rules with absolute path
	ownershipRulesPath := projectRoot + "/config/ownership_rules.yml"
	ownershipRules, err := loadOwnershipRulesFromPath(ownershipRulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ownership rules: %w", err)
	}

	// Load validation rules with absolute path (optional for tests)
	validationRulesPath := projectRoot + "/config/validation_rules.yml"
	validationRules, err := loadValidationRulesFromPath(validationRulesPath)
	if err != nil {
		// If validation rules file doesn't exist, that's okay for testing
		validationRules = []config.ValidationRule{}
	}

	return &config.Config{
		Port:             os.Getenv("APP_PORT"),
		DSN:              os.Getenv("DATABASE_DSN"),
		RedisAddr:        os.Getenv("REDIS_ADDR"),
		RedisPassword:    os.Getenv("REDIS_PASSWORD"),
		RedisDB:          0, // Will be overridden to test DB
		JWTSecret:        os.Getenv("JWT_SECRET"),
		JWTIssuer:        os.Getenv("JWT_ISSUER"),
		AccessTTL:        accTTL,
		RefreshTTL:       refTTL,
		OTP_TTL:          otpTTL,
		OTP_Length:       atoi(os.Getenv("OTP_LENGTH")),
		OTP_MaxAttempts:  atoi(os.Getenv("OTP_MAX_ATTEMPTS")),
		OTP_ResendWindow: resWnd,
		TwilioSID:        os.Getenv("TWILIO_ACCOUNT_SID"),
		TwilioToken:      os.Getenv("TWILIO_AUTH_TOKEN"),
		TwilioFrom:       os.Getenv("TWILIO_FROM_NUMBER"),
		CasbinModelPath:  os.Getenv("CASBIN_MODEL"),
		OwnershipRules:   ownershipRules,
		ValidationRules:  validationRules,
	}, nil
}

// loadOwnershipRulesFromPath loads ownership rules from an absolute path
func loadOwnershipRulesFromPath(path string) ([]config.OwnershipRule, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read ownership rules file at %s: %w", path, err)
	}

	var rules struct {
		Rules []config.OwnershipRule `yaml:"ownershipRules"`
	}
	if err := yaml.Unmarshal(bytes, &rules); err != nil {
		return nil, fmt.Errorf("could not parse ownership rules yaml: %w", err)
	}
	return rules.Rules, nil
}

// loadValidationRulesFromPath loads validation rules from an absolute path
func loadValidationRulesFromPath(path string) ([]config.ValidationRule, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read validation rules file at %s: %w", path, err)
	}

	var configStruct struct {
		Rules []config.ValidationRule `yaml:"validationRules"`
	}
	if err := yaml.Unmarshal(bytes, &configStruct); err != nil {
		return nil, fmt.Errorf("could not parse validation rules yaml: %w", err)
	}
	return configStruct.Rules, nil
}

// atoi converts string to int (helper function for tests)
func atoi(s string) int {
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}