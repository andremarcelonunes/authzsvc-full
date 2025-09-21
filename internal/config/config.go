package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type OwnershipRule struct {
	Method    string `yaml:"method"`
	Path      string `yaml:"path"`
	Source    string `yaml:"source"`
	ParamName string `yaml:"paramName"`
}

type AppConfig struct {
	Port    int    `yaml:"port"`
	GinMode string `yaml:"gin_mode"`
}

type DatabaseConfig struct {
	DSN string `yaml:"dsn"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type JWTConfig struct {
	Secret     string `yaml:"secret"`
	Issuer     string `yaml:"issuer"`
	AccessTTL  string `yaml:"access_ttl"`
	RefreshTTL string `yaml:"refresh_ttl"`
}

type OTPConfig struct {
	TTL          string `yaml:"ttl"`
	Length       int    `yaml:"length"`
	MaxAttempts  int    `yaml:"max_attempts"`
	ResendWindow string `yaml:"resend_window"`
}

type TwilioConfig struct {
	AccountSID string `yaml:"account_sid"`
	AuthToken  string `yaml:"auth_token"`
	FromNumber string `yaml:"from_number"`
}

type CasbinConfig struct {
	ModelPath string `yaml:"model_path"`
}

// ValidationConfig holds configuration for the CB-182 validation system
type ValidationConfig struct {
	EnableSecurityValidation bool          `yaml:"enable_security_validation"`
	EnableBusinessValidation bool          `yaml:"enable_business_validation"`
	EnableRateLimiting      bool          `yaml:"enable_rate_limiting"`
	EnableValidationCaching bool          `yaml:"enable_validation_caching"`
	MaxRequestSize          int64         `yaml:"max_request_size"`
	ValidationTimeout       time.Duration `yaml:"validation_timeout"`
	CacheTimeout           time.Duration `yaml:"cache_timeout"`
	MaxValidationTime      time.Duration `yaml:"max_validation_time"`
	SkipValidationPaths    []string      `yaml:"skip_validation_paths"`
	LogValidationEvents    bool          `yaml:"log_validation_events"`
	EnableMetrics          bool          `yaml:"enable_metrics"`
	ShadowMode             bool          `yaml:"shadow_mode"` // Log violations but don't block
	EnableGracefulMode     bool          `yaml:"enable_graceful_mode"` // Continue if validation fails
}

type ConfigFile struct {
	App        AppConfig        `yaml:"app"`
	Database   DatabaseConfig   `yaml:"database"`
	Redis      RedisConfig      `yaml:"redis"`
	JWT        JWTConfig        `yaml:"jwt"`
	OTP        OTPConfig        `yaml:"otp"`
	Twilio     TwilioConfig     `yaml:"twilio"`
	Casbin     CasbinConfig     `yaml:"casbin"`
	Validation ValidationConfig `yaml:"validation"`
}

type Config struct {
	Port             string
	DSN              string
	RedisAddr        string
	RedisPassword    string
	RedisDB          int
	JWTSecret        string
	JWTIssuer        string
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
	OTP_TTL          time.Duration
	OTP_Length       int
	OTP_MaxAttempts  int
	OTP_ResendWindow time.Duration
	TwilioSID        string
	TwilioToken      string
	TwilioFrom       string
	CasbinModelPath  string
	OwnershipRules   []OwnershipRule
	ValidationRules  []ValidationRule // New field for enhanced validation rules
	UseSimpleCasbin  bool             // Feature flag for SimpleCasbinMW
	
	// CB-182: Validation system configuration
	ValidationConfig ValidationConfig
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func Load() (*Config, error) {
	// Try to load from config file first, then fallback to environment variables
	configFile, err := loadConfigFile("config/config.yml")
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	// Parse duration strings
	accTTL, err := time.ParseDuration(configFile.JWT.AccessTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT access TTL: %w", err)
	}

	refTTL, err := time.ParseDuration(configFile.JWT.RefreshTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid JWT refresh TTL: %w", err)
	}

	otpTTL, err := time.ParseDuration(configFile.OTP.TTL)
	if err != nil {
		return nil, fmt.Errorf("invalid OTP TTL: %w", err)
	}

	resWnd, err := time.ParseDuration(configFile.OTP.ResendWindow)
	if err != nil {
		return nil, fmt.Errorf("invalid OTP resend window: %w", err)
	}

	// Load legacy ownership rules
	ownershipRules, err := loadOwnershipRules("config/ownership_rules.yml")
	if err != nil {
		return nil, err
	}

	// Load new validation rules
	validationRules, err := loadValidationRules("config/validation_rules.yml")
	if err != nil {
		// If validation rules file doesn't exist, that's okay for backward compatibility
		validationRules = []ValidationRule{}
	}

	// Set up validation configuration with defaults for CB-182
	validationConfig := setupValidationConfig(configFile.Validation)

	return &Config{
		Port:             fmt.Sprintf("%d", configFile.App.Port),
		DSN:              configFile.Database.DSN,
		RedisAddr:        configFile.Redis.Addr,
		RedisPassword:    configFile.Redis.Password,
		RedisDB:          configFile.Redis.DB,
		JWTSecret:        configFile.JWT.Secret,
		JWTIssuer:        configFile.JWT.Issuer,
		AccessTTL:        accTTL,
		RefreshTTL:       refTTL,
		OTP_TTL:          otpTTL,
		OTP_Length:       configFile.OTP.Length,
		OTP_MaxAttempts:  configFile.OTP.MaxAttempts,
		OTP_ResendWindow: resWnd,
		TwilioSID:        configFile.Twilio.AccountSID,
		TwilioToken:      configFile.Twilio.AuthToken,
		TwilioFrom:       configFile.Twilio.FromNumber,
		CasbinModelPath:  configFile.Casbin.ModelPath,
		OwnershipRules:   ownershipRules,
		ValidationRules:  validationRules,
		UseSimpleCasbin:  env("USE_SIMPLE_CASBIN", "false") == "true",
		ValidationConfig: validationConfig,
	}, nil
}

func loadConfigFile(path string) (*ConfigFile, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read config file at %s: %w", path, err)
	}

	var config ConfigFile
	if err := yaml.Unmarshal(bytes, &config); err != nil {
		return nil, fmt.Errorf("could not parse config yaml: %w", err)
	}

	return &config, nil
}

func loadOwnershipRules(path string) ([]OwnershipRule, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read ownership rules file: %w", err)
	}

	var rules struct {
		Rules []OwnershipRule `yaml:"ownershipRules"`
	}
	if err := yaml.Unmarshal(bytes, &rules); err != nil {
		return nil, fmt.Errorf("could not parse ownership rules yaml: %w", err)
	}
	return rules.Rules, nil
}

func loadValidationRules(path string) ([]ValidationRule, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read validation rules file: %w", err)
	}

	var config struct {
		Rules []ValidationRule `yaml:"validationRules"`
	}
	if err := yaml.Unmarshal(bytes, &config); err != nil {
		return nil, fmt.Errorf("could not parse validation rules yaml: %w", err)
	}
	return config.Rules, nil
}

func atoi(s string) int {
	var i int
	fmt.Sscanf(s, "%d", &i)
	return i
}

// setupValidationConfig sets up validation configuration with sensible defaults for CB-182
func setupValidationConfig(configFromFile ValidationConfig) ValidationConfig {
	// Start with provided configuration
	config := configFromFile
	
	// Set defaults for CB-182 safe rollout (shadow mode initially)
	if config.ValidationTimeout == 0 {
		config.ValidationTimeout = 5 * time.Second
	}
	if config.CacheTimeout == 0 {
		config.CacheTimeout = 5 * time.Minute
	}
	if config.MaxValidationTime == 0 {
		config.MaxValidationTime = 10 * time.Second
	}
	if config.MaxRequestSize == 0 {
		config.MaxRequestSize = 1024 * 1024 // 1MB
	}
	if len(config.SkipValidationPaths) == 0 {
		config.SkipValidationPaths = []string{"/health", "/metrics", "/docs", "/external/health"}
	}
	
	// CB-182: Safe rollout configuration - start in shadow mode
	// Override with environment variables for deployment control
	if env("VALIDATION_ENABLE_SECURITY", "") != "" {
		config.EnableSecurityValidation = env("VALIDATION_ENABLE_SECURITY", "false") == "true"
	} else if !configFromFile.EnableSecurityValidation {
		config.EnableSecurityValidation = true // Enable by default for CB-182
	}
	
	if env("VALIDATION_ENABLE_BUSINESS", "") != "" {
		config.EnableBusinessValidation = env("VALIDATION_ENABLE_BUSINESS", "false") == "true"
	} else if !configFromFile.EnableBusinessValidation {
		config.EnableBusinessValidation = true // Enable by default for CB-182
	}
	
	if env("VALIDATION_ENABLE_RATE_LIMITING", "") != "" {
		config.EnableRateLimiting = env("VALIDATION_ENABLE_RATE_LIMITING", "false") == "true"
	} else if !configFromFile.EnableRateLimiting {
		config.EnableRateLimiting = true // Enable by default for CB-182
	}
	
	if env("VALIDATION_SHADOW_MODE", "") != "" {
		config.ShadowMode = env("VALIDATION_SHADOW_MODE", "true") == "true"
	} else if !configFromFile.ShadowMode {
		config.ShadowMode = true // START IN SHADOW MODE for safe rollout
	}
	
	if env("VALIDATION_GRACEFUL_MODE", "") != "" {
		config.EnableGracefulMode = env("VALIDATION_GRACEFUL_MODE", "true") == "true"
	} else if !configFromFile.EnableGracefulMode {
		config.EnableGracefulMode = true // Enable graceful degradation
	}
	
	// Always enable logging and metrics for CB-182 monitoring
	config.LogValidationEvents = true
	config.EnableMetrics = true
	config.EnableValidationCaching = true
	
	return config
}