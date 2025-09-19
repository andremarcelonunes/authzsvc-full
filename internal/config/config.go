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

type ConfigFile struct {
	App     AppConfig      `yaml:"app"`
	Database DatabaseConfig `yaml:"database"`
	Redis   RedisConfig    `yaml:"redis"`
	JWT     JWTConfig      `yaml:"jwt"`
	OTP     OTPConfig      `yaml:"otp"`
	Twilio  TwilioConfig   `yaml:"twilio"`
	Casbin  CasbinConfig   `yaml:"casbin"`
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