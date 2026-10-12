package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/you/authzsvc/domain"
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
	// LogCodes: the no-SMS-provider mock path prints the message with the code (OTP_LOG_CODES). Default false.
	LogCodes *bool `yaml:"log_codes"`
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

// BootstrapAccount holds the credentials of an account created at startup.
type BootstrapAccount struct {
	Email    string `yaml:"email"`
	Phone    string `yaml:"phone"`
	Password string `yaml:"password"`
}

// BootstrapConfig is the optional "bootstrap" section: the root administrator and an optional
// dedicated service administrator (role admin) created idempotently at startup.
type BootstrapConfig struct {
	RootAdmin    BootstrapAccount `yaml:"root_admin"`
	ServiceAdmin BootstrapAccount `yaml:"service_admin"`
}

// IdentityBackendFileConfig is the optional "identity_backend" section: the backend's internal
// API that translates an AuthzSvc user id into the backend user id (token.backend_user_id).
type IdentityBackendFileConfig struct {
	URL     string `yaml:"url"`
	APIKey  string `yaml:"api_key"`
	Timeout string `yaml:"timeout"`
}

// IdentityBackendConfig is the resolved identity backend configuration. An empty URL means
// the resolver is not configured.
type IdentityBackendConfig struct {
	URL     string
	APIKey  string
	Timeout time.Duration
}

// DefaultIdentityBackendTimeout is used when no timeout is configured.
const DefaultIdentityBackendTimeout = 2 * time.Second

// RegistrationFileConfig is the optional "registration" section. Both keys are optional;
// an absent key keeps the strict default (true).
type RegistrationFileConfig struct {
	RequireEmail             *bool  `yaml:"require_email"`
	RequirePhoneVerification *bool  `yaml:"require_phone_verification"`
	RateLimitPerIP           *int   `yaml:"rate_limit_per_ip"`
	RateLimitWindow          string `yaml:"rate_limit_window"`
}

// RegistrationConfig holds the two switches that relax the sign-up / login rules for
// phone-first clients. Both default to true (strict behaviour).
type RegistrationConfig struct {
	// RequireEmail: when false, e-mail is optional at registration (REQUIRE_REGISTRATION_EMAIL).
	RequireEmail bool
	// RequirePhoneVerification: when false, unverified users may log in and registration sends
	// no OTP (REQUIRE_PHONE_VERIFICATION).
	RequirePhoneVerification bool
	// RateLimitPerIP and RateLimitWindow: public registrations allowed per client IP in each
	// window (REGISTRATION_RATE_LIMIT_PER_IP, REGISTRATION_RATE_LIMIT_WINDOW). Defaults 2 per 30s.
	// Privileged creation (POST /admin/users) is exempt.
	RateLimitPerIP  int
	RateLimitWindow time.Duration
}

// PasswordFileConfig is the optional "password" section; every key is optional.
type PasswordFileConfig struct {
	RequireComplexity *bool `yaml:"require_complexity"`
	MinLength         *int  `yaml:"min_length"`
	ResetRequireEmail *bool `yaml:"reset_require_email"`
}

// PasswordConfig holds the password switches. The defaults are today's strict behaviour.
type PasswordConfig struct {
	// RequireComplexity: when false the composition rules are off and only the length rules
	// apply (PASSWORD_REQUIRE_COMPLEXITY). Default true.
	RequireComplexity bool
	// MinLength is the minimum password length (PASSWORD_MIN_LENGTH). Default 8.
	MinLength int
	// ResetRequireEmail: when true (default) the public password reset needs an e-mail and a phone
	// that belong to the same user; when false the phone alone identifies the account
	// (PASSWORD_RESET_REQUIRE_EMAIL).
	ResetRequireEmail bool
}

// SelfDeletionFileConfig is the optional "self_deletion" section; every key is optional.
type SelfDeletionFileConfig struct {
	Immediate       *bool  `yaml:"immediate"`
	MinAccountAge   string `yaml:"min_account_age"`
	RequirePassword *bool  `yaml:"require_password"`
}

// DefaultSelfDeletionMinAccountAge is the minimum account age to request deletion when unset.
const DefaultSelfDeletionMinAccountAge = 24 * time.Hour

// SelfDeletionConfig holds the switches of POST /users/me/deletion. The defaults keep the
// scheduled flow: nothing is processed at once, accounts must be 24h old, no credential is asked.
type SelfDeletionConfig struct {
	// Immediate: when true a self-requested deletion is processed synchronously (SELF_DELETION_IMMEDIATE). Default false.
	Immediate bool
	// MinAccountAge: accounts younger than this cannot request deletion; 0 disables the rule
	// (SELF_DELETION_MIN_ACCOUNT_AGE). Default 24h.
	MinAccountAge time.Duration
	// RequirePassword: when true the request must carry the account password (SELF_DELETION_REQUIRE_PASSWORD). Default false.
	RequirePassword bool
}

// SMSBudgetFileConfig is the optional "sms_budget" section; every key is optional (defaults: domain.DefaultSMSLimits).
type SMSBudgetFileConfig struct {
	MaxPerPhonePerDay    *int   `yaml:"max_per_phone_per_day"`
	MaxPerPhonePer30Days *int   `yaml:"max_per_phone_per_30_days"`
	MinIntervalPerPhone  string `yaml:"min_interval_per_phone"`
	MaxPerIPPerDay       *int   `yaml:"max_per_ip_per_day"`
	GlobalDailyCap       *int   `yaml:"global_daily_cap"`
	GlobalMonthlyCap     *int   `yaml:"global_monthly_cap"`
}

// Bounds accepted for PASSWORD_MIN_LENGTH and the registration rate limit settings.
const (
	MinAllowedPasswordMinLength = 4
	MaxAllowedPasswordMinLength = domain.DefaultPasswordMaxLength
	MaxRegistrationRateLimit    = 100000
	MinRegistrationRateWindow   = time.Second
	MaxRegistrationRateWindow   = time.Hour
)

type ConfigFile struct {
	App        AppConfig        `yaml:"app"`
	Database   DatabaseConfig   `yaml:"database"`
	Redis      RedisConfig      `yaml:"redis"`
	JWT        JWTConfig        `yaml:"jwt"`
	OTP        OTPConfig        `yaml:"otp"`
	Twilio     TwilioConfig     `yaml:"twilio"`
	Casbin     CasbinConfig     `yaml:"casbin"`
	Validation ValidationConfig `yaml:"validation"`
	Bootstrap  BootstrapConfig  `yaml:"bootstrap"`

	IdentityBackend IdentityBackendFileConfig `yaml:"identity_backend"`
	Registration    RegistrationFileConfig    `yaml:"registration"`
	Password        PasswordFileConfig        `yaml:"password"`
	SelfDeletion    SelfDeletionFileConfig    `yaml:"self_deletion"`
	SMSBudget       SMSBudgetFileConfig       `yaml:"sms_budget"`
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

	// Bootstrap accounts (root / service admin) created at startup; environment overrides config file
	Bootstrap BootstrapConfig

	// IdentityBackend configures the backend id translation API; environment overrides config file
	IdentityBackend IdentityBackendConfig

	// Registration switches (REQUIRE_REGISTRATION_EMAIL, REQUIRE_PHONE_VERIFICATION); environment overrides config file
	Registration RegistrationConfig

	// Password switches (PASSWORD_REQUIRE_COMPLEXITY, PASSWORD_MIN_LENGTH, PASSWORD_RESET_REQUIRE_EMAIL); environment overrides config file
	Password PasswordConfig

	// Self-deletion switches (SELF_DELETION_IMMEDIATE, SELF_DELETION_MIN_ACCOUNT_AGE, SELF_DELETION_REQUIRE_PASSWORD); environment overrides config file
	SelfDeletion SelfDeletionConfig

	// OTPLogCodes (OTP_LOG_CODES, default false): let the mock SMS path (no provider configured) log the code. Never in production.
	OTPLogCodes bool

	// SMSBudget bounds the SMS sent (SMS_* variables, "sms_budget" section); strict defaults.
	SMSBudget domain.SMSLimits
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

	identityBackend, err := loadIdentityBackendConfig(configFile.IdentityBackend)
	if err != nil {
		return nil, err
	}

	registration, err := loadRegistrationConfig(configFile.Registration)
	if err != nil {
		return nil, err
	}

	password, err := loadPasswordConfig(configFile.Password)
	if err != nil {
		return nil, err
	}

	selfDeletion, err := loadSelfDeletionConfig(configFile.SelfDeletion)
	if err != nil {
		return nil, err
	}

	otpLogCodes, err := resolveBoolSwitchDefaultFalse("OTP_LOG_CODES", configFile.OTP.LogCodes)
	if err != nil {
		return nil, err
	}

	smsBudget, err := loadSMSBudgetConfig(configFile.SMSBudget)
	if err != nil {
		return nil, err
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
		ValidationConfig: validationConfig,
		Bootstrap:        loadBootstrapConfig(configFile.Bootstrap),
		IdentityBackend:  identityBackend,
		Registration:     registration,
		Password:         password,
		SelfDeletion:     selfDeletion,
		OTPLogCodes:      otpLogCodes,
		SMSBudget:        smsBudget,
	}, nil
}

// loadBootstrapConfig applies the ROOT_ADMIN_* and SERVICE_ADMIN_* environment variables
// over the values read from the optional bootstrap section of the config file.
func loadBootstrapConfig(fromFile BootstrapConfig) BootstrapConfig {
	return BootstrapConfig{
		RootAdmin: BootstrapAccount{
			Email:    env("ROOT_ADMIN_EMAIL", fromFile.RootAdmin.Email),
			Phone:    env("ROOT_ADMIN_PHONE", fromFile.RootAdmin.Phone),
			Password: env("ROOT_ADMIN_PASSWORD", fromFile.RootAdmin.Password),
		},
		ServiceAdmin: BootstrapAccount{
			Email:    env("SERVICE_ADMIN_EMAIL", fromFile.ServiceAdmin.Email),
			Phone:    env("SERVICE_ADMIN_PHONE", fromFile.ServiceAdmin.Phone),
			Password: env("SERVICE_ADMIN_PASSWORD", fromFile.ServiceAdmin.Password),
		},
	}
}

// loadIdentityBackendConfig applies the IDENTITY_BACKEND_URL, IDENTITY_BACKEND_API_KEY and
// IDENTITY_BACKEND_TIMEOUT environment variables over the optional identity_backend section.
func loadIdentityBackendConfig(fromFile IdentityBackendFileConfig) (IdentityBackendConfig, error) {
	cfg := IdentityBackendConfig{
		URL:     env("IDENTITY_BACKEND_URL", fromFile.URL),
		APIKey:  env("IDENTITY_BACKEND_API_KEY", fromFile.APIKey),
		Timeout: DefaultIdentityBackendTimeout,
	}
	if raw := env("IDENTITY_BACKEND_TIMEOUT", fromFile.Timeout); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return IdentityBackendConfig{}, fmt.Errorf("invalid identity backend timeout %q", raw)
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

// loadRegistrationConfig applies the REQUIRE_REGISTRATION_EMAIL and REQUIRE_PHONE_VERIFICATION
// environment variables over the optional registration section. Each switch defaults to true.
func loadRegistrationConfig(fromFile RegistrationFileConfig) (RegistrationConfig, error) {
	requireEmail, err := resolveBoolSwitch("REQUIRE_REGISTRATION_EMAIL", fromFile.RequireEmail)
	if err != nil {
		return RegistrationConfig{}, err
	}
	requirePhone, err := resolveBoolSwitch("REQUIRE_PHONE_VERIFICATION", fromFile.RequirePhoneVerification)
	if err != nil {
		return RegistrationConfig{}, err
	}
	limit, window, err := resolveRegistrationRateLimit(fromFile)
	if err != nil {
		return RegistrationConfig{}, err
	}
	return RegistrationConfig{
		RequireEmail:             requireEmail,
		RequirePhoneVerification: requirePhone,
		RateLimitPerIP:           limit,
		RateLimitWindow:          window,
	}, nil
}

// resolveRegistrationRateLimit applies REGISTRATION_RATE_LIMIT_PER_IP and
// REGISTRATION_RATE_LIMIT_WINDOW over the optional registration section; the defaults are
// 2 registrations per 30 seconds per IP. Out-of-range or unparsable values are errors.
func resolveRegistrationRateLimit(fromFile RegistrationFileConfig) (int, time.Duration, error) {
	limit := domain.DefaultRegistrationRateLimitPerIP
	if fromFile.RateLimitPerIP != nil {
		limit = *fromFile.RateLimitPerIP
	}
	if raw := os.Getenv("REGISTRATION_RATE_LIMIT_PER_IP"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid value for REGISTRATION_RATE_LIMIT_PER_IP: expected an integer")
		}
		limit = v
	}
	if limit < 1 || limit > MaxRegistrationRateLimit {
		return 0, 0, fmt.Errorf("invalid registration rate limit per IP %d: must be between 1 and %d", limit, MaxRegistrationRateLimit)
	}

	window := domain.DefaultRegistrationRateWindow
	if raw := env("REGISTRATION_RATE_LIMIT_WINDOW", fromFile.RateLimitWindow); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid registration rate limit window %q: expected a duration such as 30s", raw)
		}
		window = d
	}
	if window < MinRegistrationRateWindow || window > MaxRegistrationRateWindow {
		return 0, 0, fmt.Errorf("invalid registration rate limit window %s: must be between %s and %s", window, MinRegistrationRateWindow, MaxRegistrationRateWindow)
	}
	return limit, window, nil
}

// loadPasswordConfig applies PASSWORD_REQUIRE_COMPLEXITY, PASSWORD_MIN_LENGTH and
// PASSWORD_RESET_REQUIRE_EMAIL over the optional password section. Defaults: true, 8, true.
func loadPasswordConfig(fromFile PasswordFileConfig) (PasswordConfig, error) {
	complexity, err := resolveBoolSwitch("PASSWORD_REQUIRE_COMPLEXITY", fromFile.RequireComplexity)
	if err != nil {
		return PasswordConfig{}, err
	}
	resetEmail, err := resolveBoolSwitch("PASSWORD_RESET_REQUIRE_EMAIL", fromFile.ResetRequireEmail)
	if err != nil {
		return PasswordConfig{}, err
	}
	minLength := domain.DefaultPasswordMinLength
	if fromFile.MinLength != nil {
		minLength = *fromFile.MinLength
	}
	if raw := os.Getenv("PASSWORD_MIN_LENGTH"); raw != "" {
		v, err := strconv.Atoi(raw)
		if err != nil {
			return PasswordConfig{}, fmt.Errorf("invalid value for PASSWORD_MIN_LENGTH: expected an integer")
		}
		minLength = v
	}
	if minLength < MinAllowedPasswordMinLength || minLength > MaxAllowedPasswordMinLength {
		return PasswordConfig{}, fmt.Errorf("invalid password minimum length %d: must be between %d and %d", minLength, MinAllowedPasswordMinLength, MaxAllowedPasswordMinLength)
	}
	return PasswordConfig{RequireComplexity: complexity, MinLength: minLength, ResetRequireEmail: resetEmail}, nil
}

// loadSelfDeletionConfig applies SELF_DELETION_IMMEDIATE, SELF_DELETION_MIN_ACCOUNT_AGE and
// SELF_DELETION_REQUIRE_PASSWORD over the optional self_deletion section. Defaults: false, 24h, false.
func loadSelfDeletionConfig(fromFile SelfDeletionFileConfig) (SelfDeletionConfig, error) {
	immediate, err := resolveBoolSwitchDefaultFalse("SELF_DELETION_IMMEDIATE", fromFile.Immediate)
	if err != nil {
		return SelfDeletionConfig{}, err
	}
	requirePassword, err := resolveBoolSwitchDefaultFalse("SELF_DELETION_REQUIRE_PASSWORD", fromFile.RequirePassword)
	if err != nil {
		return SelfDeletionConfig{}, err
	}
	minAge := DefaultSelfDeletionMinAccountAge
	if raw := env("SELF_DELETION_MIN_ACCOUNT_AGE", fromFile.MinAccountAge); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return SelfDeletionConfig{}, fmt.Errorf("invalid self deletion minimum account age %q: expected a duration such as 24h or 0", raw)
		}
		if d < 0 {
			return SelfDeletionConfig{}, fmt.Errorf("invalid self deletion minimum account age %s: must not be negative", d)
		}
		minAge = d
	}
	return SelfDeletionConfig{Immediate: immediate, MinAccountAge: minAge, RequirePassword: requirePassword}, nil
}

// loadSMSBudgetConfig applies the SMS_* environment variables over the optional sms_budget section
// over domain.DefaultSMSLimits. Caps must be at least 1 (a zero cap would silently disable SMS);
// the minimum interval may be 0.
func loadSMSBudgetConfig(f SMSBudgetFileConfig) (domain.SMSLimits, error) {
	limits := domain.DefaultSMSLimits()
	ints := []struct {
		env  string
		file *int
		dst  *int
	}{
		{"SMS_MAX_PER_PHONE_PER_DAY", f.MaxPerPhonePerDay, &limits.MaxPerPhonePerDay},
		{"SMS_MAX_PER_PHONE_PER_30_DAYS", f.MaxPerPhonePer30Days, &limits.MaxPerPhonePer30Days},
		{"SMS_MAX_PER_IP_PER_DAY", f.MaxPerIPPerDay, &limits.MaxPerIPPerDay},
		{"SMS_GLOBAL_DAILY_CAP", f.GlobalDailyCap, &limits.GlobalDailyCap},
		{"SMS_GLOBAL_MONTHLY_CAP", f.GlobalMonthlyCap, &limits.GlobalMonthlyCap},
	}
	for _, in := range ints {
		if in.file != nil {
			*in.dst = *in.file
		}
		if raw := os.Getenv(in.env); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				return limits, fmt.Errorf("invalid value for %s: expected an integer", in.env)
			}
			*in.dst = v
		}
		if *in.dst < 1 {
			return limits, fmt.Errorf("invalid %s %d: must be at least 1", in.env, *in.dst)
		}
	}
	if raw := env("SMS_MIN_INTERVAL_PER_PHONE", f.MinIntervalPerPhone); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < 0 {
			return limits, fmt.Errorf("invalid SMS_MIN_INTERVAL_PER_PHONE %q: expected a non-negative duration such as 2m", raw)
		}
		limits.MinIntervalPerPhone = d
	}
	return limits, nil
}

// resolveBoolSwitchDefaultFalse is resolveBoolSwitch for switches that are off unless enabled.
func resolveBoolSwitchDefaultFalse(name string, fromFile *bool) (bool, error) {
	return resolveBoolSwitchWithDefault(name, fromFile, false)
}

// resolveBoolSwitch returns the environment value of name when set, else the file value, else true.
// An unparsable environment value is an error (a typo must not silently keep or drop a safeguard).
func resolveBoolSwitch(name string, fromFile *bool) (bool, error) {
	return resolveBoolSwitchWithDefault(name, fromFile, true)
}

func resolveBoolSwitchWithDefault(name string, fromFile *bool, def bool) (bool, error) {
	if raw := os.Getenv(name); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			return false, fmt.Errorf("invalid value for %s: expected true or false", name)
		}
		return v, nil
	}
	if fromFile != nil {
		return *fromFile, nil
	}
	return def, nil
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