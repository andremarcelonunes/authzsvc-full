package domain

import (
	"fmt"
	"regexp"
	"strings"
)

// Password policy violation codes. They are the codes the registration validator has always
// returned (PASSWORD_*), so the 400 response shape (error / code / field) does not change.
const (
	PasswordViolationTooShort         = "PASSWORD_TOO_SHORT"
	PasswordViolationTooLong          = "PASSWORD_TOO_LONG"
	PasswordViolationMissingUppercase = "PASSWORD_MISSING_UPPERCASE"
	PasswordViolationMissingLowercase = "PASSWORD_MISSING_LOWERCASE"
	PasswordViolationMissingNumber    = "PASSWORD_MISSING_NUMBER"
	PasswordViolationMissingSpecial   = "PASSWORD_MISSING_SPECIAL"
	PasswordViolationForbidden        = "PASSWORD_FORBIDDEN"
	PasswordViolationRepeatingChars   = "PASSWORD_REPEATING_CHARS"
	PasswordViolationContainsEmail    = "PASSWORD_CONTAINS_EMAIL"
)

const (
	// DefaultPasswordMinLength is the minimum length every flow enforces today (registration and
	// password change/reset); PASSWORD_MIN_LENGTH overrides it.
	DefaultPasswordMinLength = 8
	// DefaultPasswordMaxLength is the maximum length registration enforces today.
	DefaultPasswordMaxLength = 128
	// defaultPasswordMaxRepeating is the longest run of the same character allowed.
	defaultPasswordMaxRepeating = 3
)

// DefaultForbiddenPasswords is the union of the common-password lists that registration and
// password change/reset used separately before the policy was unified.
func DefaultForbiddenPasswords() []string {
	return []string{"password", "123456", "admin", "user", "test"}
}

// PasswordViolation is one rule a password does not satisfy. Expected carries the limit for the
// length rules (0 otherwise).
type PasswordViolation struct {
	Code     string
	Message  string
	Expected int
}

// PasswordPolicy is the single rule set applied wherever a password is set (registration, admin
// creation, password change, password reset). It is a pure value: no I/O, no framework.
// The zero value of a boolean/limit means "rule off" (MaxLength 0 means no maximum).
//
// Lengths are counted in bytes, as they always were.
type PasswordPolicy struct {
	MinLength           int
	MaxLength           int
	RequireUppercase    bool
	RequireLowercase    bool
	RequireNumbers      bool
	RequireSpecialChars bool
	ForbiddenPasswords  []string
	MaxRepeatingChars   int
	// CheckPersonalInfo rejects a password that contains the local part of the user's e-mail.
	CheckPersonalInfo bool
}

// NewPasswordPolicy builds the policy from the two configuration switches.
//
// requireComplexity=true (the default of the service) turns on every composition rule that
// exists today: upper case, lower case and number required, common passwords refused, no run of
// more than 3 identical characters, no e-mail local part inside the password.
// requireComplexity=false turns all composition rules off: only the minimum length and the
// maximum length (128) remain.
func NewPasswordPolicy(minLength int, requireComplexity bool) PasswordPolicy {
	p := PasswordPolicy{MinLength: minLength, MaxLength: DefaultPasswordMaxLength}
	if requireComplexity {
		p.RequireUppercase = true
		p.RequireLowercase = true
		p.RequireNumbers = true
		p.ForbiddenPasswords = DefaultForbiddenPasswords()
		p.MaxRepeatingChars = defaultPasswordMaxRepeating
		p.CheckPersonalInfo = true
	}
	return p
}

// StrictPasswordPolicy is the default policy: minimum length 8 with all composition rules.
func StrictPasswordPolicy() PasswordPolicy {
	return NewPasswordPolicy(DefaultPasswordMinLength, true)
}

var (
	upperPattern   = regexp.MustCompile(`[A-Z]`)
	lowerPattern   = regexp.MustCompile(`[a-z]`)
	numberPattern  = regexp.MustCompile(`[0-9]`)
	specialPattern = regexp.MustCompile(`[^a-zA-Z0-9]`)
)

// Check returns every rule the password violates, in a stable order (length, maximum, upper,
// lower, number, special, common list, repetition, e-mail). email may be empty. An empty result
// means the password is acceptable.
func (p PasswordPolicy) Check(password, email string) []PasswordViolation {
	var out []PasswordViolation
	add := func(code, message string, expected int) {
		out = append(out, PasswordViolation{Code: code, Message: message, Expected: expected})
	}

	if len(password) < p.MinLength {
		add(PasswordViolationTooShort, fmt.Sprintf("Password must be at least %d characters long", p.MinLength), p.MinLength)
	}
	if p.MaxLength > 0 && len(password) > p.MaxLength {
		add(PasswordViolationTooLong, fmt.Sprintf("Password must be at most %d characters long", p.MaxLength), p.MaxLength)
	}
	if p.RequireUppercase && !upperPattern.MatchString(password) {
		add(PasswordViolationMissingUppercase, "Password must contain at least one uppercase letter", 0)
	}
	if p.RequireLowercase && !lowerPattern.MatchString(password) {
		add(PasswordViolationMissingLowercase, "Password must contain at least one lowercase letter", 0)
	}
	if p.RequireNumbers && !numberPattern.MatchString(password) {
		add(PasswordViolationMissingNumber, "Password must contain at least one number", 0)
	}
	if p.RequireSpecialChars && !specialPattern.MatchString(password) {
		add(PasswordViolationMissingSpecial, "Password must contain at least one special character", 0)
	}

	lower := strings.ToLower(password)
	for _, forbidden := range p.ForbiddenPasswords {
		if lower == strings.ToLower(forbidden) {
			add(PasswordViolationForbidden, "Password is too common and not allowed", 0)
			break
		}
	}

	if p.MaxRepeatingChars > 0 && hasRepeatingRun(password, p.MaxRepeatingChars) {
		add(PasswordViolationRepeatingChars, fmt.Sprintf("Password cannot have more than %d repeating characters", p.MaxRepeatingChars), p.MaxRepeatingChars)
	}

	if p.CheckPersonalInfo && email != "" {
		local := strings.ToLower(strings.Split(email, "@")[0])
		if local != "" && strings.Contains(lower, local) {
			add(PasswordViolationContainsEmail, "Password cannot contain your email address", 0)
		}
	}

	return out
}

// hasRepeatingRun reports whether the same byte appears more than max times in a row.
func hasRepeatingRun(password string, max int) bool {
	if len(password) <= max {
		return false
	}
	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count > max {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}
