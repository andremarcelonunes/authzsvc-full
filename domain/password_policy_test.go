package domain

import (
	"reflect"
	"strings"
	"testing"
)

func violationCodes(vs []PasswordViolation) []string {
	var codes []string
	for _, v := range vs {
		codes = append(codes, v.Code)
	}
	return codes
}

func TestPasswordPolicy_Check(t *testing.T) {
	strict := NewPasswordPolicy(8, true)
	relaxed6 := NewPasswordPolicy(6, false)
	long := strings.Repeat("aB1", 50) // 150 bytes

	cases := []struct {
		name     string
		policy   PasswordPolicy
		password string
		email    string
		want     []string
	}{
		// complexity on: every composition rule that exists today
		{"strict ok", strict, "Abcdef12", "", nil},
		{"strict too short", strict, "Abc1", "", []string{PasswordViolationTooShort}},
		{"strict missing uppercase", strict, "abcdef12", "", []string{PasswordViolationMissingUppercase}},
		{"strict missing lowercase", strict, "ABCDEF12", "", []string{PasswordViolationMissingLowercase}},
		{"strict missing number", strict, "Abcdefgh", "", []string{PasswordViolationMissingNumber}},
		{"strict does not require a special character", strict, "Abcdef12", "", nil},
		{"strict repeating run of 4", strict, "Abcdddd1", "", []string{PasswordViolationRepeatingChars}},
		{"strict repeating run of 3 is fine", strict, "Abcddd12", "", nil},
		{"strict too long", strict, long, "", []string{PasswordViolationTooLong}},
		{"strict contains e-mail local part", strict, "Maria1234", "maria@example.com", []string{PasswordViolationContainsEmail}},
		{"strict e-mail local part is case-insensitive", strict, "xMARIAx12a", "Maria@example.com", []string{PasswordViolationContainsEmail}},
		{"strict without e-mail skips the personal-info rule", strict, "Maria1234", "", nil},
		{"strict several violations keep a stable order", strict, "abc", "", []string{PasswordViolationTooShort, PasswordViolationMissingUppercase, PasswordViolationMissingNumber}},
		{"strict common password with the right shape is still refused", NewPasswordPolicy(4, true), "admin", "", []string{PasswordViolationMissingUppercase, PasswordViolationMissingNumber, PasswordViolationForbidden}},
		{"strict forbidden list is case-insensitive", PasswordPolicy{MinLength: 4, ForbiddenPasswords: DefaultForbiddenPasswords()}, "PassWord", "", []string{PasswordViolationForbidden}},
		{"strict forbidden is exact match, not substring", strict, "Password12", "", nil},

		// complexity off: only the minimum and the maximum length remain
		{"relaxed 6 lowercase chars accepted", relaxed6, "abcdef", "", nil},
		{"relaxed all-same chars accepted", relaxed6, "aaaaaa", "", nil},
		{"relaxed common password accepted", relaxed6, "123456", "", nil},
		{"relaxed e-mail local part accepted", relaxed6, "mariaxx", "maria@example.com", nil},
		{"relaxed 5 chars refused", relaxed6, "abcde", "", []string{PasswordViolationTooShort}},
		{"relaxed empty refused", relaxed6, "", "", []string{PasswordViolationTooShort}},
		{"relaxed still has a maximum", relaxed6, long, "", []string{PasswordViolationTooLong}},
		{"relaxed exactly the maximum accepted", relaxed6, strings.Repeat("a", DefaultPasswordMaxLength), "", nil},
		{"relaxed one over the maximum refused", relaxed6, strings.Repeat("a", DefaultPasswordMaxLength+1), "", []string{PasswordViolationTooLong}},

		// the minimum length is configurable independently of complexity
		{"min length 12 refuses 11", NewPasswordPolicy(12, false), strings.Repeat("a", 11), "", []string{PasswordViolationTooShort}},
		{"min length 12 accepts 12", NewPasswordPolicy(12, false), strings.Repeat("a", 12), "", nil},

		// explicit rules (legacy callers build the struct by hand)
		{"special char required when asked", PasswordPolicy{MinLength: 4, RequireSpecialChars: true}, "abcd", "", []string{PasswordViolationMissingSpecial}},
		{"special char satisfied", PasswordPolicy{MinLength: 4, RequireSpecialChars: true}, "abc!", "", nil},
		{"zero MaxLength means no maximum", PasswordPolicy{MinLength: 1}, long + long, "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := violationCodes(tc.policy.Check(tc.password, tc.email))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Check(%q, %q) = %v, want %v", tc.password, tc.email, got, tc.want)
			}
		})
	}
}

func TestPasswordPolicy_ViolationCarriesExpectedLimit(t *testing.T) {
	vs := NewPasswordPolicy(10, false).Check("abc", "")
	if len(vs) != 1 || vs[0].Expected != 10 || vs[0].Message == "" {
		t.Fatalf("expected one too-short violation carrying the limit, got %+v", vs)
	}
	for _, v := range NewPasswordPolicy(6, true).Check("secretvalue", "") {
		if strings.Contains(v.Message, "secretvalue") {
			t.Errorf("violation message echoes the password: %q", v.Message)
		}
	}
}

func TestStrictPasswordPolicy_IsTheDefault(t *testing.T) {
	p := StrictPasswordPolicy()
	if p.MinLength != 8 || p.MaxLength != 128 || !p.RequireUppercase || !p.RequireLowercase || !p.RequireNumbers {
		t.Errorf("strict default drifted: %+v", p)
	}
	if p.RequireSpecialChars {
		t.Error("today no flow requires a special character in production wiring")
	}
	if len(p.ForbiddenPasswords) != 5 || p.MaxRepeatingChars != 3 || !p.CheckPersonalInfo {
		t.Errorf("strict default drifted: %+v", p)
	}
}
