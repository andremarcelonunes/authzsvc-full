package domain

import (
	"errors"
	"testing"
)

func TestValidateMobilePhone(t *testing.T) {
	cases := map[string]bool{
		"+5511999990000":  true, // SP mobile
		"+5521987654321":  true,
		"+551133334444":   false, // landline, 10 digits
		"+5511899990000":  false, // 11 digits, third digit 8
		"+55119999900001": false, // 12 digits
		"+5511999990":     false, // 9 digits
		"+55119999900a0":  false, // non digit
		"+15551234567":    true,  // not Brazilian: not checked
		"+351912345678":   true,
	}
	for phone, ok := range cases {
		err := ValidateMobilePhone(phone)
		if ok && err != nil {
			t.Errorf("%s should pass, got %v", phone, err)
		}
		if !ok && !errors.Is(err, ErrPhoneNotMobile) {
			t.Errorf("%s should be refused, got %v", phone, err)
		}
	}
}
