package notifications

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	fn()
	return buf.String()
}

func TestMockSMS_DoesNotLogTheMessageByDefault(t *testing.T) {
	svc := NewTwilioService("", "", "")
	out := captureLog(t, func() {
		if err := svc.SendSMS("+5511999990000", "Your verification code is: 123456."); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "123456") || strings.Contains(out, "+5511999990000") {
		t.Errorf("the mock path leaked the code or the full phone: %q", out)
	}
	if !strings.Contains(out, "+55") || !strings.Contains(out, "00") || !strings.Contains(out, "*") {
		t.Errorf("the log must say a message was generated for a masked phone: %q", out)
	}
}

func TestMockSMS_LogsTheMessageWhenSwitchedOn(t *testing.T) {
	svc := NewTwilioService("", "", "", WithLogMessages(true))
	out := captureLog(t, func() { _ = svc.SendSMS("+5511999990000", "Your verification code is: 123456.") })
	if !strings.Contains(out, "123456") {
		t.Errorf("with OTP_LOG_CODES on the mock path prints the message: %q", out)
	}
}

func TestMaskPhone(t *testing.T) {
	for in, want := range map[string]string{"+5511999990000": "+55*********00", "123": "***", "": ""} {
		if got := maskPhone(in); got != want {
			t.Errorf("maskPhone(%q) = %q, want %q", in, got, want)
		}
	}
}
