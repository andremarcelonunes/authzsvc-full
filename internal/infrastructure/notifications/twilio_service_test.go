package notifications

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestMockSMS_DoesNotPrintTheMessageByDefault(t *testing.T) {
	svc := NewTwilioService("", "", "")
	out := captureStdout(t, func() {
		if err := svc.SendSMS("+5511999990000", "Your verification code is: 123456."); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(out, "123456") || strings.Contains(out, "+5511999990000") {
		t.Errorf("the mock path leaked the code or the full phone: %q", out)
	}
}
