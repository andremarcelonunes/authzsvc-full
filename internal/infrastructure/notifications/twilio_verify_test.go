package notifications

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/you/authzsvc/domain"
)

// verifyFake is an HTTP fake of Twilio Verify: it records requests and answers a canned status/body.
type verifyFake struct {
	status int
	body   string
	paths  []string
	forms  []url.Values
	user   string
	pass   string
}

func newVerifyFake(t *testing.T, status int, body string) (*verifyFake, *TwilioVerify) {
	t.Helper()
	f := &verifyFake{status: status, body: body}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.paths = append(f.paths, r.Method+" "+r.URL.Path)
		f.forms = append(f.forms, r.PostForm)
		f.user, f.pass, _ = r.BasicAuth()
		w.WriteHeader(f.status)
		_, _ = w.Write([]byte(f.body))
	}))
	t.Cleanup(srv.Close)
	return f, NewTwilioVerify("ACtest", "tok", "VAsvc", WithVerifyBaseURL(srv.URL))
}

func TestVerifyStart_SendsToAndChannel(t *testing.T) {
	f, v := newVerifyFake(t, 201, `{"status":"pending"}`)
	if err := v.StartVerification(context.Background(), "+5511999990000"); err != nil {
		t.Fatal(err)
	}
	if f.paths[0] != "POST /v2/Services/VAsvc/Verifications" {
		t.Errorf("path %v", f.paths)
	}
	if f.forms[0].Get("To") != "+5511999990000" || f.forms[0].Get("Channel") != "sms" {
		t.Errorf("form %v", f.forms[0])
	}
	if f.user != "ACtest" || f.pass != "tok" {
		t.Error("basic auth not used")
	}
}

func TestVerifyStart_ErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		check  func(error) bool
	}{
		{"60200 invalid phone", 400, `{"code":60200,"message":"secret text +5511999990000"}`, func(e error) bool { return errors.Is(e, domain.ErrSMSInvalidPhone) }},
		{"60203 rate limited", 429, `{"code":60203,"message":"Max send attempts reached"}`, func(e error) bool {
			var l *domain.SMSLimitError
			return errors.As(e, &l) && l.RetryAfter > 0
		}},
		{"other", 500, `{"code":20500,"message":"boom +5511999990000"}`, func(e error) bool {
			return e != nil && !strings.Contains(e.Error(), "+55") && !strings.Contains(e.Error(), "boom")
		}},
	}
	for _, c := range cases {
		_, v := newVerifyFake(t, c.status, c.body)
		err := v.StartVerification(context.Background(), "+5511999990000")
		if !c.check(err) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

func TestVerifyStart_EmptyPhoneNeverCallsTheNetwork(t *testing.T) {
	f, v := newVerifyFake(t, 201, `{}`)
	err := v.StartVerification(context.Background(), "")
	if !errors.Is(err, domain.ErrSMSNotSent) || len(f.paths) != 0 {
		t.Errorf("err=%v calls=%d", err, len(f.paths))
	}
}

func TestVerifyStart_TransportErrorLeaksNothing(t *testing.T) {
	v := NewTwilioVerify("ACtest", "tok", "VAsvc", WithVerifyBaseURL("http://127.0.0.1:1"))
	err := v.StartVerification(context.Background(), "+5511999990000")
	if err == nil || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "+55") {
		t.Errorf("err=%v", err)
	}
}

func TestVerifyCheck(t *testing.T) {
	f, v := newVerifyFake(t, 200, `{"status":"approved"}`)
	ok, err := v.CheckVerification(context.Background(), "+5511999990000", "123456")
	if err != nil || !ok {
		t.Fatalf("approved: %v %v", ok, err)
	}
	if f.paths[0] != "POST /v2/Services/VAsvc/VerificationCheck" || f.forms[0].Get("To") != "+5511999990000" || f.forms[0].Get("Code") != "123456" {
		t.Errorf("request %v %v", f.paths, f.forms)
	}

	f.status, f.body = 200, `{"status":"pending"}`
	if ok, err := v.CheckVerification(context.Background(), "+5511999990000", "000000"); ok || err != nil {
		t.Errorf("pending: %v %v", ok, err)
	}
}

func TestVerifyCheck_ErrorMapping(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"60202 too many attempts", 429, `{"code":60202}`, domain.ErrOTPMaxAttempts},
		{"20404 expired", 404, `{"code":20404}`, domain.ErrOTPExpired},
		{"60200 invalid", 400, `{"code":60200}`, domain.ErrOTPInvalid},
		{"status max_attempts_reached", 200, `{"status":"max_attempts_reached"}`, domain.ErrOTPMaxAttempts},
		{"status expired", 200, `{"status":"expired"}`, domain.ErrOTPExpired},
		{"status canceled", 200, `{"status":"canceled"}`, domain.ErrOTPExpired},
	}
	for _, c := range cases {
		_, v := newVerifyFake(t, c.status, c.body)
		ok, err := v.CheckVerification(context.Background(), "+5511999990000", "123456")
		if ok || !errors.Is(err, c.want) {
			t.Errorf("%s: ok=%v err=%v", c.name, ok, err)
		}
	}
	_, v := newVerifyFake(t, 500, `{"code":20500,"message":"boom"}`)
	if _, err := v.CheckVerification(context.Background(), "+5511999990000", "1"); err == nil || strings.Contains(err.Error(), "boom") {
		t.Errorf("unknown error must not leak: %v", err)
	}
	_, v = newVerifyFake(t, 200, `{"status":"weird"}`)
	if _, err := v.CheckVerification(context.Background(), "+5511999990000", "1"); err == nil {
		t.Error("unexpected status must be an error")
	}
}

// fakeVerifier is a domain.PhoneCodeVerifier that never touches the network.
type fakeVerifier struct {
	starts, checks int
	startErr       error
}

func (f *fakeVerifier) StartVerification(ctx context.Context, phone string) error {
	f.starts++
	return f.startErr
}
func (f *fakeVerifier) CheckVerification(ctx context.Context, phone, code string) (bool, error) {
	f.checks++
	return true, nil
}

func TestNotifierVerify_TestPrefixNeverReachesVerifyNorBudget(t *testing.T) {
	v, budget := &fakeVerifier{}, &fakeBudget{}
	n := NewBudgetedNotifier(&fakeProvider{}, budget,
		WithTestPhonePrefixes([]string{"+5500000000", "+5511900000"}, false), WithPhoneCodeVerifier(v))
	for _, phone := range []string{"+5500000000123", "+5511900000800"} {
		if n.UsesProviderVerification(phone) {
			t.Errorf("%s must not use the provider", phone)
		}
		if err := n.CheckPhone(phone); err != nil {
			t.Errorf("%s: test numbers skip the mobile check: %v", phone, err)
		}
	}
	if !n.UsesProviderVerification("+5511999990000") {
		t.Error("a real number must use the provider")
	}
	if v.starts != 0 || budget.reserved != 0 {
		t.Errorf("starts=%d reserved=%d", v.starts, budget.reserved)
	}
}

func TestNotifierVerify_StartConsumesBudgetLikeASend(t *testing.T) {
	v, budget := &fakeVerifier{}, &fakeBudget{}
	n := NewBudgetedNotifier(&fakeProvider{}, budget, WithPhoneCodeVerifier(v))
	if err := n.StartVerification(context.Background(), "+5511999990000"); err != nil {
		t.Fatal(err)
	}
	if v.starts != 1 || budget.reserved != 1 || budget.sent != 1 {
		t.Errorf("starts=%d budget=%+v", v.starts, budget)
	}
	// a refusal by the budget stops before the provider
	limit := &domain.SMSLimitError{Kind: domain.SMSLimitPhoneDay}
	budget.reserveErr = limit
	if err := n.StartVerification(context.Background(), "+5511999990000"); !errors.Is(err, limit) && err != limit {
		t.Errorf("got %v", err)
	}
	if v.starts != 1 {
		t.Error("the budget refusal must stop before the provider")
	}
	// failure before the network gives the reservation back
	budget.reserveErr = nil
	v.startErr = domain.ErrSMSNotSent
	_ = n.StartVerification(context.Background(), "+5511999990000")
	if budget.released != 1 {
		t.Errorf("released=%d", budget.released)
	}
}

func TestNotifierCheckPhone(t *testing.T) {
	live := true
	prov := &fakeProvider{live: &live}
	n := NewBudgetedNotifier(prov, &fakeBudget{})
	if err := n.CheckPhone("+551133334444"); !errors.Is(err, domain.ErrPhoneNotMobile) {
		t.Errorf("live direct SMS must refuse a landline: %v", err)
	}
	notLive := false
	mock := NewBudgetedNotifier(&fakeProvider{live: &notLive}, &fakeBudget{})
	if err := mock.CheckPhone("+551133334444"); err != nil {
		t.Errorf("mock path sends nothing, nothing to refuse: %v", err)
	}
	withVerify := NewBudgetedNotifier(&fakeProvider{live: &notLive}, &fakeBudget{}, WithPhoneCodeVerifier(&fakeVerifier{}))
	if err := withVerify.CheckPhone("+551133334444"); !errors.Is(err, domain.ErrPhoneNotMobile) {
		t.Errorf("verify mode must refuse a landline: %v", err)
	}
}

func TestWithTwilioVerifyIfConfigured(t *testing.T) {
	n := NewBudgetedNotifier(&fakeProvider{}, &fakeBudget{}, WithTwilioVerifyIfConfigured("AC", "tok", ""))
	if n.verifier != nil {
		t.Error("no service SID: Verify must stay off")
	}
	n = NewBudgetedNotifier(&fakeProvider{}, &fakeBudget{}, WithTwilioVerifyIfConfigured("AC", "tok", "VAxxxxxxxxxxxx"))
	if n.verifier == nil {
		t.Error("all set: Verify on")
	}
}

// Regression (staging 2026-10-17): sends Twilio refused used to consume the per-phone caps, so a person
// whose earlier attempts all failed (no sender, error 21659) was refused with sms_limit and never got a
// code. A refusal by Twilio (4xx) gives the reservation back; a 5xx may have sent, so it stays consumed.
func TestNotifierVerify_TwilioRefusalGivesTheReservationBack(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		released int
	}{
		{"4xx refusal", 400, `{"code":21659}`, 1},
		{"60203", 429, `{"code":60203}`, 1},
		{"60200", 400, `{"code":60200}`, 1},
		{"5xx may have sent", 503, `{"code":20503}`, 0},
	}
	for _, c := range cases {
		_, v := newVerifyFake(t, c.status, c.body)
		budget := &fakeBudget{}
		n := NewBudgetedNotifier(&fakeProvider{}, budget, WithPhoneCodeVerifier(v))
		err := n.StartVerification(context.Background(), "+5511999990000")
		if err == nil || budget.released != c.released || budget.sent != 0 {
			t.Errorf("%s: err=%v budget=%+v", c.name, err, budget)
		}
	}
	// the mapped errors survive the wrapping
	_, v := newVerifyFake(t, 429, `{"code":60203}`)
	var limit *domain.SMSLimitError
	if err := v.StartVerification(context.Background(), "+5511999990000"); !errors.As(err, &limit) {
		t.Errorf("limit lost: %v", err)
	}
}
