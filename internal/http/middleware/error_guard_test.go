package middleware

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func guardedRouter(handler gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(ErrorGuard(), Recovery())
	r.GET("/x", handler)
	return r
}

func capture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func get(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	return w
}

func TestErrorGuard_5xxBodyIsFixedAndTheRequestIDMatchesTheLog(t *testing.T) {
	logs := capture(t)
	detail := `ERROR: relation "auth.password_history" does not exist (SQLSTATE 42P01)`
	for _, status := range []int{500, 502, 503} {
		w := get(guardedRouter(func(c *gin.Context) { c.JSON(status, gin.H{"error": "x", "details": errors.New(detail).Error()}) }))
		if w.Code != status {
			t.Fatalf("the status must be kept, got %d want %d", w.Code, status)
		}
		body := w.Body.String()
		if strings.Contains(body, "password_history") || strings.Contains(body, "SQLSTATE") {
			t.Errorf("the body leaks the internal error: %s", body)
		}
		if !strings.Contains(body, `"error":"internal_error"`) || !strings.Contains(body, `"message":"Erro interno. Tente novamente."`) {
			t.Errorf("unexpected body %s", body)
		}
		id := regexp.MustCompile(`"request_id":"([0-9a-f]{12})"`).FindStringSubmatch(body)
		if id == nil {
			t.Fatalf("no request_id in %s", body)
		}
		if w.Header().Get("X-Request-Id") != id[1] {
			t.Errorf("the X-Request-Id header %q must equal the body id %q", w.Header().Get("X-Request-Id"), id[1])
		}
		if !strings.Contains(logs.String(), "request_id="+id[1]) || !strings.Contains(logs.String(), "password_history") {
			t.Errorf("the log must carry the same id and the real error: %s", logs.String())
		}
	}
}

func TestErrorGuard_SwitchOnShowsTheDetail(t *testing.T) {
	SetExposeErrorDetails(true)
	defer SetExposeErrorDetails(false)
	w := get(guardedRouter(func(c *gin.Context) { c.JSON(500, gin.H{"error": "x", "details": "relation missing"}) }))
	if !strings.Contains(w.Body.String(), "relation missing") {
		t.Errorf("with EXPOSE_ERROR_DETAILS the original body is sent: %s", w.Body.String())
	}
}

func TestErrorGuard_ClientErrorsAndDeliberate5xxPassThroughUnchanged(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   gin.H
	}{
		"400":                {400, gin.H{"error": "Invalid OTP code"}},
		"401":                {401, gin.H{"error": "Invalid credentials"}},
		"409":                {409, gin.H{"error": "User already exists"}},
		"429 sms_limit":      {429, gin.H{"error": "sms_limit", "message": "Limite", "retry_after_seconds": 90}},
		"403 phone":          {403, gin.H{"error": "Phone number not verified.", "code": "phone_not_verified", "user_id": 7}},
		"503 sms_unavailable": {503, gin.H{"error": "sms_unavailable", "message": "Envio indisponível"}},
		"500 deletion_failed": {500, gin.H{"error": "deletion_failed", "message": "Contact support", "request_id": "abc"}},
	} {
		t.Run(name, func(t *testing.T) {
			direct := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(direct)
			c.JSON(tc.status, tc.body)

			w := get(guardedRouter(func(c *gin.Context) { c.JSON(tc.status, tc.body) }))
			if w.Code != tc.status || w.Body.String() != direct.Body.String() {
				t.Errorf("got %d %s, want %d %s", w.Code, w.Body.String(), tc.status, direct.Body.String())
			}
		})
	}
}

func TestErrorGuard_PanicGetsTheFixedBodyAndNoStackInTheResponse(t *testing.T) {
	logs := capture(t)
	w := get(guardedRouter(func(c *gin.Context) { panic(errors.New("nil pointer in secret place")) }))
	body := w.Body.String()
	if w.Code != 500 || strings.Contains(body, "secret place") || !strings.Contains(body, `"error":"internal_error"`) {
		t.Errorf("unexpected panic answer %d %s", w.Code, body)
	}
	if !strings.Contains(logs.String(), "PANIC") || !strings.Contains(logs.String(), "secret place") {
		t.Errorf("the panic must be logged: %s", logs.String())
	}
}

func TestErrorGuard_EmptyAndHeaderOnly5xxAlsoGetTheFixedBody(t *testing.T) {
	capture(t)
	w := get(guardedRouter(func(c *gin.Context) { c.AbortWithStatus(500) }))
	if w.Code != 500 || !strings.Contains(w.Body.String(), `"error":"internal_error"`) {
		t.Errorf("unexpected answer %d %s", w.Code, w.Body.String())
	}
}

func TestRedactSensitive(t *testing.T) {
	in := `duplicate key value violates unique constraint "users_phone_key" Key (phone)=(+5511999990000) already exists for ana@example.com hash $2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab`
	out := RedactSensitive(in)
	for _, leak := range []string{"5511999990000", "ana@example.com", "$2a$10$"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q survived redaction: %s", leak, out)
		}
	}
	if !strings.Contains(out, "users_phone_key") {
		t.Errorf("the useful part of the message must stay: %s", out)
	}
	if len(RedactSensitive(strings.Repeat("x", 5000))) > maxLoggedDetail+5 {
		t.Error("long details are truncated")
	}
}
