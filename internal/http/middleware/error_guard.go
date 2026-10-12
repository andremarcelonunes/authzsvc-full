package middleware

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"runtime/debug"
	"sync/atomic"

	"github.com/gin-gonic/gin"
)

// InternalErrorBody is the fixed answer to every internal failure; the real error goes only to the log,
// under the same request id.
const (
	internalErrorCode    = "internal_error"
	internalErrorMessage = "Erro interno. Tente novamente."
	requestIDKey         = "request_id"
	requestIDHeader      = "X-Request-Id"
	maxLoggedDetail      = 600
)

var exposeErrorDetails atomic.Bool

// SetExposeErrorDetails makes 5xx answers carry the original body (EXPOSE_ERROR_DETAILS). Default off.
func SetExposeErrorDetails(on bool) { exposeErrorDetails.Store(on) }

// deliberate5xx are 5xx bodies written on purpose for the client (the app matches on them); the guard
// leaves them alone.
var deliberate5xx = map[string]bool{
	"sms_unavailable":       true, // the SMS budget is exhausted or its store is down
	"sms_usage_unavailable": true,
	"deletion_failed":       true, // immediate self-deletion failed; carries its request id
	internalErrorCode:       true, // already the fixed body (recovery)
}

// RequestID returns the id of the current request ("" outside ErrorGuard).
func RequestID(c *gin.Context) string { return c.GetString(requestIDKey) }

func newRequestID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}

func internalBody(id string) []byte {
	out, _ := json.Marshal(gin.H{"error": internalErrorCode, "message": internalErrorMessage, "request_id": id})
	return out
}

var (
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	phonePattern = regexp.MustCompile(`\+?\d[\d\s\-()]{6,}\d`)
	hashPattern  = regexp.MustCompile(`\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}`)
)

// RedactSensitive masks e-mails, phone-like digit runs and bcrypt hashes, so an error text copied into
// a log line cannot carry them (database errors quote the offending values).
func RedactSensitive(s string) string {
	s = hashPattern.ReplaceAllString(s, "[hash]")
	s = emailPattern.ReplaceAllString(s, "[email]")
	s = phonePattern.ReplaceAllString(s, "[number]")
	if len(s) > maxLoggedDetail {
		s = s[:maxLoggedDetail] + "..."
	}
	return s
}

// guardWriter holds back any response with a 5xx status so the guard can replace its body.
type guardWriter struct {
	gin.ResponseWriter
	status int
	hold   bool
	buf    bytes.Buffer
}

func (w *guardWriter) WriteHeader(code int) {
	if code >= http.StatusInternalServerError {
		w.status, w.hold = code, true
		return
	}
	w.hold = false
	w.ResponseWriter.WriteHeader(code)
}

func (w *guardWriter) WriteHeaderNow() {
	if !w.hold {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *guardWriter) Write(b []byte) (int, error) {
	if w.hold {
		return w.buf.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *guardWriter) WriteString(s string) (int, error) {
	if w.hold {
		return w.buf.WriteString(s)
	}
	return w.ResponseWriter.WriteString(s)
}

func (w *guardWriter) Status() int {
	if w.hold {
		return w.status
	}
	return w.ResponseWriter.Status()
}

func (w *guardWriter) Size() int {
	if w.hold {
		return w.buf.Len()
	}
	return w.ResponseWriter.Size()
}

func (w *guardWriter) Written() bool {
	if w.hold {
		return w.buf.Len() > 0
	}
	return w.ResponseWriter.Written()
}

func (w *guardWriter) Flush() {
	if !w.hold {
		w.ResponseWriter.Flush()
	}
}

// ErrorGuard gives every request an id (header X-Request-Id) and turns internal failures (5xx) into the
// fixed body {"error":"internal_error","message":"Erro interno. Tente novamente.","request_id":"..."}.
// The original body, which is where handlers put the error text, is logged under the same id with
// e-mails, numbers and hashes masked. Deliberate 5xx bodies (deliberate5xx) pass through. With
// SetExposeErrorDetails(true) the original body is sent as well.
func ErrorGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := newRequestID()
		c.Set(requestIDKey, id)
		c.Header(requestIDHeader, id)

		gw := &guardWriter{ResponseWriter: c.Writer}
		c.Writer = gw
		c.Next()
		if !gw.hold {
			return
		}

		original := gw.buf.Bytes()
		var parsed map[string]interface{}
		_ = json.Unmarshal(original, &parsed)
		code, _ := parsed["error"].(string)
		deliberate := deliberate5xx[code]

		if !deliberate {
			log.Printf("ERROR request_id=%s %s %s status=%d detail=%s", id, c.Request.Method, c.Request.URL.Path, gw.status, RedactSensitive(string(original)))
		}
		body := original
		if !deliberate && !exposeErrorDetails.Load() {
			body = internalBody(id)
		}
		gw.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
		gw.ResponseWriter.WriteHeader(gw.status)
		_, _ = gw.ResponseWriter.Write(body)
	}
}

// Recovery turns a panic into the same fixed 500 body, logging the panic and stack under the request id.
// Unlike gin.Recovery it never prints request headers.
func Recovery() gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(io.Discard, func(c *gin.Context, recovered interface{}) {
		id := RequestID(c)
		if id == "" {
			id = newRequestID()
		}
		log.Printf("PANIC request_id=%s %s %s: %v\n%s", id, c.Request.Method, c.Request.URL.Path, recovered, debug.Stack())
		body := gin.H{"error": internalErrorCode, "message": internalErrorMessage, "request_id": id}
		if exposeErrorDetails.Load() {
			body["detail"] = RedactSensitive(sprint(recovered))
		}
		c.AbortWithStatusJSON(http.StatusInternalServerError, body)
	})
}

func sprint(v interface{}) string {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
