package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

func TestRespondPhoneCodeError_ShapeIsTheRegistrationValidationShape(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		err error
		msg string
	}{
		{domain.ErrPhoneNotMobile, "Use um número de celular"},
		{fmt.Errorf("wrapped: %w", domain.ErrPhoneNotMobile), "Use um número de celular"},
		{domain.ErrSMSInvalidPhone, "Phone number format is invalid"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(w)
		if !respondPhoneCodeError(ctx, c.err) {
			t.Fatalf("%v not handled", c.err)
		}
		var body map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusBadRequest || body["error"] != c.msg || body["code"] != "PHONE_FORMAT_INVALID" || body["field"] != "phone" {
			t.Errorf("%v: %d %v", c.err, w.Code, body)
		}
	}
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	if respondPhoneCodeError(ctx, errors.New("other")) {
		t.Error("an unrelated error must not be handled here")
	}
}
