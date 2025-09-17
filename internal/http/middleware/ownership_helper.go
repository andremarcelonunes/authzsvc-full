package middleware

import (
	"bytes"
	"encoding/json"
	"io/ioutil"

	"github.com/gin-gonic/gin"
)

// extractUserID extracts a user ID from the request based on a defined rule.
func extractUserID(c *gin.Context, source string, paramName string) string {
	switch source {
	case "path":
		return c.Param(paramName)
	case "query":
		return c.Query(paramName)
	case "header":
		return c.GetHeader(paramName)
	case "body":
		// For the body, we must read it and then replace it so other handlers can access it.
		bodyBytes, err := ioutil.ReadAll(c.Request.Body)
		if err != nil {
			// Handle error appropriately, maybe log it.
			return ""
		}
		// Restore the body
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))

		var bodyJSON map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &bodyJSON); err != nil {
			// Handle error appropriately, maybe log it.
			return ""
		}

		if id, ok := bodyJSON[paramName]; ok {
			if idStr, ok := id.(string); ok {
				return idStr
			}
		}
	}
	return ""
}
