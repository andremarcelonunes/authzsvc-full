package handlers

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

// SwaggerDocsHandler serves the Swagger documentation
type SwaggerDocsHandler struct{}

// NewSwaggerDocsHandler creates a new Swagger docs handler
func NewSwaggerDocsHandler() *SwaggerDocsHandler {
	return &SwaggerDocsHandler{}
}

// GetSwaggerYAML serves the swagger.yaml file
func (h *SwaggerDocsHandler) GetSwaggerYAML(c *gin.Context) {
	yamlPath := filepath.Join("docs", "swagger.yaml")
	
	// Check if file exists
	if _, err := os.Stat(yamlPath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Swagger documentation not found",
		})
		return
	}

	// Serve the YAML file
	c.Header("Content-Type", "application/x-yaml")
	c.File(yamlPath)
}

// GetSwaggerUI serves a simple Swagger UI HTML page
func (h *SwaggerDocsHandler) GetSwaggerUI(c *gin.Context) {
	html := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthZ Service API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.10.3/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/docs/swagger.yaml',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                validatorUrl: null,
                tryItOutEnabled: true,
                supportedSubmitMethods: ['get', 'post', 'put', 'delete', 'patch'],
                onComplete: function() {
                    console.log('Swagger UI loaded successfully');
                }
            });
            
            window.ui = ui;
        };
    </script>
</body>
</html>`
	
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, html)
}

// GetAPIDocs serves API documentation information
func (h *SwaggerDocsHandler) GetAPIDocs(c *gin.Context) {
	docs := gin.H{
		"title":       "AuthZ Service API Documentation",
		"description": "Complete authentication and authorization service with JWT, OTP, and RBAC",
		"version":     "1.0.0",
		"endpoints": gin.H{
			"swagger_ui":   "/docs",
			"swagger_yaml": "/docs/swagger.yaml",
			"openapi_spec": "/docs/swagger.yaml",
		},
		"features": []string{
			"JWT Authentication with Access/Refresh Tokens",
			"SMS OTP Verification via Twilio",
			"Casbin RBAC with Role Inheritance",
			"Field-Level Validation and Ownership Rules",
			"Session Management with Redis",
			"External Authorization for Envoy Integration",
			"Complete Admin Policy Management",
		},
		"quick_start": gin.H{
			"health_check": "GET /health",
			"register":     "POST /auth/register",
			"login":        "POST /auth/login",
			"swagger_ui":   "GET /docs",
		},
	}
	
	c.JSON(http.StatusOK, docs)
}