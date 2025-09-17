package examples

import (
	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/config"
	"github.com/you/authzsvc/internal/http/middleware"
	"github.com/you/authzsvc/domain"
)

// This example shows how to integrate the new validation system into your existing middleware chain

func IntegrateEnhancedValidation(
	cfg *config.Config,
	enforcer *casbin.Enforcer,
	tokenService domain.TokenService,
	sessionRepo domain.SessionRepository,
) *gin.Engine {
	router := gin.New()

	// 1. Setup JWT authentication middleware (now with session validation)
	authMW := middleware.NewAuthMW(tokenService, sessionRepo)
	
	// 2. Setup enhanced Casbin middleware with validation rules
	enhancedCasbinMW := middleware.NewEnhancedCasbinMW(
		enforcer,
		cfg.OwnershipRules,    // Legacy ownership rules for backward compatibility
		cfg.ValidationRules,   // New flexible validation rules
	)

	// 3. Apply middleware chain to protected routes
	protected := router.Group("/api/v1")
	protected.Use(authMW.WithJWT())           // JWT authentication
	protected.Use(enhancedCasbinMW.Enforce()) // Enhanced authorization + validation

	// 4. Define your routes (handlers remain unchanged)
	protected.GET("/users/:user_id", getUserProfile)
	protected.PUT("/users/:user_id", updateUserProfile)
	protected.POST("/projects", createProject)
	protected.GET("/projects/:project_id", getProject)
	protected.DELETE("/documents/:doc_id", deleteDocument)

	return router
}

// Example handlers (unchanged - they don't need to know about validation logic)
func getUserProfile(c *gin.Context) {
	userID := c.Param("user_id")
	// Handle user profile retrieval
	c.JSON(200, gin.H{"user_id": userID, "message": "Profile retrieved"})
}

func updateUserProfile(c *gin.Context) {
	userID := c.Param("user_id")
	// Handle user profile update
	c.JSON(200, gin.H{"user_id": userID, "message": "Profile updated"})
}

func createProject(c *gin.Context) {
	// Handle project creation
	c.JSON(201, gin.H{"message": "Project created"})
}

func getProject(c *gin.Context) {
	projectID := c.Param("project_id")
	// Handle project retrieval  
	c.JSON(200, gin.H{"project_id": projectID, "message": "Project retrieved"})
}

func deleteDocument(c *gin.Context) {
	docID := c.Param("doc_id")
	// Handle document deletion
	c.JSON(200, gin.H{"doc_id": docID, "message": "Document deleted"})
}

// Example of extending JWT claims to support additional validation fields
type CustomJWTClaims struct {
	UserID        string   `json:"user_id"`
	Role          string   `json:"role"`
	TenantID      string   `json:"tenant_id,omitempty"`
	OrganizationID string  `json:"organization_id,omitempty"`
	ProjectIDs    []string `json:"project_ids,omitempty"`
	TeamIDs       []string `json:"team_ids,omitempty"`
}

// Enhanced token service that supports additional claims
func generateEnhancedToken(userID string, claims CustomJWTClaims) string {
	// Implementation would create JWT with additional claims
	// These claims will be available in the validation engine
	return "enhanced-jwt-token"
}

// Migration strategy: Gradual rollout of validation rules
func MigrationExample() {
	// Step 1: Start with legacy ownership rules only
	// (current system continues to work)

	// Step 2: Add simple validation rules alongside legacy rules
	// e.g., header validation rules that duplicate existing logic
	
	// Step 3: Add more complex validation rules
	// e.g., tenant consistency, project access control
	
	// Step 4: Gradually disable legacy rules as validation rules take over
	// Set `enabled: false` on legacy rules in ownership_rules.yml
	
	// Step 5: Eventually remove legacy ownership system entirely
	// (this is optional - both can coexist indefinitely)
}