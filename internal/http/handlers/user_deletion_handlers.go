package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/services"
)

// UserDeletionHandlers handles LGPD-compliant user deletion requests
type UserDeletionHandlers struct {
	deletionService *services.UserDeletionService
	authService     domain.AuthService
}

// NewUserDeletionHandlers creates new deletion handlers
func NewUserDeletionHandlers(
	deletionService *services.UserDeletionService,
	authService domain.AuthService,
) *UserDeletionHandlers {
	return &UserDeletionHandlers{
		deletionService: deletionService,
		authService:     authService,
	}
}

// RequestDeletionRequest represents user deletion request payload
type RequestDeletionRequest struct {
	DeletionType string `json:"deletion_type" binding:"required,oneof=full_delete soft_delete anonymization deactivation export_delete"`
	Reason       string `json:"reason" binding:"required,min=10,max=500"`
	Confirm      bool   `json:"confirm" binding:"required"`
}

// RequestDeletion handles POST /users/me/deletion - LGPD Article 18, VI
// @Summary Request account deletion (LGPD compliant)
// @Description Request deletion, anonymization, or deactivation of user account per LGPD Article 18
// @Tags User Management
// @Accept json
// @Produce json
// @Param request body RequestDeletionRequest true "Deletion request details"
// @Success 201 {object} map[string]interface{} "Deletion request created"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 401 {object} map[string]interface{} "Unauthorized"
// @Failure 403 {object} map[string]interface{} "Deletion blocked for legal reasons"
// @Router /users/me/deletion [post]
// @Security Bearer
func (h *UserDeletionHandlers) RequestDeletion(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "user not authenticated",
		})
		return
	}

	var req RequestDeletionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"details": err.Error(),
		})
		return
	}

	// Require explicit confirmation
	if !req.Confirm {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "deletion must be explicitly confirmed",
			"hint": "Set 'confirm' to true to proceed",
		})
		return
	}

	// Map string to domain type
	var requestType domain.DeletionRequestType
	switch req.DeletionType {
	case "full_delete":
		requestType = domain.DeletionTypeFullDelete
	case "soft_delete":
		requestType = domain.DeletionTypeSoftDelete
	case "anonymization":
		requestType = domain.DeletionTypeAnonymization
	case "deactivation":
		requestType = domain.DeletionTypeDeactivation
	case "export_delete":
		requestType = domain.DeletionTypeExportAndDelete
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid deletion type",
		})
		return
	}

	// Create deletion request
	deletionReq, err := h.deletionService.RequestDeletion(
		c.Request.Context(),
		userID.(uint),
		requestType,
		req.Reason,
	)
	if err != nil {
		// Check if it's a compliance block
		if containsString(err.Error(), "deletion blocked") {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "deletion_blocked",
				"message": err.Error(),
				"lgpd_article": "Article 16 - Data retention for legal compliance",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create deletion request",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"request_id": deletionReq.ID.String(),
			"status": deletionReq.Status,
			"type": deletionReq.RequestType,
			"scheduled_for": deletionReq.ScheduledFor,
			"retention_required": deletionReq.RetentionRequired,
			"message": "Deletion request created. You have 30 days to cancel this request.",
			"lgpd_rights": gin.H{
				"article": "Article 18, VI",
				"description": "Right to deletion of personal data",
			},
		},
	})
}

// GetDeletionStatus handles GET /users/me/deletion/:id
// @Summary Check deletion request status
// @Description Get the current status of a deletion request
// @Tags User Management
// @Produce json
// @Param id path string true "Deletion request ID"
// @Success 200 {object} map[string]interface{} "Deletion request status"
// @Failure 404 {object} map[string]interface{} "Request not found"
// @Router /users/me/deletion/{id} [get]
// @Security Bearer
func (h *UserDeletionHandlers) GetDeletionStatus(c *gin.Context) {
	userID, _ := c.Get("user_id")
	requestIDStr := c.Param("id")
	
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request ID",
		})
		return
	}

	request, err := h.deletionService.GetDeletionStatus(c.Request.Context(), requestID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "deletion request not found",
		})
		return
	}

	// Verify the request belongs to the user
	if request.UserID != userID.(uint) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "access denied",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"request_id": request.ID.String(),
			"status": request.Status,
			"type": request.RequestType,
			"requested_at": request.RequestedAt,
			"scheduled_for": request.ScheduledFor,
			"processed_at": request.ProcessedAt,
			"completed_at": request.CompletedAt,
			"retention_required": request.RetentionRequired,
			"retention_reason": request.RetentionReason,
		},
	})
}

// CancelDeletion handles DELETE /users/me/deletion/:id
// @Summary Cancel deletion request
// @Description Cancel a pending deletion request within the grace period
// @Tags User Management
// @Accept json
// @Produce json
// @Param id path string true "Deletion request ID"
// @Success 200 {object} map[string]interface{} "Deletion cancelled"
// @Failure 400 {object} map[string]interface{} "Cannot cancel"
// @Router /users/me/deletion/{id} [delete]
// @Security Bearer
func (h *UserDeletionHandlers) CancelDeletion(c *gin.Context) {
	userID, _ := c.Get("user_id")
	requestIDStr := c.Param("id")
	
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request ID",
		})
		return
	}

	// Verify ownership
	request, err := h.deletionService.GetDeletionStatus(c.Request.Context(), requestID)
	if err != nil || request.UserID != userID.(uint) {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "access denied",
		})
		return
	}

	// Cancel the request
	if err := h.deletionService.CancelDeletionRequest(c.Request.Context(), requestID, "User cancelled"); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "cannot cancel deletion",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "Deletion request cancelled successfully",
			"request_id": requestID.String(),
		},
	})
}

// ExportDataRequest represents data export request
type ExportDataRequest struct {
	Format string `json:"format" binding:"required,oneof=json csv xml"`
}

// ExportUserData handles POST /users/me/export - LGPD Article 18, V
// @Summary Export user data (LGPD data portability)
// @Description Export all user data in machine-readable format per LGPD Article 18, V
// @Tags User Management
// @Accept json
// @Produce json
// @Param request body ExportDataRequest true "Export format"
// @Success 201 {object} map[string]interface{} "Export created"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Router /users/me/export [post]
// @Security Bearer
func (h *UserDeletionHandlers) ExportUserData(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	var req ExportDataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request",
			"details": err.Error(),
		})
		return
	}

	export, err := h.deletionService.ExportUserData(
		c.Request.Context(),
		userID.(uint),
		req.Format,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create export",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"export_id": export.ExportID.String(),
			"download_url": export.DownloadURL,
			"format": export.Format,
			"size_bytes": export.Size,
			"expires_at": export.ExpiresAt,
			"checksum": export.Checksum,
			"lgpd_rights": gin.H{
				"article": "Article 18, V",
				"description": "Right to data portability",
			},
		},
	})
}

// GetDeletionHistory handles GET /users/me/deletion/history
// @Summary Get deletion request history
// @Description Get all deletion requests and audit logs for the user
// @Tags User Management
// @Produce json
// @Success 200 {object} map[string]interface{} "Deletion history"
// @Router /users/me/deletion/history [get]
// @Security Bearer
func (h *UserDeletionHandlers) GetDeletionHistory(c *gin.Context) {
	userID, _ := c.Get("user_id")
	
	auditLogs, err := h.deletionService.GetDeletionAuditLog(
		c.Request.Context(),
		userID.(uint),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to get deletion history",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"audit_logs": auditLogs,
			"total": len(auditLogs),
		},
	})
}

// AdminProcessDeletion handles POST /admin/users/deletion/:id/process
// @Summary Process pending deletion request (Admin)
// @Description Manually trigger processing of a scheduled deletion request
// @Tags Admin
// @Produce json
// @Param id path string true "Deletion request ID"
// @Success 200 {object} map[string]interface{} "Processing started"
// @Failure 403 {object} map[string]interface{} "Not authorized"
// @Router /admin/users/deletion/{id}/process [post]
// @Security Bearer
func (h *UserDeletionHandlers) AdminProcessDeletion(c *gin.Context) {
	// Verify admin role (should be checked by middleware too)
	role, _ := c.Get("user_role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "admin access required",
		})
		return
	}

	requestIDStr := c.Param("id")
	requestID, err := uuid.Parse(requestIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request ID",
		})
		return
	}

	if err := h.deletionService.ProcessDeletionRequest(c.Request.Context(), requestID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to process deletion",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "Deletion request processed successfully",
			"request_id": requestID.String(),
		},
	})
}

// AdminListPendingDeletions handles GET /admin/users/deletion/pending
// @Summary List pending deletion requests (Admin)
// @Description Get all pending deletion requests for processing
// @Tags Admin
// @Produce json
// @Success 200 {object} map[string]interface{} "Pending deletions"
// @Router /admin/users/deletion/pending [get]
// @Security Bearer
func (h *UserDeletionHandlers) AdminListPendingDeletions(c *gin.Context) {
	// Verify admin role
	role, _ := c.Get("user_role")
	if role != "admin" {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "admin access required",
		})
		return
	}

	requests, err := h.deletionService.ListPendingDeletions(
		c.Request.Context(),
		30*24*time.Hour, // Older than 30 days
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to list pending deletions",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"pending_deletions": requests,
			"total": len(requests),
		},
	})
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}