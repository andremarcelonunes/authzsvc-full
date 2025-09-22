package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// AuditHandlers provides HTTP handlers for audit log management
type AuditHandlers struct {
	auditService domain.ComprehensiveAuditService
}

// NewAuditHandlers creates new audit handlers
func NewAuditHandlers(auditService domain.ComprehensiveAuditService) *AuditHandlers {
	return &AuditHandlers{
		auditService: auditService,
	}
}

// AuditQueryRequest represents the request for querying audit events
type AuditQueryRequest struct {
	// Time range
	StartTime *time.Time `json:"start_time" form:"start_time"`
	EndTime   *time.Time `json:"end_time" form:"end_time"`
	
	// Event filters
	EventTypes     []string                   `json:"event_types" form:"event_types"`
	EventCategories []domain.AuditEventCategory `json:"event_categories" form:"event_categories"`
	Success        *bool                      `json:"success" form:"success"`
	
	// User filters
	UserIDs     []uint   `json:"user_ids" form:"user_ids"`
	SessionIDs  []string `json:"session_ids" form:"session_ids"`
	IPAddresses []string `json:"ip_addresses" form:"ip_addresses"`
	
	// Resource filters
	ResourceTypes []string `json:"resource_types" form:"resource_types"`
	ResourceIDs   []string `json:"resource_ids" form:"resource_ids"`
	Actions       []string `json:"actions" form:"actions"`
	
	// Compliance filters
	LegalBases          []domain.LegalBasis         `json:"legal_bases" form:"legal_bases"`
	DataClassifications []domain.DataClassification `json:"data_classifications" form:"data_classifications"`
	
	// Security filters
	SecurityEvents bool                    `json:"security_events" form:"security_events"`
	MinSeverity    *domain.SecuritySeverity `json:"min_severity" form:"min_severity"`
	
	// Pagination
	Page           int    `json:"page" form:"page"`
	PageSize       int    `json:"page_size" form:"page_size"`
	OrderBy        string `json:"order_by" form:"order_by"`
	OrderDirection string `json:"order_direction" form:"order_direction"`
}

// AuditExportRequest represents the request for exporting audit events
type AuditExportRequest struct {
	AuditQueryRequest
	Format        domain.ExportFormat `json:"format" form:"format" binding:"required"`
	IncludeFields []string            `json:"include_fields" form:"include_fields"`
	ExcludeFields []string            `json:"exclude_fields" form:"exclude_fields"`
	Encryption    bool                `json:"encryption" form:"encryption"`
	MaxRecords    int                 `json:"max_records" form:"max_records"`
}

// QueryAuditEvents handles GET /admin/audit/events
// @Summary Query audit events
// @Description Query audit events with filtering and pagination
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param query query AuditQueryRequest false "Query parameters"
// @Success 200 {object} domain.AuditResults
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/events [get]
func (h *AuditHandlers) QueryAuditEvents(c *gin.Context) {
	var req AuditQueryRequest
	
	// Bind query parameters
	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid query parameters",
			Details: err.Error(),
		})
		return
	}
	
	// Set defaults
	if req.Page <= 0 {
		req.Page = 1
	}
	if req.PageSize <= 0 {
		req.PageSize = 50
	}
	if req.PageSize > 1000 {
		req.PageSize = 1000 // Max page size
	}
	
	// Convert to domain criteria
	criteria := &domain.AuditCriteria{
		StartTime:           req.StartTime,
		EndTime:             req.EndTime,
		EventTypes:          req.EventTypes,
		EventCategories:     req.EventCategories,
		Success:             req.Success,
		UserIDs:             req.UserIDs,
		SessionIDs:          req.SessionIDs,
		IPAddresses:         req.IPAddresses,
		ResourceTypes:       req.ResourceTypes,
		ResourceIDs:         req.ResourceIDs,
		Actions:             req.Actions,
		LegalBases:          req.LegalBases,
		DataClassifications: req.DataClassifications,
		SecurityEvents:      req.SecurityEvents,
		MinSeverity:         req.MinSeverity,
		Limit:               req.PageSize,
		Offset:              (req.Page - 1) * req.PageSize,
		OrderBy:             req.OrderBy,
		OrderDirection:      req.OrderDirection,
	}
	
	// Query audit events
	results, err := h.auditService.QueryEvents(c.Request.Context(), criteria)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to query audit events",
			Details: err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, results)
}

// GetAuditEvent handles GET /admin/audit/events/:id
// @Summary Get audit event by ID
// @Description Get a specific audit event by its ID
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "Audit Event ID"
// @Success 200 {object} domain.ComprehensiveAuditEvent
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/events/{id} [get]
func (h *AuditHandlers) GetAuditEvent(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid audit event ID",
			Details: "ID must be a valid integer",
		})
		return
	}
	
	// For individual event access, we'll use the repository directly
	// In a production system, this might go through the service for additional authorization
	criteria := &domain.AuditCriteria{
		Limit:  1,
		Offset: 0,
	}
	
	// This is a simplified approach - in production you might want to add criteria for the specific ID
	results, err := h.auditService.QueryEvents(c.Request.Context(), criteria)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get audit event",
			Details: err.Error(),
		})
		return
	}
	
	// Find the specific event (simplified - in production use a proper FindByID method)
	for _, event := range results.Events {
		if event.ID == id {
			c.JSON(http.StatusOK, event)
			return
		}
	}
	
	c.JSON(http.StatusNotFound, ErrorResponse{
		Error:   "Audit event not found",
		Details: "No audit event found with the specified ID",
	})
}

// ExportAuditEvents handles POST /admin/audit/export
// @Summary Export audit events
// @Description Export audit events in various formats (JSON, CSV, XLSX, PDF)
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body AuditExportRequest true "Export request"
// @Success 200 {object} domain.ExportResult
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/export [post]
func (h *AuditHandlers) ExportAuditEvents(c *gin.Context) {
	var req AuditExportRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid export request",
			Details: err.Error(),
		})
		return
	}
	
	// Validate export format
	validFormats := []domain.ExportFormat{
		domain.ExportFormatJSON,
		domain.ExportFormatCSV,
		domain.ExportFormatXLSX,
		domain.ExportFormatPDF,
	}
	
	validFormat := false
	for _, format := range validFormats {
		if req.Format == format {
			validFormat = true
			break
		}
	}
	
	if !validFormat {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid export format",
			Details: "Supported formats: json, csv, xlsx, pdf",
		})
		return
	}
	
	// Set export limits
	if req.MaxRecords <= 0 {
		req.MaxRecords = 10000 // Default max
	}
	if req.MaxRecords > 100000 {
		req.MaxRecords = 100000 // Hard limit
	}
	
	// Convert to export criteria
	criteria := &domain.ExportCriteria{
		AuditCriteria: domain.AuditCriteria{
			StartTime:           req.StartTime,
			EndTime:             req.EndTime,
			EventTypes:          req.EventTypes,
			EventCategories:     req.EventCategories,
			Success:             req.Success,
			UserIDs:             req.UserIDs,
			SessionIDs:          req.SessionIDs,
			IPAddresses:         req.IPAddresses,
			ResourceTypes:       req.ResourceTypes,
			ResourceIDs:         req.ResourceIDs,
			Actions:             req.Actions,
			LegalBases:          req.LegalBases,
			DataClassifications: req.DataClassifications,
			SecurityEvents:      req.SecurityEvents,
			MinSeverity:         req.MinSeverity,
			Limit:               req.MaxRecords,
			Offset:              0,
			OrderBy:             req.OrderBy,
			OrderDirection:      req.OrderDirection,
		},
		Format:        req.Format,
		IncludeFields: req.IncludeFields,
		ExcludeFields: req.ExcludeFields,
		Encryption:    req.Encryption,
		MaxRecords:    req.MaxRecords,
	}
	
	// Export audit events
	result, err := h.auditService.ExportEvents(c.Request.Context(), criteria)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to export audit events",
			Details: err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, result)
}

// GetAuditStatistics handles GET /admin/audit/statistics
// @Summary Get audit statistics
// @Description Get audit event statistics and metrics
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param time_range query string false "Time range (e.g., 24h, 7d, 30d)" default:"24h"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/statistics [get]
func (h *AuditHandlers) GetAuditStatistics(c *gin.Context) {
	timeRangeStr := c.DefaultQuery("time_range", "24h")
	
	timeRange, err := time.ParseDuration(timeRangeStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid time range",
			Details: "Time range must be a valid duration (e.g., 24h, 7d, 30d)",
		})
		return
	}
	
	// Get metrics from the audit service
	metrics, err := h.auditService.GetMetrics(c.Request.Context(), timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get audit statistics",
			Details: err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, metrics)
}

// GetAuditHealth handles GET /admin/audit/health
// @Summary Get audit system health
// @Description Get audit system health status and component status
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/health [get]
func (h *AuditHandlers) GetAuditHealth(c *gin.Context) {
	health, err := h.auditService.GetHealthStatus(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get audit health status",
			Details: err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, health)
}

// GetUserAuditTrail handles GET /admin/audit/users/:user_id/trail
// @Summary Get user audit trail
// @Description Get audit trail for a specific user (LGPD compliance)
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param user_id path int true "User ID"
// @Param time_range query string false "Time range (e.g., 24h, 7d, 30d)" default:"30d"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/users/{user_id}/trail [get]
func (h *AuditHandlers) GetUserAuditTrail(c *gin.Context) {
	userIDStr := c.Param("user_id")
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid user ID",
			Details: "User ID must be a valid integer",
		})
		return
	}
	
	timeRangeStr := c.DefaultQuery("time_range", "30d")
	timeRange, err := time.ParseDuration(timeRangeStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid time range",
			Details: "Time range must be a valid duration (e.g., 24h, 7d, 30d)",
		})
		return
	}
	
	// Get user activity summary for LGPD compliance
	trail, err := h.auditService.TrackDataSubjectRights(c.Request.Context(), uint(userID))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get user audit trail",
			Details: err.Error(),
		})
		return
	}
	
	// Add time range to response metadata
	trail["requested_time_range"] = timeRange.String()
	
	c.JSON(http.StatusOK, trail)
}

// GenerateComplianceReport handles POST /admin/audit/compliance/report
// @Summary Generate LGPD compliance report
// @Description Generate a compliance report for a specific user
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body ComplianceReportRequest true "Compliance report request"
// @Success 200 {object} domain.ExportResult
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/compliance/report [post]
func (h *AuditHandlers) GenerateComplianceReport(c *gin.Context) {
	var req ComplianceReportRequest
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid compliance report request",
			Details: err.Error(),
		})
		return
	}
	
	timeRange := 30 * 24 * time.Hour // Default to 30 days
	if req.TimeRange != "" {
		var err error
		timeRange, err = time.ParseDuration(req.TimeRange)
		if err != nil {
			c.JSON(http.StatusBadRequest, ErrorResponse{
				Error:   "Invalid time range",
				Details: "Time range must be a valid duration (e.g., 24h, 7d, 30d)",
			})
			return
		}
	}
	
	// Generate LGPD compliance report
	report, err := h.auditService.GenerateLGPDReport(c.Request.Context(), req.UserID, timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to generate compliance report",
			Details: err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, report)
}

// GetSecurityEvents handles GET /admin/audit/security
// @Summary Get security events
// @Description Get security-related audit events for threat analysis
// @Tags Audit
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param time_range query string false "Time range (e.g., 24h, 7d, 30d)" default:"24h"
// @Param severity query string false "Minimum severity (low, medium, high, critical)"
// @Param limit query int false "Maximum number of events" default:"100"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /admin/audit/security [get]
func (h *AuditHandlers) GetSecurityEvents(c *gin.Context) {
	timeRangeStr := c.DefaultQuery("time_range", "24h")
	timeRange, err := time.ParseDuration(timeRangeStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "Invalid time range",
			Details: "Time range must be a valid duration (e.g., 24h, 7d, 30d)",
		})
		return
	}
	
	// Generate security report
	report, err := h.auditService.GenerateSecurityReport(c.Request.Context(), timeRange)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "Failed to get security events",
			Details: err.Error(),
		})
		return
	}
	
	c.JSON(http.StatusOK, report)
}

// Supporting types for API requests

// ComplianceReportRequest represents a request for generating compliance reports
type ComplianceReportRequest struct {
	UserID    uint   `json:"user_id" binding:"required"`
	TimeRange string `json:"time_range,omitempty"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Details string `json:"details,omitempty"`
}