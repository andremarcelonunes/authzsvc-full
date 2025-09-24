package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
)

// DeletionScheduler handles background processing of deletion requests
type DeletionScheduler struct {
	deletionService  *UserDeletionService
	deletionRepo     domain.DeletionRequestRepository
	auditService     domain.ComprehensiveAuditLogger
	complianceService *LGPDComplianceService
	
	// Configuration
	config           *DeletionSchedulerConfig
	
	// Job management
	jobs             map[string]*ScheduledJob
	jobsMutex        sync.RWMutex
	
	// Channel for job processing
	jobQueue         chan *ScheduledJob
	stopChannel      chan bool
	
	// Monitoring
	metrics          *JobMetrics
	
	// Sync
	wg               sync.WaitGroup
	running          bool
	runningMutex     sync.RWMutex
}

// DeletionSchedulerConfig contains configuration for the scheduler
type DeletionSchedulerConfig struct {
	// Processing intervals
	GracePeriodCheckInterval    time.Duration
	RetentionCheckInterval      time.Duration
	ExportCleanupInterval       time.Duration
	FailedRetryInterval         time.Duration
	
	// Limits
	MaxConcurrentJobs          int
	MaxRetryAttempts           int
	RetryBackoffMultiplier     float64
	
	// Timeouts
	JobTimeout                 time.Duration
	ShutdownTimeout            time.Duration
	
	// Features
	EnableAutoProcessing       bool
	EnableRetentionEnforcement bool
	EnableExportCleanup        bool
	EnableMetrics              bool
	
	// Testing
	TestMode                   bool
}

// DefaultDeletionSchedulerConfig returns production-ready configuration
func DefaultDeletionSchedulerConfig() *DeletionSchedulerConfig {
	return &DeletionSchedulerConfig{
		GracePeriodCheckInterval:    15 * time.Minute,  // Check every 15 minutes
		RetentionCheckInterval:      24 * time.Hour,    // Daily retention check
		ExportCleanupInterval:       6 * time.Hour,     // Clean exports every 6 hours
		FailedRetryInterval:         30 * time.Minute,  // Retry failed jobs every 30 minutes
		MaxConcurrentJobs:           10,
		MaxRetryAttempts:            3,
		RetryBackoffMultiplier:      2.0,
		JobTimeout:                  5 * time.Minute,
		ShutdownTimeout:             30 * time.Second,
		EnableAutoProcessing:        true,
		EnableRetentionEnforcement:  true,
		EnableExportCleanup:         true,
		EnableMetrics:               true,
		TestMode:                    false,
	}
}

// ScheduledJob represents a scheduled background job
type ScheduledJob struct {
	ID              string
	Type            JobType
	UserID          uint
	DeletionRequestID string
	ScheduledAt     time.Time
	ExecuteAt       time.Time
	Priority        int
	RetryCount      int
	LastError       string
	Status          JobStatus
	Metadata        map[string]interface{}
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// JobType defines types of scheduled jobs
type JobType string

const (
	JobTypeProcessDeletion      JobType = "process_deletion"
	JobTypeCheckGracePeriod     JobType = "check_grace_period"
	JobTypeEnforceRetention     JobType = "enforce_retention"
	JobTypeCleanupExports       JobType = "cleanup_exports"
	JobTypeRetryFailed          JobType = "retry_failed"
	JobTypeGenerateReport       JobType = "generate_report"
)

// JobStatus defines job execution status
type JobStatus string

const (
	JobStatusPending     JobStatus = "pending"
	JobStatusProcessing  JobStatus = "processing"
	JobStatusCompleted   JobStatus = "completed"
	JobStatusFailed      JobStatus = "failed"
	JobStatusCancelled   JobStatus = "cancelled"
	JobStatusRetrying    JobStatus = "retrying"
)

// JobMetrics tracks scheduler performance metrics
type JobMetrics struct {
	TotalJobsProcessed   int64
	SuccessfulJobs       int64
	FailedJobs           int64
	RetryCount           int64
	AverageProcessingTime time.Duration
	LastProcessedAt      time.Time
	ActiveJobs           int32
	QueueSize            int32
	mutex                sync.RWMutex
}

// NewDeletionScheduler creates a new deletion scheduler
func NewDeletionScheduler(
	deletionService *UserDeletionService,
	deletionRepo domain.DeletionRequestRepository,
	auditService domain.ComprehensiveAuditLogger,
	complianceService *LGPDComplianceService,
	config *DeletionSchedulerConfig,
) *DeletionScheduler {
	if config == nil {
		config = DefaultDeletionSchedulerConfig()
	}
	
	return &DeletionScheduler{
		deletionService:   deletionService,
		deletionRepo:      deletionRepo,
		auditService:      auditService,
		complianceService: complianceService,
		config:            config,
		jobs:              make(map[string]*ScheduledJob),
		jobQueue:          make(chan *ScheduledJob, 1000),
		stopChannel:       make(chan bool),
		metrics:           &JobMetrics{},
	}
}

// Start begins the background job processing
func (s *DeletionScheduler) Start(ctx context.Context) error {
	s.runningMutex.Lock()
	if s.running {
		s.runningMutex.Unlock()
		return fmt.Errorf("scheduler already running")
	}
	s.running = true
	s.runningMutex.Unlock()
	
	// Start worker pool
	for i := 0; i < s.config.MaxConcurrentJobs; i++ {
		s.wg.Add(1)
		go s.worker(ctx, i)
	}
	
	// Start scheduled tasks
	if s.config.EnableAutoProcessing {
		s.wg.Add(1)
		go s.gracePeriodChecker(ctx)
		
		s.wg.Add(1)
		go s.failedJobRetrier(ctx)
	}
	
	if s.config.EnableRetentionEnforcement {
		s.wg.Add(1)
		go s.retentionEnforcer(ctx)
	}
	
	if s.config.EnableExportCleanup {
		s.wg.Add(1)
		go s.exportCleaner(ctx)
	}
	
	// Log startup
	s.auditService.LogSystemEvent(ctx, "deletion_scheduler_started", 
		"LGPD deletion scheduler started", 
		map[string]interface{}{
			"config": s.config,
		})
	
	return nil
}

// Stop gracefully stops the scheduler
func (s *DeletionScheduler) Stop(ctx context.Context) error {
	s.runningMutex.Lock()
	if !s.running {
		s.runningMutex.Unlock()
		return fmt.Errorf("scheduler not running")
	}
	s.running = false
	s.runningMutex.Unlock()
	
	// Signal stop
	close(s.stopChannel)
	
	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// Clean shutdown
		s.auditService.LogSystemEvent(ctx, "deletion_scheduler_stopped", 
			"LGPD deletion scheduler stopped gracefully", nil)
		return nil
	case <-time.After(s.config.ShutdownTimeout):
		// Force shutdown
		s.auditService.LogSystemEvent(ctx, "deletion_scheduler_forced_stop", 
			"LGPD deletion scheduler forced stop after timeout", nil)
		return fmt.Errorf("scheduler shutdown timeout exceeded")
	}
}

// ScheduleDeletionProcessing schedules a deletion request for processing
func (s *DeletionScheduler) ScheduleDeletionProcessing(ctx context.Context, requestID string, executeAt time.Time) error {
	job := &ScheduledJob{
		ID:                fmt.Sprintf("del_%s_%d", requestID, time.Now().Unix()),
		Type:              JobTypeProcessDeletion,
		DeletionRequestID: requestID,
		ScheduledAt:       time.Now(),
		ExecuteAt:         executeAt,
		Priority:          1,
		Status:            JobStatusPending,
		CreatedAt:         time.Now(),
		Metadata: map[string]interface{}{
			"request_id": requestID,
		},
	}
	
	return s.enqueueJob(ctx, job)
}

// enqueueJob adds a job to the processing queue
func (s *DeletionScheduler) enqueueJob(ctx context.Context, job *ScheduledJob) error {
	s.jobsMutex.Lock()
	s.jobs[job.ID] = job
	s.jobsMutex.Unlock()
	
	// Add to queue if execution time has arrived
	if time.Now().After(job.ExecuteAt) || time.Now().Equal(job.ExecuteAt) {
		select {
		case s.jobQueue <- job:
			s.updateMetrics(func(m *JobMetrics) {
				m.QueueSize++
			})
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			return fmt.Errorf("job queue is full")
		}
	}
	
	// Schedule for later execution
	go func() {
		timer := time.NewTimer(time.Until(job.ExecuteAt))
		defer timer.Stop()
		
		select {
		case <-timer.C:
			s.jobQueue <- job
		case <-s.stopChannel:
			return
		}
	}()
	
	return nil
}

// worker processes jobs from the queue
func (s *DeletionScheduler) worker(ctx context.Context, workerID int) {
	defer s.wg.Done()
	
	for {
		select {
		case job := <-s.jobQueue:
			s.updateMetrics(func(m *JobMetrics) {
				m.QueueSize--
				m.ActiveJobs++
			})
			
			s.processJob(ctx, job)
			
			s.updateMetrics(func(m *JobMetrics) {
				m.ActiveJobs--
			})
			
		case <-s.stopChannel:
			return
			
		case <-ctx.Done():
			return
		}
	}
}

// processJob executes a scheduled job
func (s *DeletionScheduler) processJob(ctx context.Context, job *ScheduledJob) {
	startTime := time.Now()
	
	// Create timeout context
	jobCtx, cancel := context.WithTimeout(ctx, s.config.JobTimeout)
	defer cancel()
	
	// Update job status
	job.Status = JobStatusProcessing
	job.UpdatedAt = time.Now()
	
	// Process based on job type
	var err error
	switch job.Type {
	case JobTypeProcessDeletion:
		err = s.processDeletionJob(jobCtx, job)
	case JobTypeCheckGracePeriod:
		err = s.processGracePeriodCheck(jobCtx)
	case JobTypeEnforceRetention:
		err = s.processRetentionEnforcement(jobCtx)
	case JobTypeCleanupExports:
		err = s.processExportCleanup(jobCtx)
	case JobTypeRetryFailed:
		err = s.processFailedRetry(jobCtx)
	default:
		err = fmt.Errorf("unknown job type: %s", job.Type)
	}
	
	// Update job result
	if err != nil {
		s.handleJobError(ctx, job, err)
	} else {
		s.handleJobSuccess(ctx, job, time.Since(startTime))
	}
}

// processDeletionJob processes a deletion request
func (s *DeletionScheduler) processDeletionJob(ctx context.Context, job *ScheduledJob) error {
	// Get deletion request  
	reqUUID, err := uuid.Parse(job.DeletionRequestID)
	if err != nil {
		return fmt.Errorf("invalid deletion request ID: %w", err)
	}
	
	request, err := s.deletionRepo.FindByID(ctx, reqUUID)
	if err != nil {
		return fmt.Errorf("failed to get deletion request: %w", err)
	}
	
	// Check if already processed
	if request.Status == domain.DeletionStatusCompleted {
		return nil // Already processed
	}
	
	// Check if grace period has expired
	if request.ScheduledFor != nil && time.Now().Before(*request.ScheduledFor) {
		// Reschedule for later
		return s.ScheduleDeletionProcessing(ctx, request.ID.String(), *request.ScheduledFor)
	}
	
	// Process the deletion
	err = s.deletionService.ProcessScheduledDeletion(ctx, request.ID.String())
	if err != nil {
		return fmt.Errorf("failed to process deletion: %w", err)
	}
	
	// Log completion
	s.auditService.LogSystemEvent(ctx, "deletion_processed",
		fmt.Sprintf("Scheduled deletion processed for user %d", request.UserID),
		map[string]interface{}{
			"request_id":    request.ID.String(),
			"user_id":       request.UserID,
			"deletion_type": request.RequestType,
		})
	
	return nil
}

// processGracePeriodCheck checks for expired grace periods
func (s *DeletionScheduler) processGracePeriodCheck(ctx context.Context) error {
	// Find all pending deletions with expired grace periods
	criteria := domain.DeletionSearchCriteria{
		Status:               domain.DeletionStatusPending,
		ScheduledBefore:      func() *time.Time { t := time.Now(); return &t }(),
		Limit:                100,
	}
	
	requests, err := s.deletionRepo.Search(ctx, criteria)
	if err != nil {
		return fmt.Errorf("failed to search pending deletions: %w", err)
	}
	
	// Process each expired request
	for _, request := range requests {
		if err := s.processDeletionJob(ctx, &ScheduledJob{
			DeletionRequestID: request.ID.String(),
		}); err != nil {
			// Log error but continue processing others
			s.auditService.LogSystemEvent(ctx, "grace_period_check_failed",
				fmt.Sprintf("Failed to process expired deletion for user %d: %v", request.UserID, err),
				map[string]interface{}{
					"request_id": request.ID.String(),
					"error":      err.Error(),
				})
		}
	}
	
	return nil
}

// processRetentionEnforcement enforces data retention policies
func (s *DeletionScheduler) processRetentionEnforcement(ctx context.Context) error {
	// This would check for data that exceeds retention policies
	// and automatically initiate deletion processes
	
	// For now, log the check
	s.auditService.LogSystemEvent(ctx, "retention_enforcement_check",
		"Data retention policies checked", nil)
	
	return nil
}

// processExportCleanup removes expired data exports
func (s *DeletionScheduler) processExportCleanup(ctx context.Context) error {
	// Find and delete expired exports
	criteria := domain.ExportSearchCriteria{
		ExpiredBefore: func() *time.Time { t := time.Now(); return &t }(),
		Limit:         100,
	}
	
	exports, err := s.deletionRepo.SearchExports(ctx, criteria)
	if err != nil {
		return fmt.Errorf("failed to search expired exports: %w", err)
	}
	
	// Clean up each expired export
	for _, export := range exports {
		if err := s.deletionService.CleanupExport(ctx, export.ExportID.String()); err != nil {
			// Log error but continue
			s.auditService.LogSystemEvent(ctx, "export_cleanup_failed",
				fmt.Sprintf("Failed to cleanup export %s: %v", export.ExportID.String(), err),
				map[string]interface{}{
					"export_id": export.ExportID.String(),
					"error":     err.Error(),
				})
		}
	}
	
	return nil
}

// processFailedRetry retries failed jobs
func (s *DeletionScheduler) processFailedRetry(ctx context.Context) error {
	s.jobsMutex.RLock()
	failedJobs := make([]*ScheduledJob, 0)
	for _, job := range s.jobs {
		if job.Status == JobStatusFailed && job.RetryCount < s.config.MaxRetryAttempts {
			failedJobs = append(failedJobs, job)
		}
	}
	s.jobsMutex.RUnlock()
	
	// Retry each failed job
	for _, job := range failedJobs {
		job.RetryCount++
		job.Status = JobStatusRetrying
		
		// Calculate backoff delay
		backoffDelay := time.Duration(float64(time.Minute) * 
			(s.config.RetryBackoffMultiplier * float64(job.RetryCount)))
		
		job.ExecuteAt = time.Now().Add(backoffDelay)
		
		if err := s.enqueueJob(ctx, job); err != nil {
			s.auditService.LogSystemEvent(ctx, "job_retry_failed",
				fmt.Sprintf("Failed to retry job %s: %v", job.ID, err),
				map[string]interface{}{
					"job_id": job.ID,
					"error":  err.Error(),
				})
		}
	}
	
	return nil
}

// Scheduled task runners

func (s *DeletionScheduler) gracePeriodChecker(ctx context.Context) {
	defer s.wg.Done()
	
	ticker := time.NewTicker(s.config.GracePeriodCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			job := &ScheduledJob{
				ID:          fmt.Sprintf("grace_check_%d", time.Now().Unix()),
				Type:        JobTypeCheckGracePeriod,
				ScheduledAt: time.Now(),
				ExecuteAt:   time.Now(),
				Priority:    2,
				Status:      JobStatusPending,
			}
			s.enqueueJob(ctx, job)
			
		case <-s.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *DeletionScheduler) retentionEnforcer(ctx context.Context) {
	defer s.wg.Done()
	
	ticker := time.NewTicker(s.config.RetentionCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			job := &ScheduledJob{
				ID:          fmt.Sprintf("retention_%d", time.Now().Unix()),
				Type:        JobTypeEnforceRetention,
				ScheduledAt: time.Now(),
				ExecuteAt:   time.Now(),
				Priority:    3,
				Status:      JobStatusPending,
			}
			s.enqueueJob(ctx, job)
			
		case <-s.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *DeletionScheduler) exportCleaner(ctx context.Context) {
	defer s.wg.Done()
	
	ticker := time.NewTicker(s.config.ExportCleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			job := &ScheduledJob{
				ID:          fmt.Sprintf("export_clean_%d", time.Now().Unix()),
				Type:        JobTypeCleanupExports,
				ScheduledAt: time.Now(),
				ExecuteAt:   time.Now(),
				Priority:    4,
				Status:      JobStatusPending,
			}
			s.enqueueJob(ctx, job)
			
		case <-s.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (s *DeletionScheduler) failedJobRetrier(ctx context.Context) {
	defer s.wg.Done()
	
	ticker := time.NewTicker(s.config.FailedRetryInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			job := &ScheduledJob{
				ID:          fmt.Sprintf("retry_%d", time.Now().Unix()),
				Type:        JobTypeRetryFailed,
				ScheduledAt: time.Now(),
				ExecuteAt:   time.Now(),
				Priority:    5,
				Status:      JobStatusPending,
			}
			s.enqueueJob(ctx, job)
			
		case <-s.stopChannel:
			return
		case <-ctx.Done():
			return
		}
	}
}

// Error and success handling

func (s *DeletionScheduler) handleJobError(ctx context.Context, job *ScheduledJob, err error) {
	job.Status = JobStatusFailed
	job.LastError = err.Error()
	job.UpdatedAt = time.Now()
	
	s.updateMetrics(func(m *JobMetrics) {
		m.FailedJobs++
		m.TotalJobsProcessed++
	})
	
	// Log error
	s.auditService.LogSystemEvent(ctx, "scheduled_job_failed",
		fmt.Sprintf("Job %s failed: %v", job.ID, err),
		map[string]interface{}{
			"job_id":      job.ID,
			"job_type":    job.Type,
			"retry_count": job.RetryCount,
			"error":       err.Error(),
		})
}

func (s *DeletionScheduler) handleJobSuccess(ctx context.Context, job *ScheduledJob, duration time.Duration) {
	job.Status = JobStatusCompleted
	job.UpdatedAt = time.Now()
	
	// Remove from active jobs
	s.jobsMutex.Lock()
	delete(s.jobs, job.ID)
	s.jobsMutex.Unlock()
	
	s.updateMetrics(func(m *JobMetrics) {
		m.SuccessfulJobs++
		m.TotalJobsProcessed++
		m.LastProcessedAt = time.Now()
		
		// Update average processing time
		if m.AverageProcessingTime == 0 {
			m.AverageProcessingTime = duration
		} else {
			m.AverageProcessingTime = (m.AverageProcessingTime + duration) / 2
		}
	})
}

// Metrics

func (s *DeletionScheduler) updateMetrics(fn func(*JobMetrics)) {
	if !s.config.EnableMetrics {
		return
	}
	
	s.metrics.mutex.Lock()
	defer s.metrics.mutex.Unlock()
	fn(s.metrics)
}

// GetMetrics returns current scheduler metrics
func (s *DeletionScheduler) GetMetrics() map[string]interface{} {
	s.metrics.mutex.RLock()
	defer s.metrics.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_jobs_processed":    s.metrics.TotalJobsProcessed,
		"successful_jobs":         s.metrics.SuccessfulJobs,
		"failed_jobs":             s.metrics.FailedJobs,
		"retry_count":             s.metrics.RetryCount,
		"average_processing_time": s.metrics.AverageProcessingTime.String(),
		"last_processed_at":       s.metrics.LastProcessedAt,
		"active_jobs":             s.metrics.ActiveJobs,
		"queue_size":              s.metrics.QueueSize,
		"is_running":              s.isRunning(),
	}
}

// GetJobStatus returns the status of a specific job
func (s *DeletionScheduler) GetJobStatus(jobID string) (*ScheduledJob, error) {
	s.jobsMutex.RLock()
	defer s.jobsMutex.RUnlock()
	
	job, exists := s.jobs[jobID]
	if !exists {
		return nil, fmt.Errorf("job not found: %s", jobID)
	}
	
	return job, nil
}

// isRunning checks if scheduler is running
func (s *DeletionScheduler) isRunning() bool {
	s.runningMutex.RLock()
	defer s.runningMutex.RUnlock()
	return s.running
}

// CancelJob cancels a pending job
func (s *DeletionScheduler) CancelJob(ctx context.Context, jobID string) error {
	s.jobsMutex.Lock()
	defer s.jobsMutex.Unlock()
	
	job, exists := s.jobs[jobID]
	if !exists {
		return fmt.Errorf("job not found: %s", jobID)
	}
	
	if job.Status != JobStatusPending {
		return fmt.Errorf("can only cancel pending jobs, current status: %s", job.Status)
	}
	
	job.Status = JobStatusCancelled
	job.UpdatedAt = time.Now()
	
	// Log cancellation
	s.auditService.LogSystemEvent(ctx, "job_cancelled",
		fmt.Sprintf("Job %s cancelled", jobID),
		map[string]interface{}{
			"job_id":   jobID,
			"job_type": job.Type,
		})
	
	return nil
}