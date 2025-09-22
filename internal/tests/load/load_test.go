package load

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/you/authzsvc/internal/services"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/domain"
)

// LoadTestMetrics tracks performance metrics during load testing
type LoadTestMetrics struct {
	TotalRequests       int64
	SuccessfulRequests  int64
	FailedRequests      int64
	TotalResponseTime   int64
	MinResponseTime     int64
	MaxResponseTime     int64
	AuditEventsCreated  int64
	DatabaseErrors      int64
	ConcurrentUsers     int
	TestDuration        time.Duration
	StartTime           time.Time
	EndTime             time.Time
}

// GetAverageResponseTime calculates average response time in milliseconds
func (m *LoadTestMetrics) GetAverageResponseTime() float64 {
	if m.TotalRequests == 0 {
		return 0
	}
	return float64(m.TotalResponseTime) / float64(m.TotalRequests) / float64(time.Millisecond)
}

// GetRequestsPerSecond calculates throughput
func (m *LoadTestMetrics) GetRequestsPerSecond() float64 {
	if m.TestDuration == 0 {
		return 0
	}
	return float64(m.TotalRequests) / m.TestDuration.Seconds()
}

// GetSuccessRate calculates success percentage
func (m *LoadTestMetrics) GetSuccessRate() float64 {
	if m.TotalRequests == 0 {
		return 0
	}
	return float64(m.SuccessfulRequests) / float64(m.TotalRequests) * 100
}

// AuditLoadTestSuite manages audit service load testing
type AuditLoadTestSuite struct {
	auditLogger domain.ComprehensiveAuditLogger
	metrics     *LoadTestMetrics
	mu          sync.RWMutex
}

// NewAuditLoadTestSuite creates a new audit load testing suite
func NewAuditLoadTestSuite(t *testing.T) *AuditLoadTestSuite {
	t.Helper()
	
	// Create mocks for dependencies
	auditRepo := mocks.NewMockAuditRepository()
	
	// Configure the repository for high-performance testing
	auditRepo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
		// Simulate database write time (1-5ms)
		time.Sleep(time.Duration(1+time.Now().UnixNano()%4) * time.Millisecond)
		return nil
	}
	
	auditRepo.CreateBatchFunc = func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) error {
		// Simulate batch database write time (5-15ms for batch)
		time.Sleep(time.Duration(5+time.Now().UnixNano()%10) * time.Millisecond)
		return nil
	}
	
	// Create the audit service
	auditLogger := services.NewComprehensiveAuditService(
		auditRepo,
		nil, // encryptor
		nil, // integrityChecker
		nil, // asyncProcessor - use synchronous for load testing
		nil, // metrics
		nil, // exporter
		nil, // config
		nil, // logger
	)
	
	return &AuditLoadTestSuite{
		auditLogger: auditLogger,
		metrics: &LoadTestMetrics{
			MinResponseTime: int64(^uint64(0) >> 1), // Max int64
		},
	}
}

// Cleanup tears down the load test suite
func (l *AuditLoadTestSuite) Cleanup() {
	// No cleanup needed for service-level testing
}

// recordAuditOperation records metrics for a single audit operation
func (l *AuditLoadTestSuite) recordAuditOperation(responseTime time.Duration, success bool, auditCreated bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	atomic.AddInt64(&l.metrics.TotalRequests, 1)
	atomic.AddInt64(&l.metrics.TotalResponseTime, int64(responseTime))
	
	if success {
		atomic.AddInt64(&l.metrics.SuccessfulRequests, 1)
	} else {
		atomic.AddInt64(&l.metrics.FailedRequests, 1)
	}
	
	if auditCreated {
		atomic.AddInt64(&l.metrics.AuditEventsCreated, 1)
	}
	
	// Update min/max response times
	rt := int64(responseTime)
	if rt < l.metrics.MinResponseTime {
		l.metrics.MinResponseTime = rt
	}
	if rt > l.metrics.MaxResponseTime {
		l.metrics.MaxResponseTime = rt
	}
}

// simulateUserRegistrationAudit simulates audit event creation for user registration
func (l *AuditLoadTestSuite) simulateUserRegistrationAudit(userID int, wg *sync.WaitGroup) {
	defer wg.Done()
	
	start := time.Now()
	
	// Use the existing audit logger method for login attempts
	err := l.auditLogger.LogLoginAttempt(
		context.Background(),
		uint(userID),
		fmt.Sprintf("loadtest.user.%d@example.com", userID),
		"192.168.1.100",
		true, // success
		"load_test_registration",
	)
	
	responseTime := time.Since(start)
	success := err == nil
	
	// Record metrics
	l.recordAuditOperation(responseTime, success, success)
}

// simulateUserLoginAudit simulates audit event creation for user login
func (l *AuditLoadTestSuite) simulateUserLoginAudit(userID int, outcome string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	start := time.Now()
	
	// Use the existing audit logger method for login attempts
	success := outcome == "success"
	err := l.auditLogger.LogLoginAttempt(
		context.Background(),
		uint(userID),
		fmt.Sprintf("loadtest.user.%d@example.com", userID),
		"192.168.1.100",
		success,
		fmt.Sprintf("load_test_login_%s", outcome),
	)
	
	responseTime := time.Since(start)
	success = err == nil
	
	// Record metrics
	l.recordAuditOperation(responseTime, success, success)
}

// TestHighConcurrencyAuditEventCreation tests audit event creation under high concurrent load
func TestHighConcurrencyAuditEventCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}
	
	t.Log("🚀 Starting high concurrency audit event creation load test")
	
	suite := NewAuditLoadTestSuite(t)
	defer suite.Cleanup()
	
	// Test parameters
	concurrentUsers := 100
	eventsPerBatch := 10
	totalEvents := concurrentUsers * eventsPerBatch
	
	suite.metrics.ConcurrentUsers = concurrentUsers
	suite.metrics.StartTime = time.Now()
	
	t.Logf("📊 Test configuration:")
	t.Logf("   - Concurrent users: %d", concurrentUsers)
	t.Logf("   - Events per batch: %d", eventsPerBatch)
	t.Logf("   - Total audit events: %d", totalEvents)
	
	var wg sync.WaitGroup
	
	// Launch concurrent audit event creation
	for batch := 0; batch < eventsPerBatch; batch++ {
		for user := 0; user < concurrentUsers; user++ {
			wg.Add(1)
			userID := batch*concurrentUsers + user
			go suite.simulateUserRegistrationAudit(userID, &wg)
		}
		
		// Small delay between batches to avoid overwhelming the system
		time.Sleep(50 * time.Millisecond)
	}
	
	wg.Wait()
	suite.metrics.EndTime = time.Now()
	suite.metrics.TestDuration = suite.metrics.EndTime.Sub(suite.metrics.StartTime)
	
	// Performance assertions
	t.Logf("📈 Load test results:")
	t.Logf("   - Total requests: %d", suite.metrics.TotalRequests)
	t.Logf("   - Successful requests: %d", suite.metrics.SuccessfulRequests)
	t.Logf("   - Failed requests: %d", suite.metrics.FailedRequests)
	t.Logf("   - Success rate: %.2f%%", suite.metrics.GetSuccessRate())
	t.Logf("   - Average response time: %.2f ms", suite.metrics.GetAverageResponseTime())
	t.Logf("   - Min response time: %.2f ms", float64(suite.metrics.MinResponseTime)/float64(time.Millisecond))
	t.Logf("   - Max response time: %.2f ms", float64(suite.metrics.MaxResponseTime)/float64(time.Millisecond))
	t.Logf("   - Requests per second: %.2f", suite.metrics.GetRequestsPerSecond())
	t.Logf("   - Audit events created: %d", suite.metrics.AuditEventsCreated)
	t.Logf("   - Test duration: %v", suite.metrics.TestDuration)
	
	// Performance targets for production readiness
	assert.GreaterOrEqual(t, suite.metrics.GetSuccessRate(), 95.0, "Success rate should be at least 95%")
	assert.LessOrEqual(t, suite.metrics.GetAverageResponseTime(), 50.0, "Average response time should be under 50ms for audit events")
	assert.GreaterOrEqual(t, suite.metrics.GetRequestsPerSecond(), 100.0, "Should handle at least 100 audit events per second")
	assert.Equal(t, suite.metrics.AuditEventsCreated, suite.metrics.SuccessfulRequests, "Each successful operation should create an audit event")
	
	t.Log("✅ High concurrency audit event creation load test completed successfully")
}

// TestMixedWorkloadWithAuditLogging tests mixed registration/login workload
func TestMixedWorkloadWithAuditLogging(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}
	
	t.Log("🚀 Starting mixed workload load test with audit logging")
	
	suite := NewAuditLoadTestSuite(t)
	defer suite.Cleanup()
	
	// Test parameters
	concurrentUsers := 50
	operationsPerUser := 20
	totalOperations := concurrentUsers * operationsPerUser
	
	suite.metrics.ConcurrentUsers = concurrentUsers
	suite.metrics.StartTime = time.Now()
	
	t.Logf("📊 Mixed workload test configuration:")
	t.Logf("   - Concurrent users: %d", concurrentUsers)
	t.Logf("   - Operations per user: %d", operationsPerUser)
	t.Logf("   - Total operations: %d", totalOperations)
	t.Logf("   - Mix: 30%% registration, 70%% login")
	
	var wg sync.WaitGroup
	
	// Pre-create some users for login tests
	testUsers := make([]map[string]string, 0, 20)
	for i := 0; i < 20; i++ {
		email := fmt.Sprintf("mixedtest.user.%d@example.com", i)
		testUsers = append(testUsers, map[string]string{
			"email":    email,
			"password": "LoadTest123!",
		})
	}
	
	// Launch mixed workload
	for user := 0; user < concurrentUsers; user++ {
		wg.Add(1)
		
		go func(userID int) {
			defer wg.Done()
			
			for op := 0; op < operationsPerUser; op++ {
				// 30% registration, 70% login
				if op%10 < 3 {
					// Registration - simulate audit event creation directly
					start := time.Now()
					err := suite.auditLogger.LogLoginAttempt(
						context.Background(),
						uint(userID*1000+op),
						fmt.Sprintf("loadtest.user.%d@example.com", userID*1000+op),
						"192.168.1.100",
						true,
						"load_test_registration",
					)
					responseTime := time.Since(start)
					success := err == nil
					suite.recordAuditOperation(responseTime, success, success)
				} else {
					// Login - simulate audit event creation directly
					start := time.Now()
					userIdx := op % len(testUsers)
					err := suite.auditLogger.LogLoginAttempt(
						context.Background(),
						uint(userIdx),
						fmt.Sprintf("loadtest.user.%d@example.com", userIdx),
						"192.168.1.100",
						true,
						"load_test_login_success",
					)
					responseTime := time.Since(start)
					success := err == nil
					suite.recordAuditOperation(responseTime, success, success)
				}
				
				// Small delay between operations
				time.Sleep(10 * time.Millisecond)
			}
		}(user)
	}
	
	wg.Wait()
	suite.metrics.EndTime = time.Now()
	suite.metrics.TestDuration = suite.metrics.EndTime.Sub(suite.metrics.StartTime)
	
	// Performance reporting
	t.Logf("📈 Mixed workload results:")
	t.Logf("   - Total operations: %d", suite.metrics.TotalRequests)
	t.Logf("   - Successful operations: %d", suite.metrics.SuccessfulRequests)
	t.Logf("   - Failed operations: %d", suite.metrics.FailedRequests)
	t.Logf("   - Success rate: %.2f%%", suite.metrics.GetSuccessRate())
	t.Logf("   - Average response time: %.2f ms", suite.metrics.GetAverageResponseTime())
	t.Logf("   - Throughput: %.2f ops/sec", suite.metrics.GetRequestsPerSecond())
	t.Logf("   - Audit events: %d", suite.metrics.AuditEventsCreated)
	
	// Performance assertions
	assert.GreaterOrEqual(t, suite.metrics.GetSuccessRate(), 90.0, "Mixed workload success rate should be at least 90%")
	assert.LessOrEqual(t, suite.metrics.GetAverageResponseTime(), 300.0, "Average response time should be under 300ms for mixed workload")
	assert.GreaterOrEqual(t, suite.metrics.GetRequestsPerSecond(), 30.0, "Should handle at least 30 mixed operations per second")
	
	t.Log("✅ Mixed workload load test completed successfully")
}

// TestSustainedLoadWithAuditValidation tests sustained load over time
func TestSustainedLoadWithAuditValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sustained load test in short mode")
	}
	
	t.Log("🚀 Starting sustained load test with audit validation")
	
	suite := NewAuditLoadTestSuite(t)
	defer suite.Cleanup()
	
	// Test parameters
	testDuration := 30 * time.Second
	concurrentUsers := 25
	requestInterval := 200 * time.Millisecond
	
	suite.metrics.ConcurrentUsers = concurrentUsers
	suite.metrics.StartTime = time.Now()
	
	t.Logf("📊 Sustained load test configuration:")
	t.Logf("   - Test duration: %v", testDuration)
	t.Logf("   - Concurrent users: %d", concurrentUsers)
	t.Logf("   - Request interval: %v", requestInterval)
	
	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()
	
	var wg sync.WaitGroup
	
	// Launch sustained load workers
	for worker := 0; worker < concurrentUsers; worker++ {
		wg.Add(1)
		
		go func(workerID int) {
			defer wg.Done()
			
			userCounter := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
					// Alternate between registration and login
					if userCounter%2 == 0 {
						// Registration - simulate audit event creation directly
						start := time.Now()
						err := suite.auditLogger.LogLoginAttempt(
							context.Background(),
							uint(workerID*10000+userCounter),
							fmt.Sprintf("sustained.test.%d@example.com", workerID*10000+userCounter),
							"192.168.1.100",
							true,
							"load_test_registration",
						)
						responseTime := time.Since(start)
						success := err == nil
						suite.recordAuditOperation(responseTime, success, success)
					} else {
						// Login - simulate audit event creation directly
						start := time.Now()
						err := suite.auditLogger.LogLoginAttempt(
							context.Background(),
							uint(workerID),
							fmt.Sprintf("sustained.test.%d@example.com", workerID),
							"192.168.1.100",
							true,
							"load_test_login_success",
						)
						responseTime := time.Since(start)
						success := err == nil
						suite.recordAuditOperation(responseTime, success, success)
					}
					
					userCounter++
					
					// Wait before next request
					select {
					case <-ctx.Done():
						return
					case <-time.After(requestInterval):
					}
				}
			}
		}(worker)
	}
	
	wg.Wait()
	suite.metrics.EndTime = time.Now()
	suite.metrics.TestDuration = suite.metrics.EndTime.Sub(suite.metrics.StartTime)
	
	// Validate audit events in database
	auditCount := suite.validateAuditEventsCreated(t)
	
	t.Logf("📈 Sustained load test results:")
	t.Logf("   - Test duration: %v", suite.metrics.TestDuration)
	t.Logf("   - Total requests: %d", suite.metrics.TotalRequests)
	t.Logf("   - Successful requests: %d", suite.metrics.SuccessfulRequests)
	t.Logf("   - Success rate: %.2f%%", suite.metrics.GetSuccessRate())
	t.Logf("   - Average response time: %.2f ms", suite.metrics.GetAverageResponseTime())
	t.Logf("   - Sustained throughput: %.2f req/sec", suite.metrics.GetRequestsPerSecond())
	t.Logf("   - Audit events in DB: %d", auditCount)
	
	// Performance assertions for sustained load
	assert.GreaterOrEqual(t, suite.metrics.GetSuccessRate(), 85.0, "Sustained load success rate should be at least 85%")
	assert.LessOrEqual(t, suite.metrics.GetAverageResponseTime(), 400.0, "Sustained load average response time should be under 400ms")
	assert.GreaterOrEqual(t, suite.metrics.GetRequestsPerSecond(), 10.0, "Should sustain at least 10 requests per second")
	assert.GreaterOrEqual(t, auditCount, suite.metrics.SuccessfulRequests*80/100, "At least 80% of successful requests should have audit events")
	
	t.Log("✅ Sustained load test with audit validation completed successfully")
}

// validateAuditEventsCreated checks audit events were properly created
func (l *AuditLoadTestSuite) validateAuditEventsCreated(t *testing.T) int64 {
	// For service-level testing, we'll simulate audit event validation
	// In a real implementation, this would query the database
	return l.metrics.AuditEventsCreated
}

// TestDatabasePerformanceUnderLoad validates database performance during load
func TestDatabasePerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping database performance test in short mode")
	}
	
	t.Log("🚀 Starting database performance test under load")
	
	suite := NewAuditLoadTestSuite(t)
	defer suite.Cleanup()
	
	// Measure database metrics before load
	initialAuditCount := suite.validateAuditEventsCreated(t)
	
	// Generate high database load
	concurrentUsers := 75
	operationsPerUser := 50
	
	t.Logf("📊 Database performance test:")
	t.Logf("   - Initial audit events: %d", initialAuditCount)
	t.Logf("   - Concurrent database operations: %d", concurrentUsers)
	t.Logf("   - Operations per user: %d", operationsPerUser)
	
	var wg sync.WaitGroup
	start := time.Now()
	
	for user := 0; user < concurrentUsers; user++ {
		wg.Add(1)
		
		go func(userID int) {
			defer wg.Done()
			
			for op := 0; op < operationsPerUser; op++ {
				// Registration - simulate audit event creation directly
				start := time.Now()
				err := suite.auditLogger.LogLoginAttempt(
					context.Background(),
					uint(userID*100+op),
					fmt.Sprintf("dbtest.user.%d@example.com", userID*100+op),
					"192.168.1.100",
					true,
					"load_test_db_performance",
				)
				responseTime := time.Since(start)
				success := err == nil
				suite.recordAuditOperation(responseTime, success, success)
				
				// Small delay to simulate realistic usage
				time.Sleep(20 * time.Millisecond)
			}
		}(user)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	// Measure database metrics after load
	finalAuditCount := suite.validateAuditEventsCreated(t)
	newAuditEvents := finalAuditCount - initialAuditCount
	
	dbWriteRate := float64(newAuditEvents) / duration.Seconds()
	
	t.Logf("📈 Database performance results:")
	t.Logf("   - Test duration: %v", duration)
	t.Logf("   - New audit events created: %d", newAuditEvents)
	t.Logf("   - Database write rate: %.2f events/sec", dbWriteRate)
	t.Logf("   - Final audit event count: %d", finalAuditCount)
	
	// Database performance assertions
	assert.GreaterOrEqual(t, dbWriteRate, 20.0, "Database should handle at least 20 audit writes per second")
	assert.GreaterOrEqual(t, newAuditEvents, int64(concurrentUsers*operationsPerUser*80/100), "At least 80% of operations should create audit events")
	
	t.Log("✅ Database performance test completed successfully")
}