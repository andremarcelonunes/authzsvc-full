package performance

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

// BenchmarkValidationService_ValidateRequest benchmarks the main validation pipeline
func BenchmarkValidationService_ValidateRequest(b *testing.B) {
	// Create validation service with optimized mocks
	securitySvc := createOptimizedSecurityMock()
	businessSvc := createOptimizedBusinessMock()
	rateLimitSvc := createOptimizedRateLimitMock()

	config := services.RequestValidationConfig{
		EnableCaching:     false, // Disable caching for pure validation benchmarks
		MaxValidationTime: 30 * time.Second,
		EnableMetrics:     false,
	}

	service := services.NewRequestValidationService(
		securitySvc,
		businessSvc,
		rateLimitSvc,
		nil,
		config,
	)

	// Test data
	request := map[string]interface{}{
		"email":    "test@example.com",
		"password": "SecurePassword123!",
		"name":     "John Doe",
		"phone":    "+1234567890",
	}

	validationCtx := &domain.ValidationContext{
		RequestID: "bench_test",
		Endpoint:  "/auth/register",
		Method:    "POST",
		IPAddress: "192.168.1.100",
		UserAgent: "BenchmarkAgent/1.0",
		Timestamp: time.Now(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := service.ValidateRequest(context.Background(), request, validationCtx)
		if err != nil {
			b.Fatalf("validation failed: %v", err)
		}
	}
}

// BenchmarkValidationService_ValidateFields benchmarks field validation performance
func BenchmarkValidationService_ValidateFields(b *testing.B) {
	service := createTestValidationService()

	fields := map[string]interface{}{
		"email":    "test@example.com",
		"password": "SecurePassword123!",
		"name":     "John Doe",
		"phone":    "+1234567890",
		"address":  "123 Main St, City, State 12345",
	}

	rules := []domain.ValidationRule{
		createEmailValidationRule(),
		createPasswordValidationRule(),
		createNameValidationRule(),
		createPhoneValidationRule(),
		createAddressValidationRule(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := service.ValidateFields(context.Background(), fields, rules)
		if err != nil {
			b.Fatalf("field validation failed: %v", err)
		}
	}
}

// BenchmarkValidationService_Security benchmarks security validation performance
func BenchmarkValidationService_Security(b *testing.B) {
	securitySvc := mocks.NewMockSecurityValidationService()
	securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
		// Simulate realistic security scanning
		time.Sleep(100 * time.Microsecond)
		return &domain.SecurityValidationResult{
			ThreatLevel: domain.ThreatNone,
			ThreatTypes: []domain.ThreatType{},
			Violations:  []domain.SecurityViolation{},
		}, nil
	}

	input := map[string]interface{}{
		"comment": "This is a normal comment with some text content",
		"data":    "Regular data that should pass security validation",
	}

	rules := []domain.SecurityConstraint{
		{
			XSSProtection:         true,
			SQLInjectionCheck:     true,
			ScriptInjectionCheck:  true,
			ThreatScanEnabled:     true,
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := securitySvc.ScanForThreats(context.Background(), input, rules)
		if err != nil {
			b.Fatalf("security validation failed: %v", err)
		}
	}
}

// TestValidationPerformanceUnderLoad tests validation performance under concurrent load
func TestValidationPerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	// Create validation service
	service := createTestValidationService()

	// Test parameters
	concurrency := 100
	requestsPerWorker := 100
	totalRequests := concurrency * requestsPerWorker

	// Metrics collection
	var (
		totalDuration time.Duration
		successCount  int
		errorCount    int
		mu            sync.Mutex
	)

	// Worker function
	worker := func(workerID int, wg *sync.WaitGroup) {
		defer wg.Done()

		for i := 0; i < requestsPerWorker; i++ {
			request := map[string]interface{}{
				"email":     fmt.Sprintf("user%d_%d@example.com", workerID, i),
				"password":  "SecurePassword123!",
				"worker_id": workerID,
				"request_id": i,
			}

			validationCtx := &domain.ValidationContext{
				RequestID: fmt.Sprintf("load_test_%d_%d", workerID, i),
				Endpoint:  "/auth/register",
				Method:    "POST",
				IPAddress: fmt.Sprintf("192.168.1.%d", 100+(workerID%155)),
				UserAgent: "LoadTestAgent/1.0",
				Timestamp: time.Now(),
			}

			start := time.Now()
			result, err := service.ValidateRequest(context.Background(), request, validationCtx)
			duration := time.Since(start)

			mu.Lock()
			totalDuration += duration
			if err != nil {
				errorCount++
			} else if result.IsValid {
				successCount++
			} else {
				errorCount++
			}
			mu.Unlock()
		}
	}

	// Start load test
	t.Logf("Starting load test: %d workers, %d requests each (%d total)", 
		concurrency, requestsPerWorker, totalRequests)

	start := time.Now()
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go worker(i, &wg)
	}

	wg.Wait()
	testDuration := time.Since(start)

	// Calculate metrics
	avgDuration := totalDuration / time.Duration(totalRequests)
	requestsPerSecond := float64(totalRequests) / testDuration.Seconds()

	// Performance assertions
	maxAvgDuration := 10 * time.Millisecond
	if avgDuration > maxAvgDuration {
		t.Errorf("average validation duration too high: %v (max: %v)", avgDuration, maxAvgDuration)
	}

	minRequestsPerSecond := 1000.0
	if requestsPerSecond < minRequestsPerSecond {
		t.Errorf("requests per second too low: %.2f (min: %.2f)", requestsPerSecond, minRequestsPerSecond)
	}

	errorRate := float64(errorCount) / float64(totalRequests)
	maxErrorRate := 0.01 // 1%
	if errorRate > maxErrorRate {
		t.Errorf("error rate too high: %.2f%% (max: %.2f%%)", errorRate*100, maxErrorRate*100)
	}

	// Report metrics
	t.Logf("Load test results:")
	t.Logf("  Total duration: %v", testDuration)
	t.Logf("  Average validation time: %v", avgDuration)
	t.Logf("  Requests per second: %.2f", requestsPerSecond)
	t.Logf("  Success rate: %.2f%% (%d/%d)", float64(successCount)*100/float64(totalRequests), successCount, totalRequests)
	t.Logf("  Error rate: %.2f%% (%d/%d)", errorRate*100, errorCount, totalRequests)
}

// TestMemoryUsageUnderLoad tests memory usage during validation load
func TestMemoryUsageUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in short mode")
	}

	service := createTestValidationService()

	// Force garbage collection and get baseline
	runtime.GC()
	runtime.GC() // Run twice to ensure complete cleanup
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Run validation load
	iterations := 10000
	for i := 0; i < iterations; i++ {
		request := map[string]interface{}{
			"email":    fmt.Sprintf("user%d@example.com", i),
			"password": "SecurePassword123!",
			"data":     strings.Repeat("x", 1000), // 1KB of data per request
		}

		validationCtx := &domain.ValidationContext{
			RequestID: fmt.Sprintf("memory_test_%d", i),
			Endpoint:  "/auth/register",
			Method:    "POST",
			IPAddress: "192.168.1.100",
			UserAgent: "MemoryTestAgent/1.0",
			Timestamp: time.Now(),
		}

		_, err := service.ValidateRequest(context.Background(), request, validationCtx)
		if err != nil {
			t.Fatalf("validation failed at iteration %d: %v", i, err)
		}

		// Force GC every 1000 iterations to check for leaks
		if i%1000 == 999 {
			runtime.GC()
		}
	}

	// Final garbage collection and memory check
	runtime.GC()
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	// Calculate memory usage
	allocatedMemory := m2.Alloc - m1.Alloc
	totalAllocations := m2.TotalAlloc - m1.TotalAlloc

	// Memory usage assertions
	maxMemoryIncrease := uint64(50 * 1024 * 1024) // 50MB
	if allocatedMemory > maxMemoryIncrease {
		t.Errorf("memory usage increased too much: %d bytes (max: %d bytes)", allocatedMemory, maxMemoryIncrease)
	}

	// Report memory metrics
	t.Logf("Memory usage analysis:")
	t.Logf("  Iterations: %d", iterations)
	t.Logf("  Memory increase: %d bytes (%.2f MB)", allocatedMemory, float64(allocatedMemory)/(1024*1024))
	t.Logf("  Total allocations: %d bytes (%.2f MB)", totalAllocations, float64(totalAllocations)/(1024*1024))
	t.Logf("  Avg per request: %.2f bytes", float64(totalAllocations)/float64(iterations))
	t.Logf("  GC runs: %d", m2.NumGC-m1.NumGC)
}

// TestValidationTimeoutHandling tests validation behavior under timeout conditions
func TestValidationTimeoutHandling(t *testing.T) {
	// Create a slow validation service
	securitySvc := mocks.NewMockSecurityValidationService()
	securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
		// Simulate slow security scanning
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(200 * time.Millisecond):
			return &domain.SecurityValidationResult{ThreatLevel: domain.ThreatNone}, nil
		}
	}

	businessSvc := createOptimizedBusinessMock()
	rateLimitSvc := createOptimizedRateLimitMock()

	config := services.RequestValidationConfig{
		EnableCaching:     false,
		MaxValidationTime: 100 * time.Millisecond, // Short timeout
		EnableMetrics:     false,
	}

	service := services.NewRequestValidationService(
		securitySvc,
		businessSvc,
		rateLimitSvc,
		nil,
		config,
	)

	request := map[string]interface{}{
		"data": "test data",
	}

	validationCtx := &domain.ValidationContext{
		RequestID: "timeout_test",
		Endpoint:  "/api/test",
		Method:    "POST",
		IPAddress: "192.168.1.100",
		Timestamp: time.Now(),
	}

	start := time.Now()
	_, err := service.ValidateRequest(context.Background(), request, validationCtx)
	duration := time.Since(start)

	// Should fail with timeout error
	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	// Should not take much longer than the timeout
	maxDuration := 150 * time.Millisecond
	if duration > maxDuration {
		t.Errorf("validation took too long: %v (max: %v)", duration, maxDuration)
	}

	t.Logf("Timeout test: duration=%v, error=%v", duration, err)
}

// TestConcurrentValidationStability tests validation stability under concurrent access
func TestConcurrentValidationStability(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stability test in short mode")
	}

	service := createTestValidationService()

	// Test parameters
	concurrency := 50
	duration := 10 * time.Second
	
	var (
		successCount int64
		errorCount   int64
		mu           sync.RWMutex
		stopChan     = make(chan struct{})
	)

	// Worker function
	worker := func(workerID int) {
		requestCount := 0
		for {
			select {
			case <-stopChan:
				return
			default:
				request := map[string]interface{}{
					"email":      fmt.Sprintf("worker%d_%d@example.com", workerID, requestCount),
					"password":   "SecurePassword123!",
					"timestamp":  time.Now().Unix(),
					"worker_id":  workerID,
					"request_num": requestCount,
				}

				validationCtx := &domain.ValidationContext{
					RequestID: fmt.Sprintf("stability_%d_%d", workerID, requestCount),
					Endpoint:  "/auth/register",
					Method:    "POST",
					IPAddress: fmt.Sprintf("192.168.1.%d", 100+(workerID%155)),
					UserAgent: "StabilityTestAgent/1.0",
					Timestamp: time.Now(),
				}

				result, err := service.ValidateRequest(context.Background(), request, validationCtx)

				mu.Lock()
				if err != nil || !result.IsValid {
					errorCount++
				} else {
					successCount++
				}
				mu.Unlock()

				requestCount++
				time.Sleep(10 * time.Millisecond) // Small delay to avoid overwhelming
			}
		}
	}

	// Start workers
	t.Logf("Starting stability test: %d workers for %v", concurrency, duration)
	for i := 0; i < concurrency; i++ {
		go worker(i)
	}

	// Run for specified duration
	time.Sleep(duration)
	close(stopChan)

	// Give workers time to finish current requests
	time.Sleep(100 * time.Millisecond)

	// Calculate results
	mu.RLock()
	totalRequests := successCount + errorCount
	successRate := float64(successCount) / float64(totalRequests)
	requestsPerSecond := float64(totalRequests) / duration.Seconds()
	mu.RUnlock()

	// Stability assertions
	minSuccessRate := 0.95 // 95%
	if successRate < minSuccessRate {
		t.Errorf("success rate too low: %.2f%% (min: %.2f%%)", successRate*100, minSuccessRate*100)
	}

	minRequestsPerSecond := 100.0
	if requestsPerSecond < minRequestsPerSecond {
		t.Errorf("requests per second too low: %.2f (min: %.2f)", requestsPerSecond, minRequestsPerSecond)
	}

	// Report stability metrics
	t.Logf("Stability test results:")
	t.Logf("  Duration: %v", duration)
	t.Logf("  Total requests: %d", totalRequests)
	t.Logf("  Success rate: %.2f%% (%d/%d)", successRate*100, successCount, totalRequests)
	t.Logf("  Requests per second: %.2f", requestsPerSecond)
	t.Logf("  Concurrency: %d workers", concurrency)
}

// Helper functions

func createTestValidationService() domain.RequestValidationService {
	securitySvc := createOptimizedSecurityMock()
	businessSvc := createOptimizedBusinessMock()
	rateLimitSvc := createOptimizedRateLimitMock()

	config := services.RequestValidationConfig{
		EnableCaching:     false,
		MaxValidationTime: 30 * time.Second,
		EnableMetrics:     false,
	}

	return services.NewRequestValidationService(
		securitySvc,
		businessSvc,
		rateLimitSvc,
		nil,
		config,
	)
}

func createOptimizedSecurityMock() *mocks.MockSecurityValidationService {
	mock := mocks.NewMockSecurityValidationService()
	mock.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
		// Fast security validation for performance testing
		return &domain.SecurityValidationResult{
			ThreatLevel: domain.ThreatNone,
			ThreatTypes: []domain.ThreatType{},
			Violations:  []domain.SecurityViolation{},
		}, nil
	}
	return mock
}

func createOptimizedBusinessMock() *mocks.MockBusinessValidationService {
	mock := mocks.NewMockBusinessValidationService()
	mock.ValidateBusinessRulesFunc = func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
		// Fast business validation for performance testing
		return &domain.ValidationResult{
			IsValid:      true,
			Passed:       true,
			Errors:       []domain.ValidationError{},
			Warnings:     []domain.ValidationError{},
			RulesApplied: 1,
		}, nil
	}
	return mock
}

func createOptimizedRateLimitMock() *mocks.MockRateLimitValidationService {
	mock := mocks.NewMockRateLimitValidationService()
	mock.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
		// Fast rate limit check for performance testing
		return &domain.RateLimitResult{
			Allowed:      true,
			CurrentCount: 1,
			Limit:        limit,
			Remaining:    limit - 1,
		}, nil
	}
	return mock
}

// Validation rule creators for benchmarks

func createEmailValidationRule() domain.ValidationRule {
	return domain.ValidationRule{
		ID:        "email_rule",
		FieldName: "email",
		IsActive:  true,
		Constraint: &domain.FieldConstraint{
			DataType:  "string",
			MinLength: intPtr(5),
			MaxLength: intPtr(100),
			Pattern:   `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
		},
	}
}

func createPasswordValidationRule() domain.ValidationRule {
	return domain.ValidationRule{
		ID:        "password_rule",
		FieldName: "password",
		IsActive:  true,
		Constraint: &domain.FieldConstraint{
			DataType:  "string",
			MinLength: intPtr(8),
			MaxLength: intPtr(128),
		},
	}
}

func createNameValidationRule() domain.ValidationRule {
	return domain.ValidationRule{
		ID:        "name_rule",
		FieldName: "name",
		IsActive:  true,
		Constraint: &domain.FieldConstraint{
			DataType:  "string",
			MinLength: intPtr(2),
			MaxLength: intPtr(50),
		},
	}
}

func createPhoneValidationRule() domain.ValidationRule {
	return domain.ValidationRule{
		ID:        "phone_rule",
		FieldName: "phone",
		IsActive:  true,
		Constraint: &domain.FieldConstraint{
			DataType: "string",
			Pattern:  `^\+[1-9]\d{1,14}$`,
		},
	}
}

func createAddressValidationRule() domain.ValidationRule {
	return domain.ValidationRule{
		ID:        "address_rule",
		FieldName: "address",
		IsActive:  true,
		Constraint: &domain.FieldConstraint{
			DataType:  "string",
			MinLength: intPtr(10),
			MaxLength: intPtr(200),
		},
	}
}

func intPtr(i int) *int {
	return &i
}