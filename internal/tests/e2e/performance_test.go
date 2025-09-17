package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// E2EPerformanceHelper provides utilities for measuring and validating performance
type E2EPerformanceHelper struct {
	t         *testing.T
	server    *TestServer
	startTime time.Time
	metrics   []PerformanceMeasurement
}

// PerformanceMeasurement represents a single performance measurement
type PerformanceMeasurement struct {
	Name        string
	Duration    time.Duration
	Endpoint    string
	StatusCode  int
	Success     bool
	Timestamp   time.Time
}

// NewE2EPerformanceHelper creates a new performance test helper
func NewE2EPerformanceHelper(t *testing.T, server *TestServer) *E2EPerformanceHelper {
	t.Helper()
	return &E2EPerformanceHelper{
		t:       t,
		server:  server,
		metrics: make([]PerformanceMeasurement, 0),
	}
}

// MeasureEndpoint measures the performance of an HTTP endpoint
func (p *E2EPerformanceHelper) MeasureEndpoint(name, method, path string, headers map[string]string) time.Duration {
	p.t.Helper()

	start := time.Now()

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, p.server.URL(path), nil)
	if err != nil {
		p.t.Fatalf("Failed to create request for %s: %v", name, err)
	}

	// Add headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Perform request
	resp, err := p.server.DoRequest(req)
	duration := time.Since(start)

	// Record measurement
	measurement := PerformanceMeasurement{
		Name:       name,
		Duration:   duration,
		Endpoint:   path,
		StatusCode: 0,
		Success:    err == nil,
		Timestamp:  start,
	}

	if resp != nil {
		measurement.StatusCode = resp.StatusCode
		resp.Body.Close()
	}

	p.metrics = append(p.metrics, measurement)

	if err != nil {
		p.t.Errorf("Request failed for %s: %v", name, err)
		return duration
	}

	p.t.Logf("Performance [%s]: %v (%d)", name, duration, measurement.StatusCode)
	return duration
}

// AssertUnder100ms validates that the last measurement is under 100ms
func (p *E2EPerformanceHelper) AssertUnder100ms() {
	p.t.Helper()

	if len(p.metrics) == 0 {
		p.t.Fatal("No performance measurements available")
	}

	last := p.metrics[len(p.metrics)-1]
	if last.Duration > 100*time.Millisecond {
		p.t.Errorf("Performance requirement failed: %s took %v (exceeds 100ms target)",
			last.Name, last.Duration)
	}
}

// AssertUnder50ms validates that the last measurement is under 50ms
func (p *E2EPerformanceHelper) AssertUnder50ms() {
	p.t.Helper()

	if len(p.metrics) == 0 {
		p.t.Fatal("No performance measurements available")
	}

	last := p.metrics[len(p.metrics)-1]
	if last.Duration > 50*time.Millisecond {
		p.t.Errorf("Critical performance requirement failed: %s took %v (exceeds 50ms target)",
			last.Name, last.Duration)
	}
}

// ValidateAllMeasurements checks all measurements against performance requirements
func (p *E2EPerformanceHelper) ValidateAllMeasurements() {
	p.t.Helper()

	var failures []string
	var totalDuration time.Duration
	successCount := 0

	for _, measurement := range p.metrics {
		totalDuration += measurement.Duration

		if measurement.Success {
			successCount++
		}

		// CB-176 Performance requirements
		if measurement.Duration > 100*time.Millisecond {
			failures = append(failures, 
				fmt.Sprintf("%s: %v exceeds 100ms", measurement.Name, measurement.Duration))
		}
	}

	if len(failures) > 0 {
		p.t.Errorf("Performance failures detected:\n%s", failures)
	}

	// Report summary
	if len(p.metrics) > 0 {
		avg := totalDuration / time.Duration(len(p.metrics))
		p.t.Logf("Performance Summary:")
		p.t.Logf("  Total measurements: %d", len(p.metrics))
		p.t.Logf("  Successful requests: %d", successCount)
		p.t.Logf("  Average duration: %v", avg)
		p.t.Logf("  Failures: %d", len(failures))
	}
}

// BenchmarkEndpoint performs repeated measurements of an endpoint
func (p *E2EPerformanceHelper) BenchmarkEndpoint(name, method, path string, iterations int, headers map[string]string) []time.Duration {
	p.t.Helper()

	durations := make([]time.Duration, 0, iterations)

	for i := 0; i < iterations; i++ {
		duration := p.MeasureEndpoint(
			fmt.Sprintf("%s_iteration_%d", name, i+1),
			method, path, headers)
		durations = append(durations, duration)
	}

	return durations
}

// AnalyzeBenchmark analyzes benchmark results and provides statistics
func (p *E2EPerformanceHelper) AnalyzeBenchmark(durations []time.Duration) BenchmarkAnalysis {
	p.t.Helper()

	if len(durations) == 0 {
		return BenchmarkAnalysis{}
	}

	// Sort for percentile calculations
	sorted := make([]time.Duration, len(durations))
	copy(sorted, durations)
	
	// Simple bubble sort
	for i := 0; i < len(sorted)-1; i++ {
		for j := 0; j < len(sorted)-i-1; j++ {
			if sorted[j] > sorted[j+1] {
				sorted[j], sorted[j+1] = sorted[j+1], sorted[j]
			}
		}
	}

	var total time.Duration
	under50ms := 0
	under100ms := 0

	for _, duration := range durations {
		total += duration
		if duration < 50*time.Millisecond {
			under50ms++
		}
		if duration < 100*time.Millisecond {
			under100ms++
		}
	}

	analysis := BenchmarkAnalysis{
		Count:      len(durations),
		Min:        sorted[0],
		Max:        sorted[len(sorted)-1],
		Average:    total / time.Duration(len(durations)),
		Under50ms:  under50ms,
		Under100ms: under100ms,
	}

	// Calculate percentiles
	p50Index := int(float64(len(sorted)) * 0.5)
	p95Index := int(float64(len(sorted)) * 0.95)
	p99Index := int(float64(len(sorted)) * 0.99)

	if p50Index >= len(sorted) {
		p50Index = len(sorted) - 1
	}
	if p95Index >= len(sorted) {
		p95Index = len(sorted) - 1
	}
	if p99Index >= len(sorted) {
		p99Index = len(sorted) - 1
	}

	analysis.P50 = sorted[p50Index]
	analysis.P95 = sorted[p95Index]
	analysis.P99 = sorted[p99Index]

	return analysis
}

// BenchmarkAnalysis contains statistical analysis of benchmark results
type BenchmarkAnalysis struct {
	Count      int
	Min        time.Duration
	Max        time.Duration
	Average    time.Duration
	P50        time.Duration
	P95        time.Duration
	P99        time.Duration
	Under50ms  int
	Under100ms int
}

// LogAnalysis logs the benchmark analysis results
func (p *E2EPerformanceHelper) LogAnalysis(name string, analysis BenchmarkAnalysis) {
	p.t.Helper()

	p.t.Logf("Benchmark Analysis [%s]:", name)
	p.t.Logf("  Iterations: %d", analysis.Count)
	p.t.Logf("  Min: %v", analysis.Min)
	p.t.Logf("  Max: %v", analysis.Max)
	p.t.Logf("  Average: %v", analysis.Average)
	p.t.Logf("  P50: %v", analysis.P50)
	p.t.Logf("  P95: %v", analysis.P95)
	p.t.Logf("  P99: %v", analysis.P99)
	p.t.Logf("  Under 50ms: %d/%d (%.1f%%)",
		analysis.Under50ms, analysis.Count,
		float64(analysis.Under50ms)*100/float64(analysis.Count))
	p.t.Logf("  Under 100ms: %d/%d (%.1f%%)",
		analysis.Under100ms, analysis.Count,
		float64(analysis.Under100ms)*100/float64(analysis.Count))
}

// ValidateAnalysis checks if benchmark results meet performance requirements
func (p *E2EPerformanceHelper) ValidateAnalysis(name string, analysis BenchmarkAnalysis) {
	p.t.Helper()

	// CB-176 Performance Requirements:
	// - P95 should be under 100ms for auth endpoints
	// - Average should be under 50ms for critical operations

	if analysis.P95 > 100*time.Millisecond {
		p.t.Errorf("Benchmark [%s] P95 %v exceeds 100ms requirement", name, analysis.P95)
	}

	if analysis.Average > 50*time.Millisecond {
		p.t.Logf("Warning: Benchmark [%s] average %v exceeds 50ms target", name, analysis.Average)
	}

	// At least 90% of requests should be under 100ms
	successRate := float64(analysis.Under100ms) * 100 / float64(analysis.Count)
	if successRate < 90.0 {
		p.t.Errorf("Benchmark [%s] success rate %.1f%% below 90%% target", name, successRate)
	}
}

// GetMeasurements returns all recorded performance measurements
func (p *E2EPerformanceHelper) GetMeasurements() []PerformanceMeasurement {
	return append([]PerformanceMeasurement(nil), p.metrics...)
}

// Reset clears all recorded measurements
func (p *E2EPerformanceHelper) Reset() {
	p.metrics = p.metrics[:0]
}

// StartTimer starts a performance timer
func (p *E2EPerformanceHelper) StartTimer() {
	p.startTime = time.Now()
}

// StopTimer stops the timer and returns elapsed time
func (p *E2EPerformanceHelper) StopTimer() time.Duration {
	if p.startTime.IsZero() {
		p.t.Fatal("Timer not started")
	}
	
	elapsed := time.Since(p.startTime)
	p.startTime = time.Time{} // Reset
	return elapsed
}