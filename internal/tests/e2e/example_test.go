// This is an example E2E test demonstrating the test infrastructure
// This file should be removed once actual E2E tests are implemented

package e2e

import (
	"testing"
	"time"
)

// TestE2EInfrastructureExample demonstrates how to use the E2E test infrastructure
func TestE2EInfrastructureExample(t *testing.T) {
	// Get global test suite
	suite := GetTestSuite()

	// Create test server
	server := NewTestServer(t, suite)

	// Start server
	helper := NewServerTestHelper(t, server)
	helper.MustStart()
	helper.MustWaitForReady()

	// Create test data fixtures
	fixtures := NewTestDataFixtures(t, suite)
	user, session := fixtures.CreateCompleteUserFixtureT()

	// Verify test infrastructure works
	if user.ID == 0 {
		t.Fatal("Expected user to be created with valid ID")
	}

	if session.ID == "" {
		t.Fatal("Expected session to be created with valid ID")
	}

	// Test database helper
	dbHelper := NewDatabaseTestHelper(t, suite)
	userCount := dbHelper.CountRecordsT("users")
	if userCount == 0 {
		t.Fatal("Expected at least one user in database")
	}

	// Test performance measurement
	perfHelper := NewE2EPerformanceHelper(t, server)
	duration := perfHelper.MeasureEndpoint("health_check", "GET", "/health", nil)
	
	if duration > 100*time.Millisecond {
		t.Logf("Warning: Health check took %v (over 100ms)", duration)
	}

	// Validate server performance
	server.ValidatePerformance(t)

	t.Logf("E2E test infrastructure working correctly")
	t.Logf("Created user: %s (ID: %d)", user.Email, user.ID)
	t.Logf("Created session: %s", session.ID)
	t.Logf("Health check duration: %v", duration)
}