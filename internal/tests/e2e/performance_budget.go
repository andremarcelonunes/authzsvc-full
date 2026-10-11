package e2e

// Wall-clock performance budgets in the E2E suite
//
// The E2E tests measure endpoint latency (bcrypt-bound, roughly 75-120 ms depending on
// machine load) and compare it with a budget such as "Registration should be < 100ms".
// Those budgets are opt-in, so the functional suite does not fail for load-related reasons:
//
//	E2E_ENFORCE_PERFORMANCE=1  budgets are enforced (same as assert.Less)
//	(unset / any other value)  a budget overrun is only logged with t.Logf
//
// Use assertWithinBudget ONLY for measured durations. Assertions about functional values
// that happen to be durations (e.g. an OTP TTL) are correctness checks and must stay hard
// assertions. The dedicated performance suites (internal/tests/performance and
// internal/tests/load) keep their hard assertions and are not affected by this variable.

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// enforcePerformanceEnvVar is the environment variable that turns budgets into hard assertions.
const enforcePerformanceEnvVar = "E2E_ENFORCE_PERFORMANCE"

// assertWithinBudget asserts actual < budget when E2E_ENFORCE_PERFORMANCE=1 (exactly like
// assert.Less). Otherwise an exceeded budget is logged and the test continues.
func assertWithinBudget(t *testing.T, actual, budget time.Duration, msgAndArgs ...interface{}) {
	t.Helper()

	if os.Getenv(enforcePerformanceEnvVar) == "1" {
		assert.Less(t, actual, budget, msgAndArgs...)
		return
	}

	if actual >= budget {
		t.Logf("performance budget exceeded (not enforced; set %s=1 to enforce): measured %v, budget %v %s",
			enforcePerformanceEnvVar, actual, budget, formatBudgetMessage(msgAndArgs...))
	}
}

// formatBudgetMessage renders optional assert-style message arguments for logging.
func formatBudgetMessage(msgAndArgs ...interface{}) string {
	if len(msgAndArgs) == 0 {
		return ""
	}
	if format, ok := msgAndArgs[0].(string); ok {
		return "- " + fmt.Sprintf(format, msgAndArgs[1:]...)
	}
	return "- " + fmt.Sprint(msgAndArgs[0])
}
