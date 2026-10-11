package app

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
)

// EnsureStandardPolicies makes sure the standard Casbin policies and role inheritance exist,
// adding only what is missing (custom policies are never removed or overwritten).
func EnsureStandardPolicies(e *casbin.Enforcer) error {
	// ===== ENSURE STANDARD POLICIES EXIST =====
	// Instead of checking if ANY policies exist, ensure SPECIFIC policies exist
	// This prevents overwriting custom policies while ensuring standard ones are present

	standardPolicies := [][]string{
		// Basic user permissions
		{"role_user", "/auth/me", "GET", "*"},
		{"role_user", "/auth/logout", "POST", "*"},
		{"role_user", "/auth/otp/*", "POST", "*"},
		{"role_user", "/users/*", "GET", "path.id==token.user_id"},

		// Password management permissions for authenticated users
		{"role_user", "/password/change", "POST", "*"},
		{"role_user", "/password/change", "GET", "*"},
		{"role_user", "/password/change/*", "GET", "*"},
		{"role_user", "/password/change/*/verification", "PUT", "*"},
		{"role_user", "/password/change/*", "DELETE", "*"},
		{"role_user", "/password/reset", "POST", "*"},
		{"role_user", "/password/reset/*", "PUT", "*"},

		// LGPD User Deletion permissions for authenticated users (Article 18 rights)
		{"role_user", "/users/me/deletion", "POST", "*"},           // Right to deletion
		{"role_user", "/users/me/deletion/*", "GET", "*"},          // Check deletion status
		{"role_user", "/users/me/deletion/*", "DELETE", "*"},       // Cancel deletion
		{"role_user", "/users/me/export", "POST", "*"},             // Right to data portability
		{"role_user", "/users/me/deletion/history", "GET", "*"},    // View deletion history

		// Admin permissions
		{"role_admin", "/admin/*", "(GET|POST|PUT|DELETE)", "*"},
		{"role_admin", "/auth/*", "(GET|POST|PUT|DELETE)", "*"},
		
		// Admin LGPD deletion management permissions
		{"role_admin", "/admin/users/deletion/*/process", "POST", "*"},     // Process deletion requests
		{"role_admin", "/admin/users/deletion/pending", "GET", "*"},        // List pending deletions

		// Other roles from policies.csv
		{"role_attendant", "/auth/me", "GET", "*"},
		{"role_attendant", "/v1/clients/*", "(GET|PUT)", "*"},
		{"role_owner", "/users/:user_id", "(GET|PUT)", "*"},
	}

	policyUpdated := false
	for _, policy := range standardPolicies {
		// Check if this specific policy exists
		exists, _ := e.HasPolicy(policy[0], policy[1], policy[2], policy[3])
		if !exists {
			e.AddPolicy(policy[0], policy[1], policy[2], policy[3])
			policyUpdated = true
			log.Printf("casbin: added missing policy: %v", policy)
		}
	}

	// Ensure role inheritance (each grouping added only if missing)
	standardGroupings := [][2]string{
		{"role_admin", "role_user"},
		{"role_root", "role_admin"},
		{"role_client", "role_user"},
		{"role_contact", "role_user"},
		{"role_attendant", "role_user"},
	}
	for _, g := range standardGroupings {
		hasInheritance, _ := e.HasGroupingPolicy(g[0], g[1])
		if !hasInheritance {
			e.AddGroupingPolicy(g[0], g[1])
			policyUpdated = true
			log.Printf("casbin: added role inheritance - %s inherits from %s", g[0], g[1])
		}
	}

	// Save policies only if something was updated
	if policyUpdated {
		if err := e.SavePolicy(); err != nil {
			log.Printf("CRITICAL: Failed to save Casbin policies: %v", err)
			return fmt.Errorf("authorization system initialization failed: %w", err)
		}
		log.Println("casbin: policies updated and saved")
	} else {
		log.Println("casbin: all standard policies already exist")
	}

	return nil
}
