package main

import (
	"fmt"
	"log"
	"os"

	"github.com/you/authzsvc/internal/infrastructure/database"
)

// Simple database connection test for CB-176 setup verification
func main() {
	// Use the exact same DSN format as the tests will use
	dsn := "postgres://auth:123456@localhost:5432/authdb?sslmode=disable&search_path=auth"
	
	// Override with environment variable if provided
	if envDSN := os.Getenv("TEST_DATABASE_DSN"); envDSN != "" {
		dsn = envDSN
	}

	fmt.Println("CB-176 Database Connection Test")
	fmt.Println("================================")
	fmt.Printf("Connecting to: %s\n", dsn)

	// Test database connection
	db, err := database.Open(dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Test database ping
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying sql.DB: %v", err)
	}
	defer sqlDB.Close()

	if err := sqlDB.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	fmt.Println("✓ Database connection successful")

	// Test AutoMigrate
	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("Failed to run auto-migration: %v", err)
	}
	fmt.Println("✓ AutoMigrate completed successfully")

	// Test basic query to verify tables exist
	var userCount int64
	if err := db.Raw("SELECT COUNT(*) FROM auth.users").Scan(&userCount).Error; err != nil {
		log.Fatalf("Failed to query users table: %v", err)
	}
	fmt.Printf("✓ Users table accessible (current count: %d)\n", userCount)

	var policyCount int64
	if err := db.Raw("SELECT COUNT(*) FROM auth.casbin_rule").Scan(&policyCount).Error; err != nil {
		log.Fatalf("Failed to query casbin_rule table: %v", err)
	}
	fmt.Printf("✓ Casbin rules table accessible (current count: %d)\n", policyCount)

	// Test verification function
	var results []map[string]interface{}
	if err := db.Raw("SELECT * FROM auth.verify_setup()").Scan(&results).Error; err != nil {
		log.Printf("Warning: Failed to run verify_setup function: %v", err)
	} else {
		fmt.Println("✓ Database verification results:")
		for _, result := range results {
			fmt.Printf("  - %v: %v (%v)\n", result["component"], result["status"], result["details"])
		}
	}

	fmt.Println("\n🎉 CB-176 Database setup verification completed successfully!")
	fmt.Println("Your database is ready for E2E authentication tests.")
}