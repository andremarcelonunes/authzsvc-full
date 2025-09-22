package main

import (
	"context"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/config"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"github.com/you/authzsvc/internal/services"
)

func main() {
	// Test direct audit service integration - use docker compose DSN
	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		dsn = "postgres://postgres:password@localhost:5432/authzsvc_test?sslmode=disable"
	}

	// Open database connection
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: "auth.",
		},
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Auto-migrate audit events table
	if err := db.AutoMigrate(&domain.ComprehensiveAuditEvent{}); err != nil {
		log.Fatalf("Failed to migrate audit events table: %v", err)
	}

	// Create audit repository and service
	auditRepo := repositories.NewComprehensiveAuditRepository(db)
	config := &config.Config{} // minimal config for testing
	auditSvc := services.NewComprehensiveAuditService(auditRepo, nil, nil, nil, nil, nil, config, nil)

	// Test audit event creation
	ctx := context.Background()
	
	log.Println("Testing audit service...")

	// Test LogSystemEvent
	err = auditSvc.LogSystemEvent(ctx, "test_event", "Direct audit service test", map[string]interface{}{
		"test_key": "test_value",
		"user_id":  999,
	})
	if err != nil {
		log.Fatalf("Failed to log system event: %v", err)
	}

	// Test LogLoginAttempt
	err = auditSvc.LogLoginAttempt(ctx, 999, "test@example.com", "127.0.0.1", true, "test login")
	if err != nil {
		log.Fatalf("Failed to log login attempt: %v", err)
	}

	// Check if events were created
	var count int64
	db.Model(&domain.ComprehensiveAuditEvent{}).Count(&count)
	log.Printf("Audit events created: %d", count)

	if count > 0 {
		log.Println("✅ Audit service is working correctly!")
	} else {
		log.Println("❌ No audit events were created")
	}
}