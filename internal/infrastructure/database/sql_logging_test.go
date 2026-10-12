package database

import (
	"bytes"
	"strings"
	"testing"

	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func dryRunDB(t *testing.T, logSQL bool, out *bytes.Buffer) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=127.0.0.1 port=1 user=x dbname=x sslmode=disable"}), &gorm.Config{
		DryRun:               true,
		DisableAutomaticPing: true,
		Logger:               newSQLLogger(out, logSQL),
	})
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// By default no statement is logged at all.
func TestSQLLoggingIsOffByDefault(t *testing.T) {
	var out bytes.Buffer
	db := dryRunDB(t, false, &out)
	var users []repositories.DBUser
	db.Where("phone = ?", "+5511999990000").Find(&users)
	if out.Len() != 0 {
		t.Errorf("nothing may be logged by default, got %q", out.String())
	}
}

// With DB_LOG_SQL the statement is logged with placeholders: the phone, e-mail or hash never appear.
func TestSQLLoggingNeverPrintsValues(t *testing.T) {
	var out bytes.Buffer
	db := dryRunDB(t, true, &out)
	var users []repositories.DBUser
	db.Where("phone = ? AND email = ?", "+5511999990000", "ana@example.com").Find(&users)
	if !strings.Contains(out.String(), "phone =") {
		t.Fatalf("the statement must be logged when asked: %q", out.String())
	}
	for _, leak := range []string{"5511999990000", "ana@example.com"} {
		if strings.Contains(out.String(), leak) {
			t.Errorf("a value reached the log: %q", out.String())
		}
	}
}
