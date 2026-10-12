package database

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// notTables are structs that carry gorm tags but are not tables of their own.
var notTables = map[string]string{
	"User":                 "domain view of the users table, which repositories.DBUser migrates",
	"FieldConstraint":      "serialized inside ValidationRule",
	"CrossFieldConstraint": "serialized inside ValidationRule",
	"SecurityConstraint":   "serialized inside ValidationRule",
	"BusinessConstraint":   "serialized inside ValidationRule",
}

func parseDir(t *testing.T, dir string) map[string]*ast.Package {
	t.Helper()
	notTest := func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }
	pkgs, err := parser.ParseDir(token.NewFileSet(), dir, notTest, 0)
	if err != nil {
		t.Fatal(err)
	}
	return pkgs
}

// gormModels returns the name of every struct, in the given directories, that carries a gorm tag or has a
// TableName method: the types the repositories persist.
func gormModels(t *testing.T, dirs ...string) map[string]bool {
	t.Helper()
	models := map[string]bool{}
	for _, dir := range dirs {
		for _, pkg := range parseDir(t, dir) {
			for _, file := range pkg.Files {
				ast.Inspect(file, func(n ast.Node) bool {
					switch d := n.(type) {
					case *ast.TypeSpec:
						if st, ok := d.Type.(*ast.StructType); ok {
							for _, field := range st.Fields.List {
								if field.Tag != nil && strings.Contains(field.Tag.Value, "gorm:") {
									models[d.Name.Name] = true
								}
							}
						}
					case *ast.FuncDecl:
						if d.Name.Name == "TableName" && d.Recv != nil && len(d.Recv.List) == 1 {
							if id, ok := d.Recv.List[0].Type.(*ast.Ident); ok {
								models[id.Name] = true
							}
						}
					}
					return true
				})
			}
		}
	}
	return models
}

// migrated returns the type names that appear as &pkg.Type{} in the non-test code of this package,
// which is where the migration list lives.
func migrated(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, pkg := range parseDir(t, ".") {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				if u, ok := n.(*ast.UnaryExpr); ok && u.Op == token.AND {
					if lit, ok := u.X.(*ast.CompositeLit); ok {
						if sel, ok := lit.Type.(*ast.SelectorExpr); ok {
							names[sel.Sel.Name] = true
						}
					}
				}
				return true
			})
		}
	}
	return names
}

// Every struct the repositories persist must be in the migration list, so a fresh database has its table.
func TestEveryPersistedModelIsMigrated(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	persisted := gormModels(t, filepath.Join(root, "domain"), filepath.Join(root, "internal", "infrastructure", "repositories"))
	listed := migrated(t)

	var missing []string
	for name := range persisted {
		if _, skip := notTables[name]; skip {
			continue
		}
		if !listed[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("these persisted models are not in the AutoMigrate list (a fresh database would lack their table): %v", missing)
	}
}

type ddlRecorder struct {
	logger.Interface
	statements []string
}

func (r *ddlRecorder) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	sql, _ := fc()
	r.statements = append(r.statements, sql)
}

// The DDL GORM generates for the password tables has the columns, types and indexes the repositories
// use. GORM runs in dry-run mode over a connection that is never opened, so no database is touched.
func TestPasswordTablesDDL(t *testing.T) {
	rec := &ddlRecorder{Interface: logger.Default.LogMode(logger.Silent)}
	db, err := gorm.Open(postgres.New(postgres.Config{DSN: "host=127.0.0.1 port=1 user=x dbname=x sslmode=disable"}), &gorm.Config{
		DryRun:               true,
		DisableAutomaticPing: true,
		Logger:               rec,
		NamingStrategy:       schema.NamingStrategy{TablePrefix: "auth."},
	})
	if err != nil {
		t.Fatalf("dry-run connection: %v", err)
	}
	if err := db.Migrator().CreateTable(&repositories.DBPasswordHistory{}, &repositories.DBPasswordChangeRequest{}); err != nil {
		t.Fatalf("dry-run CreateTable: %v", err)
	}
	ddl := strings.Join(rec.statements, "\n")
	for _, want := range []string{
		`CREATE TABLE "auth"."password_history"`,
		`"user_id" bigint NOT NULL`,
		`"password_hash" varchar(255) NOT NULL`,
		`CREATE TABLE "auth"."password_change_requests"`,
		`"id" uuid`,
		`"otp_code" text`,
		`"otp_attempts" bigint DEFAULT 0`,
		`"nonce" text NOT NULL`,
		`"status" varchar(50) NOT NULL`,
		`"expires_at" timestamptz NOT NULL`,
	} {
		if !strings.Contains(ddl, want) {
			t.Errorf("the generated DDL lacks %q:\n%s", want, ddl)
		}
	}
	if n := strings.Count(ddl, "CREATE INDEX"); n < 6 {
		t.Errorf("expected the user_id / status / expiry indexes, got %d CREATE INDEX statements:\n%s", n, ddl)
	}
}

// The migration list is parseable by GORM: every model gets a table name.
func TestEveryModelHasATableName(t *testing.T) {
	seen := map[string]bool{}
	for _, model := range Models() {
		s, err := schema.Parse(model, &sync.Map{}, schema.NamingStrategy{TablePrefix: "auth."})
		if err != nil {
			t.Fatalf("%T: %v", model, err)
		}
		if s.Table == "" || seen[s.Table] {
			t.Errorf("%T: empty or duplicated table %q", model, s.Table)
		}
		seen[s.Table] = true
	}
	for _, table := range []string{"auth.password_history", "auth.password_change_requests"} {
		if !seen[table] {
			t.Errorf("table %s is not in Models()", table)
		}
	}
}
