package database

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"testing"
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
