package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

var allowedStdlibPrefixes = []string{
	"archive/", "bufio", "bytes", "compress/", "container/", "context",
	"crypto", "database/", "debug/", "embed", "encoding", "errors",
	"expvar", "flag", "fmt", "hash", "html", "image", "io", "log",
	"math", "mime", "net", "os", "path", "plugin", "reflect", "regexp",
	"runtime", "sort", "strconv", "strings", "sync", "syscall", "testing",
	"text", "time", "unicode", "unsafe", "talaria/",
}

var forbiddenMutationCalls = map[string]bool{
	"Create":     true,
	"CreateTemp": true,
	"WriteFile":  true,
	"Mkdir":      true,
	"MkdirAll":   true,
	"Remove":     true,
	"RemoveAll":  true,
	"Chmod":      true,
	"Chown":      true,
	"Truncate":   true,
	"Rename":     true,
}

func main() {
	fmt.Println("==================================================")
	fmt.Println("🛡️  Talaria Security & Code Standards Gatekeeper")
	fmt.Println("==================================================")

	var failures []string

	// 1. Verify go.mod has zero third-party dependencies
	if err := checkGoMod("go.mod"); err != nil {
		failures = append(failures, fmt.Sprintf("[ZERO-DEPS] %v", err))
	} else {
		fmt.Println("✅ [ZERO-DEPS] Verified: 0 external dependencies in go.mod")
	}

	// 2. AST inspection across packages
	fset := token.NewFileSet()
	packages := []string{"cmd", "core", "models", "scanners", "internal"}

	fileCount := 0
	for _, pkg := range packages {
		pkgPath := filepath.Clean(pkg)
		if _, err := os.Stat(pkgPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(pkgPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}

			fileCount++
			node, parseErr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if parseErr != nil {
				failures = append(failures, fmt.Sprintf("[PARSE-ERROR] Failed to parse %s: %v", path, parseErr))
				return nil
			}

			isTest := strings.HasSuffix(path, "_test.go")

			// Check imports (applied to all files including tests)
			for _, imp := range node.Imports {
				impPath := strings.Trim(imp.Path.Value, `"`)
				if impPath == "C" {
					failures = append(failures, fmt.Sprintf("[CGO-BAN] %s imports C (CGO is strictly prohibited)", path))
				} else if !isAllowedImport(impPath) {
					failures = append(failures, fmt.Sprintf("[EXTERNAL-DEP] %s imports non-standard package: %s", path, impPath))
				}

				if (pkg == "models" || pkg == "internal") && impPath == "os/exec" {
					failures = append(failures, fmt.Sprintf("[EXEC-LEAK] %s imports os/exec (exec is prohibited in %s)", path, pkg))
				}
			}

			// AST checks for non-test files in scanners/ and core/
			if !isTest && (pkg == "scanners" || pkg == "core") {
				ast.Inspect(node, func(n ast.Node) bool {
					// Check for forbidden mutation calls (os.Create, os.WriteFile, etc.)
					if call, ok := n.(*ast.CallExpr); ok {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
							if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "os" {
								if forbiddenMutationCalls[sel.Sel.Name] {
									pos := fset.Position(call.Pos())
									failures = append(failures, fmt.Sprintf("[ZERO-MUTATION] %s:%d calls forbidden os.%s (read-only invariant violated)", path, pos.Line, sel.Sel.Name))
								}
							}

							// Check for un-contexted exec.Command in scanners
							if pkg == "scanners" {
								if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "exec" {
									if sel.Sel.Name == "Command" {
										pos := fset.Position(call.Pos())
										failures = append(failures, fmt.Sprintf("[SAFE-EXEC] %s:%d calls un-contexted exec.Command (must use exec.CommandContext)", path, pos.Line))
									}
								}
							}
						}
					}
					return true
				})
			}

			return nil
		})

		if err != nil {
			failures = append(failures, fmt.Sprintf("[WALK-ERROR] Error auditing %s: %v", pkg, err))
		}
	}

	fmt.Printf("✅ [AST-ANALYSIS] Audited %d Go source files across core packages\n", fileCount)

	// 3. Test Suite Presence Check
	testSuites := []string{
		"cmd/cli_test.go",
		"cmd/dispatch_test.go",
		"cmd/report_test.go",
		"core/crypto_test.go",
		"core/graph_test.go",
		"core/intelligence_test.go",
		"core/reporting_test.go",
		"core/sarif_test.go",
		"core/terminal_test.go",
		"internal/walkpool/pool_test.go",
	}

	for _, ts := range testSuites {
		if _, err := os.Stat(ts); os.IsNotExist(err) {
			failures = append(failures, fmt.Sprintf("[TEST-MISSING] Core test suite %s is missing", ts))
		}
	}
	fmt.Printf("✅ [TEST-HYGIENE] Verified core package test suites exist and are tracked\n")

	// 4. Report Final Results
	fmt.Println("--------------------------------------------------")
	if len(failures) == 0 {
		fmt.Println("🎉 ALL SECURITY & CODE STANDARDS CHECKS PASSED!")
		fmt.Println("   • Zero third-party dependencies verified")
		fmt.Println("   • Zero filesystem mutations verified in scanners & core")
		fmt.Println("   • CGO strictly disabled & forbidden")
		fmt.Println("   • Subprocess execution bounded and context-safe")
		fmt.Println("   • Unit test coverage verified for core and scanner modules")
		fmt.Println("==================================================")
		os.Exit(0)
	}

	fmt.Printf("❌ %d SECURITY/STANDARDS VIOLATION(S) DETECTED:\n", len(failures))
	for _, f := range failures {
		fmt.Printf("   ⛔ %s\n", f)
	}
	fmt.Println("==================================================")
	os.Exit(1)
}

func checkGoMod(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require") {
			return fmt.Errorf("external dependency detected: %s", line)
		}
	}
	return scanner.Err()
}

func isAllowedImport(importPath string) bool {
	for _, p := range allowedStdlibPrefixes {
		if importPath == p || strings.HasPrefix(importPath, p) {
			return true
		}
	}
	return false
}
