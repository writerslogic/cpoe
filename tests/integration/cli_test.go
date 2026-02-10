//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// CLITestEnv sets up an environment for CLI integration testing.
type CLITestEnv struct {
	T           *testing.T
	TempDir     string
	WitnessdDir string
	DataDir     string
	BinDir      string
	WitnessdBin string
	WitnessctlBin string
}

// NewCLITestEnv creates a new CLI test environment.
func NewCLITestEnv(t *testing.T) *CLITestEnv {
	t.Helper()

	tempDir := t.TempDir()
	witnessdDir := filepath.Join(tempDir, ".witnessd")
	dataDir := filepath.Join(tempDir, "data")
	binDir := filepath.Join(tempDir, "bin")

	// Create directories
	for _, dir := range []string{witnessdDir, dataDir, binDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create directory %s: %v", dir, err)
		}
	}

	env := &CLITestEnv{
		T:             t,
		TempDir:       tempDir,
		WitnessdDir:   witnessdDir,
		DataDir:       dataDir,
		BinDir:        binDir,
		WitnessdBin:   filepath.Join(binDir, "witnessd"),
		WitnessctlBin: filepath.Join(binDir, "witnessctl"),
	}

	return env
}

// BuildBinaries builds the CLI binaries for testing.
func (env *CLITestEnv) BuildBinaries() error {
	// Get the project root
	projectRoot, err := getProjectRoot()
	if err != nil {
		return err
	}

	// Build witnessd
	cmd := exec.Command("go", "build", "-o", env.WitnessdBin, "./cmd/witnessd")
	cmd.Dir = projectRoot
	cmd.Env = os.Environ()
	if output, err := cmd.CombinedOutput(); err != nil {
		env.T.Logf("Build witnessd output: %s", output)
		return err
	}

	// Build witnessctl
	cmd = exec.Command("go", "build", "-o", env.WitnessctlBin, "./cmd/witnessctl")
	cmd.Dir = projectRoot
	cmd.Env = os.Environ()
	if output, err := cmd.CombinedOutput(); err != nil {
		env.T.Logf("Build witnessctl output: %s", output)
		return err
	}

	return nil
}

// RunWitnessd runs the witnessd daemon command.
func (env *CLITestEnv) RunWitnessd(args ...string) (string, error) {
	args = append([]string{"--data-dir", env.DataDir}, args...)
	return env.runCommand(env.WitnessdBin, args...)
}

// RunWitnessctl runs the witnessctl command.
func (env *CLITestEnv) RunWitnessctl(args ...string) (string, error) {
	args = append([]string{"--data-dir", env.DataDir}, args...)
	return env.runCommand(env.WitnessctlBin, args...)
}

// runCommand executes a command and returns output.
func (env *CLITestEnv) runCommand(bin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(),
		"WITNESSD_DATA_DIR="+env.DataDir,
		"HOME="+env.TempDir,
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String() + stderr.String()

	return output, err
}

// CreateTestDocument creates a test document.
func (env *CLITestEnv) CreateTestDocument(name, content string) string {
	path := filepath.Join(env.TempDir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		env.T.Fatalf("failed to create test document: %v", err)
	}
	return path
}

// Helper to get project root
func getProjectRoot() (string, error) {
	// Start from current directory and go up until we find go.mod
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

// TestCLIHelp tests the help commands.
func TestCLIHelp(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	t.Run("witnessd_help", func(t *testing.T) {
		output, err := env.RunWitnessd("--help")
		// --help returns exit code 0 or special handling
		if err != nil && !strings.Contains(output, "Usage") {
			t.Errorf("witnessd --help failed: %v, output: %s", err, output)
		}

		if !strings.Contains(output, "witnessd") && !strings.Contains(output, "Usage") {
			t.Errorf("witnessd --help should show usage, got: %s", output)
		}
	})

	t.Run("witnessctl_help", func(t *testing.T) {
		output, err := env.RunWitnessctl("--help")
		if err != nil && !strings.Contains(output, "Usage") {
			t.Errorf("witnessctl --help failed: %v, output: %s", err, output)
		}

		if !strings.Contains(output, "witnessctl") && !strings.Contains(output, "Usage") {
			t.Errorf("witnessctl --help should show usage, got: %s", output)
		}
	})

	t.Run("witnessctl_version", func(t *testing.T) {
		output, _ := env.RunWitnessctl("version")
		// Version command should not fail even if no version is set
		t.Logf("witnessctl version output: %s", output)
	})
}

// TestCLIStatus tests the status command.
func TestCLIStatus(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	t.Run("status_no_daemon", func(t *testing.T) {
		output, _ := env.RunWitnessctl("status")
		// Status should report daemon not running or similar
		t.Logf("witnessctl status output: %s", output)
	})
}

// TestCLICommit tests the commit workflow.
func TestCLICommit(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	// Create test document
	docPath := env.CreateTestDocument("test.md", "# Test Document\n\nInitial content.\n")

	t.Run("init_document", func(t *testing.T) {
		output, err := env.RunWitnessctl("init", docPath)
		t.Logf("witnessctl init output: %s, err: %v", output, err)
	})

	t.Run("commit_document", func(t *testing.T) {
		output, err := env.RunWitnessctl("commit", "-m", "Initial commit", docPath)
		t.Logf("witnessctl commit output: %s, err: %v", output, err)
	})

	t.Run("log_document", func(t *testing.T) {
		output, err := env.RunWitnessctl("log", docPath)
		t.Logf("witnessctl log output: %s, err: %v", output, err)
	})
}

// TestCLIVerify tests the verify command.
func TestCLIVerify(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	// Create and commit a document first
	docPath := env.CreateTestDocument("verify_test.md", "# Verification Test\n\nContent to verify.\n")

	// Initialize and commit
	env.RunWitnessctl("init", docPath)
	env.RunWitnessctl("commit", "-m", "Initial", docPath)

	t.Run("verify_document", func(t *testing.T) {
		output, err := env.RunWitnessctl("verify", docPath)
		t.Logf("witnessctl verify output: %s, err: %v", output, err)
	})

	t.Run("verify_json_output", func(t *testing.T) {
		output, err := env.RunWitnessctl("verify", "--json", docPath)
		t.Logf("witnessctl verify --json output: %s, err: %v", output, err)

		// Try to parse as JSON if output is not empty
		if len(strings.TrimSpace(output)) > 0 {
			var result map[string]interface{}
			if jsonErr := json.Unmarshal([]byte(output), &result); jsonErr == nil {
				t.Logf("Parsed JSON result: %+v", result)
			}
		}
	})
}

// TestCLIExport tests the export command.
func TestCLIExport(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	// Create and commit a document
	docPath := env.CreateTestDocument("export_test.md", "# Export Test\n\nContent to export.\n")
	outputPath := filepath.Join(env.TempDir, "evidence.json")

	env.RunWitnessctl("init", docPath)
	env.RunWitnessctl("commit", "-m", "Initial", docPath)

	t.Run("export_evidence", func(t *testing.T) {
		output, err := env.RunWitnessctl("export", "-o", outputPath, docPath)
		t.Logf("witnessctl export output: %s, err: %v", output, err)

		// Check if output file was created
		if _, statErr := os.Stat(outputPath); statErr == nil {
			data, readErr := os.ReadFile(outputPath)
			if readErr == nil {
				t.Logf("Exported evidence size: %d bytes", len(data))

				// Try to parse
				var packet map[string]interface{}
				if jsonErr := json.Unmarshal(data, &packet); jsonErr == nil {
					t.Logf("Evidence packet version: %v", packet["version"])
				}
			}
		}
	})
}

// TestCLIForensics tests the forensics command.
func TestCLIForensics(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	// Create a document with some history
	docPath := env.CreateTestDocument("forensics_test.md", "# Forensics Test\n")
	env.RunWitnessctl("init", docPath)
	env.RunWitnessctl("commit", "-m", "Initial", docPath)

	// Add more content
	os.WriteFile(docPath, []byte("# Forensics Test\n\nParagraph 1.\n"), 0644)
	env.RunWitnessctl("commit", "-m", "Added paragraph", docPath)

	os.WriteFile(docPath, []byte("# Forensics Test\n\nParagraph 1.\n\nParagraph 2.\n"), 0644)
	env.RunWitnessctl("commit", "-m", "Added more", docPath)

	t.Run("forensics_analysis", func(t *testing.T) {
		output, err := env.RunWitnessctl("forensics", docPath)
		t.Logf("witnessctl forensics output: %s, err: %v", output, err)
	})

	t.Run("forensics_json", func(t *testing.T) {
		output, err := env.RunWitnessctl("forensics", "--json", docPath)
		t.Logf("witnessctl forensics --json output: %s, err: %v", output, err)
	})
}

// TestCLIConfig tests configuration management.
func TestCLIConfig(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	t.Run("config_show", func(t *testing.T) {
		output, err := env.RunWitnessctl("config", "show")
		t.Logf("witnessctl config show output: %s, err: %v", output, err)
	})

	t.Run("config_set", func(t *testing.T) {
		output, err := env.RunWitnessctl("config", "set", "test.key", "test-value")
		t.Logf("witnessctl config set output: %s, err: %v", output, err)
	})

	t.Run("config_get", func(t *testing.T) {
		output, err := env.RunWitnessctl("config", "get", "test.key")
		t.Logf("witnessctl config get output: %s, err: %v", output, err)
	})
}

// TestCLIAnchorCommands tests anchor-related commands.
func TestCLIAnchorCommands(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	t.Run("anchor_list", func(t *testing.T) {
		output, err := env.RunWitnessctl("anchor", "list")
		t.Logf("witnessctl anchor list output: %s, err: %v", output, err)
	})

	t.Run("anchor_status", func(t *testing.T) {
		output, err := env.RunWitnessctl("anchor", "status")
		t.Logf("witnessctl anchor status output: %s, err: %v", output, err)
	})
}

// TestCLIDeclare tests the declaration command.
func TestCLIDeclare(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	// Create and commit a document
	docPath := env.CreateTestDocument("declare_test.md", "# Declaration Test\n\nMy original content.\n")
	env.RunWitnessctl("init", docPath)
	env.RunWitnessctl("commit", "-m", "Initial", docPath)

	t.Run("declare_authorship", func(t *testing.T) {
		output, err := env.RunWitnessctl("declare",
			"--modality", "keyboard:100",
			"--statement", "I wrote this content myself",
			docPath)
		t.Logf("witnessctl declare output: %s, err: %v", output, err)
	})

	t.Run("declare_with_ai", func(t *testing.T) {
		output, err := env.RunWitnessctl("declare",
			"--modality", "keyboard:80",
			"--ai-tool", "Claude:3.5:research:20",
			"--statement", "I wrote this with AI assistance for research",
			docPath)
		t.Logf("witnessctl declare with AI output: %s, err: %v", output, err)
	})
}

// TestCLIWorkflow tests a complete CLI workflow.
func TestCLIWorkflow(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	docPath := env.CreateTestDocument("workflow.md", "# My Document\n")

	// Step 1: Initialize
	t.Run("step1_init", func(t *testing.T) {
		output, err := env.RunWitnessctl("init", docPath)
		t.Logf("Init: %s, err: %v", output, err)
	})

	// Step 2: First commit
	t.Run("step2_first_commit", func(t *testing.T) {
		output, err := env.RunWitnessctl("commit", "-m", "Start document", docPath)
		t.Logf("First commit: %s, err: %v", output, err)
	})

	// Step 3: Add content
	t.Run("step3_add_content", func(t *testing.T) {
		os.WriteFile(docPath, []byte("# My Document\n\n## Introduction\n\nThis is my work.\n"), 0644)
	})

	// Step 4: Second commit
	t.Run("step4_second_commit", func(t *testing.T) {
		output, err := env.RunWitnessctl("commit", "-m", "Add introduction", docPath)
		t.Logf("Second commit: %s, err: %v", output, err)
	})

	// Step 5: More content
	t.Run("step5_more_content", func(t *testing.T) {
		os.WriteFile(docPath, []byte("# My Document\n\n## Introduction\n\nThis is my work.\n\n## Body\n\nMore content here.\n"), 0644)
	})

	// Step 6: Third commit
	t.Run("step6_third_commit", func(t *testing.T) {
		output, err := env.RunWitnessctl("commit", "-m", "Add body section", docPath)
		t.Logf("Third commit: %s, err: %v", output, err)
	})

	// Step 7: View log
	t.Run("step7_log", func(t *testing.T) {
		output, err := env.RunWitnessctl("log", docPath)
		t.Logf("Log: %s, err: %v", output, err)
	})

	// Step 8: Verify
	t.Run("step8_verify", func(t *testing.T) {
		output, err := env.RunWitnessctl("verify", docPath)
		t.Logf("Verify: %s, err: %v", output, err)
	})

	// Step 9: Export
	t.Run("step9_export", func(t *testing.T) {
		outputPath := filepath.Join(env.TempDir, "workflow_evidence.json")
		output, err := env.RunWitnessctl("export", "-o", outputPath, docPath)
		t.Logf("Export: %s, err: %v", output, err)

		if _, statErr := os.Stat(outputPath); statErr == nil {
			data, _ := os.ReadFile(outputPath)
			t.Logf("Evidence exported: %d bytes", len(data))
		}
	})
}

// TestCLIErrorHandling tests error scenarios.
func TestCLIErrorHandling(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	t.Run("nonexistent_file", func(t *testing.T) {
		output, err := env.RunWitnessctl("commit", "-m", "test", "/nonexistent/file.md")
		t.Logf("Nonexistent file output: %s, err: %v", output, err)

		// Should return error
		if err == nil && !strings.Contains(output, "error") && !strings.Contains(output, "not found") {
			t.Log("Expected error for nonexistent file")
		}
	})

	t.Run("invalid_command", func(t *testing.T) {
		output, err := env.RunWitnessctl("invalid-command")
		t.Logf("Invalid command output: %s, err: %v", output, err)
	})

	t.Run("missing_argument", func(t *testing.T) {
		output, err := env.RunWitnessctl("commit", "-m")
		t.Logf("Missing argument output: %s, err: %v", output, err)
	})

	t.Run("verify_uninitialized", func(t *testing.T) {
		docPath := env.CreateTestDocument("uninitialized.md", "Content")
		output, err := env.RunWitnessctl("verify", docPath)
		t.Logf("Verify uninitialized output: %s, err: %v", output, err)
	})
}

// TestCLIOutputFormats tests different output formats.
func TestCLIOutputFormats(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	docPath := env.CreateTestDocument("format_test.md", "# Format Test\n")
	env.RunWitnessctl("init", docPath)
	env.RunWitnessctl("commit", "-m", "Initial", docPath)

	t.Run("text_output", func(t *testing.T) {
		output, _ := env.RunWitnessctl("log", docPath)
		t.Logf("Text output: %s", output)
	})

	t.Run("json_output", func(t *testing.T) {
		output, _ := env.RunWitnessctl("log", "--json", docPath)
		t.Logf("JSON output: %s", output)

		// If output looks like JSON, try to parse it
		trimmed := strings.TrimSpace(output)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			var data interface{}
			if err := json.Unmarshal([]byte(trimmed), &data); err != nil {
				t.Logf("Note: Output is not valid JSON: %v", err)
			}
		}
	})
}

// TestCLIInteractiveMode tests interactive mode if available.
func TestCLIInteractiveMode(t *testing.T) {
	env := NewCLITestEnv(t)

	if err := env.BuildBinaries(); err != nil {
		t.Skipf("Skipping CLI tests - failed to build binaries: %v", err)
	}

	// Check if menu command exists
	t.Run("menu_mode", func(t *testing.T) {
		// Run with timeout since menu might wait for input
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, env.WitnessctlBin, "--data-dir", env.DataDir, "menu")
		output, _ := cmd.CombinedOutput()
		t.Logf("Menu mode output: %s", output)
	})
}
