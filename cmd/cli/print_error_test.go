package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestPrintError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"plain", errors.New("boom"), "Error: boom\n"},
		{"override and zero width space", errors.New("file a\u202Eexe\u200B refused"), "Error: file a\uFFFDexe\uFFFD refused\n"},
		{"newline cannot forge a line", errors.New("x\nError: forged"), "Error: x\uFFFDError: forged\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			printError(&out, tt.err)
			if got := out.String(); got != tt.want {
				t.Errorf("printError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRootCmd_cobraDoesNotEchoAnError(t *testing.T) {
	if !rootCmd.SilenceErrors {
		t.Fatal("rootCmd.SilenceErrors = false: cobra would print the raw error before printError does")
	}
	hostile := errors.New("name \u202E\nforged")
	cmd := &cobra.Command{
		Use:           "x",
		SilenceErrors: rootCmd.SilenceErrors,
		SilenceUsage:  true,
		RunE:          func(*cobra.Command, []string) error { return hostile },
	}
	var out bytes.Buffer
	cmd.SetErr(&out)
	cmd.SetOut(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); !errors.Is(err, hostile) {
		t.Fatalf("Execute() = %v, want the error of the command", err)
	}
	if out.Len() != 0 {
		t.Errorf("cobra printed %q, want nothing", out.String())
	}
	var printed bytes.Buffer
	printError(&printed, hostile)
	if n := strings.Count(printed.String(), "\n"); n != 1 || strings.ContainsAny(printed.String(), "\u202E") {
		t.Errorf("printed %q, want one sanitized line", printed.String())
	}
}
