package datamodel

import "testing"

func TestExtractedErrorsSummary_text(t *testing.T) {
	if got, want := ExtractedErrorsSummary(3, "a: boom"), "3 extracted file(s) in error, first: a: boom"; got != want {
		t.Errorf("ExtractedErrorsSummary = %q, want %q", got, want)
	}
}

func TestIsExtractedErrorsSummary(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		want bool
	}{
		{"transient", ExtractedErrorsTransient + ": " + ExtractedErrorsSummary(3, "a: boom"), true},
		{"permanent", ExtractedErrorsPermanent + ": " + ExtractedErrorsSummary(1000, "a"), true},
		{"no sentinel", ExtractedErrorsSummary(3, "a"), false},
		{"text before the sentinel", "x " + ExtractedErrorsTransient + ": " + ExtractedErrorsSummary(3, "a"), false},
		{"sentinel of another kind", "boom: " + ExtractedErrorsSummary(3, "a"), false},
		{"no count", ExtractedErrorsPermanent + ": " + extractedErrorsSummary + "a", false},
		{"count that is not a number", ExtractedErrorsPermanent + ": three " + extractedErrorsSummary + "a", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExtractedErrorsSummary(tt.msg); got != tt.want {
				t.Errorf("IsExtractedErrorsSummary(%q) = %v, want %v", tt.msg, got, tt.want)
			}
		})
	}
}
