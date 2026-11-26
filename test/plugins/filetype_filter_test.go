//go:build linux && (e2e || e2e_plugins)

package plugins

import (
	"bytes"
	"image"
	"image/png"
	"strings"
	"testing"

	"github.com/glimps-re/host-connector/pkg/datamodel"
	"github.com/glimps-re/host-connector/test/internal/harness"
)

// realPNG is a small image the type detection recognizes.
func realPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for i := range img.Pix {
		img.Pix[i] = byte(i * 7)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// A type the filter forbids is refused inside an archive too: the member is
// judged by its content, on the real path it has once extracted, and the whole
// archive is quarantined. An archive without such a member is delivered.
func TestE2E_aForbiddenTypeInsideAZipIsRefused(t *testing.T) {
	t.Parallel()
	text := []byte(strings.Repeat("a text member beside an image ", 40))
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a zip with an image and one without",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{
					"extract":         nil,
					"filetype_filter": {"forbidden_types": []string{"image/png"}},
				},
				Files: []harness.File{
					archive(t, "with.zip", zipOf,
						harness.File{Path: "pic.png", Content: realPNG(t)},
						harness.File{Path: "a.txt", Content: text},
					),
					archive(t, "without.zip", zipOf,
						harness.File{Path: "a.txt", Content: text},
						harness.File{Path: "b.txt", Content: []byte(strings.Repeat("another text member ", 40))},
					),
				},
				Want: map[string]harness.Outcome{
					"with.zip":    {In: harness.Quarantine, Malware: datamodel.FilteredFileType},
					"without.zip": {In: harness.Output},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// P7: a refusal beats an exemption. A file that the path rules let through (a
// skipped path) and a plugin refuses (a forbidden type) is refused.
// The same image is dropped outside the trusted folder (the control) and in it:
// each path gets its own container, so two are quarantined.
func TestE2E_aRefusalBeatsAnExemption(t *testing.T) {
	t.Parallel()
	pic := realPNG(t)
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "an image in a skipped folder",
			scenario: harness.Scenario{
				Config:  map[string]any{"filepath_filter": map[string]any{"skipped_paths": []string{`/trusted/`}}},
				Plugins: map[string]map[string]any{"filetype_filter": {"forbidden_types": []string{"image/png"}}},
				Files: []harness.File{
					{Path: "control.png", Content: pic},
					{Path: "trusted/p.png", Content: pic},
					{Path: "trusted/t.txt", Content: []byte("a text in a trusted folder")},
				},
				Want: map[string]harness.Outcome{
					"control.png":   {In: harness.Quarantine, Malware: datamodel.FilteredFileType},
					"trusted/p.png": {In: harness.Quarantine, Malware: datamodel.FilteredFileType},
					"trusted/t.txt": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedPath, ServiceVerdict: harness.NotGiven},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// T54: beyond what the type detection reads, a type never waives. A file whose
// type is in skipped_types is delivered without analysis when it is small, and
// analyzed when it is larger than what the detection reads (about 7 MiB): the
// type of such a file is judged from its head alone.
func TestE2E_aSkippedTypeIsNotWaivedForALargeFile(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a small and a 9 MiB image",
			scenario: harness.Scenario{
				Plugins: map[string]map[string]any{
					"filetype_filter": {"skipped_types": []string{"image/png"}},
				},
				Files: []harness.File{
					{Path: "small.png", Content: realPNG(t)},
					// A real image followed by zeros: still typed image/png, but past the size
					// the detection reads.
					{Path: "large.png", Content: append(realPNG(t), make([]byte, 9<<20)...)},
				},
				Want: map[string]harness.Outcome{
					"small.png": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedType, ServiceVerdict: harness.NotGiven},
					"large.png": {In: harness.Output, ServiceVerdict: harness.Given},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

// D-003: a release lifts the filters for the released file at its place. A
// restored file of a forbidden type is delivered with the restored mark, the
// type filter is not called on it; the same content deposited elsewhere is not
// released there and the filter still refuses it.
func TestE2E_aRestoredFileOfAForbiddenTypeIsDeliveredRestored(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		scenario harness.Scenario
	}{
		{
			name: "a restored image, and a copy of it elsewhere",
			scenario: harness.Scenario{
				Agent: true,
				Plugins: map[string]map[string]any{
					"filetype_filter": {"forbidden_types": []string{"image/png"}},
				},
				Files: []harness.File{
					{Path: "pic.png", Content: realPNG(t)},
				},
				Steps: []harness.Step{
					harness.Await("pic.png", harness.Outcome{In: harness.Quarantine, Malware: datamodel.FilteredFileType}),
					harness.Restore("pic.png", ""),
					harness.AwaitDelivered("pic.png"),
					harness.AddFileToInput(harness.File{Path: "copy/pic.png", Content: realPNG(t)}),
				},
				Want: map[string]harness.Outcome{
					"pic.png":      {In: harness.Output, Restored: true},
					"copy/pic.png": {In: harness.Quarantine, Malware: datamodel.FilteredFileType},
				},
				WantMitigations: []string{"filetype", "filetype"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			harness.Run(t, tt.scenario)
		})
	}
}

func TestE2E_aFileMatchingASkippedPathAndASkippedTypeIsMarkedSkippedPath(t *testing.T) {
	harness.Run(t, harness.Scenario{
		Config:  harness.PathFilter(nil, []string{`/both/`}),
		Plugins: map[string]map[string]any{"filetype_filter": {"skipped_types": []string{"image/png"}}},
		Files: []harness.File{
			{Path: "both/p.png", Content: realPNG(t)},
			{Path: "type.png", Content: realPNG(t)},
		},
		Want: map[string]harness.Outcome{
			"both/p.png": {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedPath, ServiceVerdict: harness.NotGiven},
			"type.png":   {In: harness.Output, NotAnalyzed: datamodel.NotAnalyzedSkippedType, ServiceVerdict: harness.NotGiven},
		},
	})
}
