package datamodel

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReportsWriter_Write(t *testing.T) {
	type args struct {
		rs []Report
	}
	tests := []struct {
		name        string
		initContent string
		args        args
		wantErr     bool
		want        string
	}{
		{
			name:        "test1",
			initContent: "[\n{}\n]",
			args: args{
				rs: []Report{{Filename: "test", SHA256: "123456"}},
			},
			want: `[
{},
{"filename":"test","sha256":"123456","malicious":false}
]`,
		},
		{
			name:        "test1",
			initContent: "",
			args: args{
				rs: []Report{{Filename: "test", SHA256: "123456"}},
			},
			want: `[
{"filename":"test","sha256":"123456","malicious":false}
]`,
		},
		{
			name: "test2",
			initContent: `[
{"filename":"test","sha256":"123456","malicious":false}
]`,
			args: args{
				rs: []Report{
					{Filename: "test2", SHA256: "1234567", Malicious: true, Deleted: true},
					{Filename: "test3", SHA256: "1234568"},
				},
			},
			want: `[
{"filename":"test","sha256":"123456","malicious":false},
{"filename":"test2","sha256":"1234567","malicious":true,"deleted":true},
{"filename":"test3","sha256":"1234568","malicious":false}
]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.CreateTemp(os.TempDir(), "test_report_writer_*")
			if err != nil {
				t.Errorf("ReportsWriter.Write() error, could not create test tmp file, error: %s", err)
				return
			}
			if _, err := f.WriteString(tt.initContent); err != nil {
				t.Logf("Warning: failed to write test content: %v", err)
			}
			defer func() {
				if closeErr := f.Close(); closeErr != nil {
					t.Logf("Warning: failed to close temp file: %v", closeErr)
				}
			}()
			defer func() {
				if removeErr := os.Remove(f.Name()); removeErr != nil {
					t.Logf("Warning: failed to remove temp file: %v", removeErr)
				}
			}()
			rw := NewReportsWriter(f)
			for _, r := range tt.args.rs {
				if err := rw.Write(r); (err != nil) != tt.wantErr {
					t.Errorf("ReportsWriter.Write() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.Logf("Warning: failed to seek to start: %v", err)
			}
			buffer := &bytes.Buffer{}
			if _, err := io.Copy(buffer, f); err != nil {
				t.Logf("Warning: failed to copy file content: %v", err)
			}
			got := buffer.String()
			if got != tt.want {
				t.Errorf("ReportsWriter.Write() %s", cmp.Diff(got, tt.want))
			}
		})
	}
}
