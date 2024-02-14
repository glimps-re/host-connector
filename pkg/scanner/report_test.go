package scanner

import (
	"bytes"
	"io"
	"os"
	"testing"
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
				rs: []Report{{FileName: "test", Sha256: "123456"}},
			},
			want: `[
{},
{"file-name":"test","sha256":"123456","malicious":false}
]`,
		},
		{
			name:        "test1",
			initContent: "",
			args: args{
				rs: []Report{{FileName: "test", Sha256: "123456"}},
			},
			want: `[
{"file-name":"test","sha256":"123456","malicious":false}
]`,
		},
		{
			name: "test2",
			initContent: `[
{"file-name":"test","sha256":"123456","malicious":false}
]`,
			args: args{
				rs: []Report{
					{FileName: "test2", Sha256: "1234567", Malicious: true, Deleted: true},
					{FileName: "test3", Sha256: "1234568"},
				},
			},
			want: `[
{"file-name":"test","sha256":"123456","malicious":false},
{"file-name":"test2","sha256":"1234567","malicious":true,"deleted":true},
{"file-name":"test3","sha256":"1234568","malicious":false}
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
			f.WriteString(tt.initContent)
			defer f.Close()
			defer os.Remove(f.Name())
			rw := NewReportsWriter(f)
			for _, r := range tt.args.rs {
				if err := rw.Write(r); (err != nil) != tt.wantErr {
					t.Errorf("ReportsWriter.Write() error = %v, wantErr %v", err, tt.wantErr)
				}
			}
			f.Seek(0, io.SeekStart)
			buffer := &bytes.Buffer{}
			io.Copy(buffer, f)
			if buffer.String() != tt.want {
				t.Errorf("ReportsWriter.Write() got = %v, want %v", buffer.String(), tt.want)
			}
		})
	}
}
