package scanner

import (
	"context"
	"io"
	"os"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

func TestMockLock(t *testing.T) {
	type fields struct {
		LockFileMock   func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error
		UnlockFileMock func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error)
		GetHeaderMock  func(in io.Reader) (entry LockEntry, err error)
	}
	tests := []struct {
		name      string
		fields    fields
		test      func(m *MockLock)
		wantPanic bool
		wantOut   string
	}{
		{
			name: "test Lock file",
			fields: fields{
				LockFileMock: func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
					return nil
				},
			},
			test:      func(m *MockLock) { m.LockFile("", nil, &LockFileInfo{}, "", nil) },
			wantPanic: false,
		},
		{
			name:      "test Lock file (panic)",
			fields:    fields{},
			test:      func(m *MockLock) { m.LockFile("", nil, &LockFileInfo{}, "", nil) },
			wantPanic: true,
		},
		{
			name: "test Unlock file",
			fields: fields{
				UnlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					return "", &LockFileInfo{}, "", nil
				},
			},
			test:      func(m *MockLock) { m.UnlockFile(nil, nil) },
			wantPanic: false,
		},
		{
			name:      "test Unlock file (panic)",
			fields:    fields{},
			test:      func(m *MockLock) { m.UnlockFile(nil, nil) },
			wantPanic: true,
		},
		{
			name: "test GetHeader",
			fields: fields{
				GetHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return
				},
			},
			test:      func(m *MockLock) { m.GetHeader(nil) },
			wantPanic: false,
		},
		{
			name:      "test GetHeader (panic)",
			fields:    fields{},
			test:      func(m *MockLock) { m.GetHeader(nil) },
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockLock{
				LockFileMock:   tt.fields.LockFileMock,
				UnlockFileMock: tt.fields.UnlockFileMock,
				GetHeaderMock:  tt.fields.GetHeaderMock,
			}
			if tt.wantPanic {
				defer func() { _ = recover() }()
			}
			tt.test(m)
			if tt.wantPanic {
				t.Errorf("test should have panic")
			}
		})
	}
}

func TestMockSubmitter(t *testing.T) {
	type fields struct {
		ExtractExpertViewURLMock func(result *gdetect.Result) (urlExpertView string, err error)
		GetResultByUUIDMock      func(ctx context.Context, uuid string) (result gdetect.Result, err error)
		GetResultBySHA256Mock    func(ctx context.Context, sha256 string) (result gdetect.Result, err error)
		GetResultsMock           func(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error)
		SubmitFileMock           func(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error)
		SubmitReaderMock         func(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error)
		WaitForFileMock          func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error)
		WaitForReaderMock        func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error)
		GetProfileStatusMock     func(ctx context.Context) (status gdetect.ProfileStatus, err error)
		GetAPIVersionMock        func(ctx context.Context) (version string, err error)
	}
	tests := []struct {
		name      string
		fields    fields
		wantPanic bool
		test      func(m *MockSubmitter)
	}{
		{
			name: "test ExtractExpertViewURL",
			fields: fields{
				ExtractExpertViewURLMock: func(result *gdetect.Result) (urlExpertView string, err error) { return },
			},
			test:      func(m *MockSubmitter) { m.ExtractExpertViewURL(nil) },
			wantPanic: false,
		},
		{
			name:      "test ExtractExpertViewURL (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.ExtractExpertViewURL(nil) },
			wantPanic: true,
		},
		{
			name: "test GetResultByUUID",
			fields: fields{
				GetResultByUUIDMock: func(ctx context.Context, uuid string) (result gdetect.Result, err error) { return },
			},
			test:      func(m *MockSubmitter) { m.GetResultByUUID(nil, "") },
			wantPanic: false,
		},
		{
			name:      "test GetResultByUUID (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.GetResultByUUID(nil, "") },
			wantPanic: true,
		},
		{
			name: "test GetResultBySHA256",
			fields: fields{
				GetResultBySHA256Mock: func(ctx context.Context, sha256 string) (result gdetect.Result, err error) { return },
			},
			test:      func(m *MockSubmitter) { m.GetResultBySHA256(nil, "") },
			wantPanic: false,
		},
		{
			name:      "test GetResultBySHA256 (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.GetResultBySHA256(nil, "") },
			wantPanic: true,
		},
		{
			name: "test GetResults",
			fields: fields{
				GetResultsMock: func(ctx context.Context, from, size int, tags ...string) (submissions []gdetect.Submission, err error) {
					return
				},
			},
			test:      func(m *MockSubmitter) { m.GetResults(nil, 0, 0) },
			wantPanic: false,
		},
		{
			name:      "test GetResults (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.GetResults(nil, 0, 0) },
			wantPanic: true,
		},
		{
			name: "test SubmitFile",
			fields: fields{
				SubmitFileMock: func(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error) {
					return
				},
			},
			test:      func(m *MockSubmitter) { m.SubmitFile(nil, "", gdetect.SubmitOptions{}) },
			wantPanic: false,
		},
		{
			name:      "test SubmitFile (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.SubmitFile(nil, "", gdetect.SubmitOptions{}) },
			wantPanic: true,
		},
		{
			name: "test SubmitReader",
			fields: fields{
				SubmitReaderMock: func(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error) { return },
			},
			test:      func(m *MockSubmitter) { m.SubmitReader(nil, nil, gdetect.SubmitOptions{}) },
			wantPanic: false,
		},
		{
			name:      "test SubmitReader (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.SubmitReader(nil, nil, gdetect.SubmitOptions{}) },
			wantPanic: true,
		},
		{
			name: "test WaitForFile",
			fields: fields{
				WaitForFileMock: func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
					return
				},
			},
			test:      func(m *MockSubmitter) { m.WaitForFile(nil, "", gdetect.WaitForOptions{}) },
			wantPanic: false,
		},
		{
			name:      "test WaitForFile (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.WaitForFile(nil, "", gdetect.WaitForOptions{}) },
			wantPanic: true,
		},
		{
			name: "test WaitForReader",
			fields: fields{
				WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
					return
				},
			},
			test:      func(m *MockSubmitter) { m.WaitForReader(nil, nil, gdetect.WaitForOptions{}) },
			wantPanic: false,
		},
		{
			name:      "test WaitForReader (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.WaitForReader(nil, nil, gdetect.WaitForOptions{}) },
			wantPanic: true,
		},
		{
			name: "test GetProfileStatus",
			fields: fields{
				GetProfileStatusMock: func(ctx context.Context) (status gdetect.ProfileStatus, err error) { return },
			},
			test:      func(m *MockSubmitter) { m.GetProfileStatus(nil) },
			wantPanic: false,
		},
		{
			name:      "test GetProfileStatus (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.GetProfileStatus(nil) },
			wantPanic: true,
		},
		{
			name: "test GetAPIVersion",
			fields: fields{
				GetAPIVersionMock: func(ctx context.Context) (version string, err error) { return },
			},
			test:      func(m *MockSubmitter) { m.GetAPIVersion(nil) },
			wantPanic: false,
		},
		{
			name:      "test GetAPIVersion (PANIC)",
			fields:    fields{},
			test:      func(m *MockSubmitter) { m.GetAPIVersion(nil) },
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockSubmitter{
				ExtractExpertViewURLMock: tt.fields.ExtractExpertViewURLMock,
				GetResultByUUIDMock:      tt.fields.GetResultByUUIDMock,
				GetResultBySHA256Mock:    tt.fields.GetResultBySHA256Mock,
				GetResultsMock:           tt.fields.GetResultsMock,
				SubmitFileMock:           tt.fields.SubmitFileMock,
				SubmitReaderMock:         tt.fields.SubmitReaderMock,
				WaitForFileMock:          tt.fields.WaitForFileMock,
				WaitForReaderMock:        tt.fields.WaitForReaderMock,
				GetProfileStatusMock:     tt.fields.GetProfileStatusMock,
				GetAPIVersionMock:        tt.fields.GetAPIVersionMock,
			}
			if tt.wantPanic {
				defer func() { _ = recover() }()
			}
			tt.test(m)
			if tt.wantPanic {
				t.Errorf("test should have panic")
			}
		})
	}
}
