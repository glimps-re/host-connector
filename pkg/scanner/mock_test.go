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
			test: func(m *MockLock) {
				err := m.LockFile("", nil, &LockFileInfo{}, "", nil)
				if err != nil {
					t.Fatalf("MockLock cannot lock file : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test Lock file (panic)",
			fields: fields{},
			test: func(m *MockLock) {
				err := m.LockFile("", nil, &LockFileInfo{}, "", nil)
				if err != nil {
					t.Fatalf("MockLock cannot lock file : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test Unlock file",
			fields: fields{
				UnlockFileMock: func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
					return "", &LockFileInfo{}, "", nil
				},
			},
			test: func(m *MockLock) {
				_, _, _, err := m.UnlockFile(nil, nil)
				if err != nil {
					t.Fatalf("MockLock cannot unlock file : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test Unlock file (panic)",
			fields: fields{},
			test: func(m *MockLock) {
				_, _, _, err := m.UnlockFile(nil, nil)
				if err != nil {
					t.Fatalf("MockLock cannot unlock file : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test GetHeader",
			fields: fields{
				GetHeaderMock: func(in io.Reader) (entry LockEntry, err error) {
					return
				},
			},
			test: func(m *MockLock) {
				_, err := m.GetHeader(nil)
				if err != nil {
					t.Fatalf("MockLock cannot get header : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetHeader (panic)",
			fields: fields{},
			test: func(m *MockLock) {
				_, err := m.GetHeader(nil)
				if err != nil {
					t.Fatalf("MocLock cannot get header : %s", err)
				}
			},
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
			test: func(m *MockSubmitter) {
				_, err := m.ExtractExpertViewURL(nil)
				if err != nil {
					t.Fatalf("MockSubmitter cannot extract : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test ExtractExpertViewURL (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.ExtractExpertViewURL(nil)
				if err != nil {
					t.Fatalf("MockSubmitter cannot extract : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test GetResultByUUID",
			fields: fields{
				GetResultByUUIDMock: func(ctx context.Context, uuid string) (result gdetect.Result, err error) { return },
			},
			test: func(m *MockSubmitter) {
				_, err := m.GetResultByUUID(context.TODO(), "")
				if err != nil {
					t.Fatalf("MockSubmitter cannot get result : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetResultByUUID (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.GetResultByUUID(context.TODO(), "")
				if err != nil {
					t.Fatalf("MockSubmitter cannot get result : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test GetResultBySHA256",
			fields: fields{
				GetResultBySHA256Mock: func(ctx context.Context, sha256 string) (result gdetect.Result, err error) { return },
			},
			test: func(m *MockSubmitter) {
				_, err := m.GetResultBySHA256(context.TODO(), "")
				if err != nil {
					t.Fatalf("MockSubmitter cannot get result : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetResultBySHA256 (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.GetResultBySHA256(context.TODO(), "")
				if err != nil {
					t.Fatalf("MockSubmitter cannot get result : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test GetResults",
			fields: fields{
				GetResultsMock: func(ctx context.Context, from, size int, tags ...string) (submissions []gdetect.Submission, err error) {
					return
				},
			},
			test: func(m *MockSubmitter) {
				_, err := m.GetResults(context.TODO(), 0, 0)
				if err != nil {
					t.Fatalf("MockSubmitter cannot get results : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetResults (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.GetResults(context.TODO(), 0, 0)
				if err != nil {
					t.Fatalf("MockSubmitter cannot get results : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test SubmitFile",
			fields: fields{
				SubmitFileMock: func(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error) {
					return
				},
			},
			test: func(m *MockSubmitter) {
				_, err := m.SubmitFile(context.TODO(), "", gdetect.SubmitOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot submit file : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test SubmitFile (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.SubmitFile(context.TODO(), "", gdetect.SubmitOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot submit file : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test SubmitReader",
			fields: fields{
				SubmitReaderMock: func(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error) { return },
			},
			test: func(m *MockSubmitter) {
				_, err := m.SubmitReader(context.TODO(), nil, gdetect.SubmitOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot submit reader : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test SubmitReader (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.SubmitReader(context.TODO(), nil, gdetect.SubmitOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot submit reader : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test WaitForFile",
			fields: fields{
				WaitForFileMock: func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
					return
				},
			},
			test: func(m *MockSubmitter) {
				_, err := m.WaitForFile(context.TODO(), "", gdetect.WaitForOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot wait for file : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test WaitForFile (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.WaitForFile(context.TODO(), "", gdetect.WaitForOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot wait for file : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test WaitForReader",
			fields: fields{
				WaitForReaderMock: func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
					return
				},
			},
			test: func(m *MockSubmitter) {
				_, err := m.WaitForReader(context.TODO(), nil, gdetect.WaitForOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot wait for reader : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test WaitForReader (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.WaitForReader(context.TODO(), nil, gdetect.WaitForOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot wait for reader : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test GetProfileStatus",
			fields: fields{
				GetProfileStatusMock: func(ctx context.Context) (status gdetect.ProfileStatus, err error) { return },
			},
			test: func(m *MockSubmitter) {
				_, err := m.GetProfileStatus(context.TODO())
				if err != nil {
					t.Fatalf("MockSubmitter cannot get profile status : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetProfileStatus (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.GetProfileStatus(context.TODO())
				if err != nil {
					t.Fatalf("MockSubmitter cannot get profile status : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test GetAPIVersion",
			fields: fields{
				GetAPIVersionMock: func(ctx context.Context) (version string, err error) { return },
			},
			test: func(m *MockSubmitter) {
				_, err := m.GetAPIVersion(context.TODO())
				if err != nil {
					t.Fatalf("MockSubmitter cannot get api version : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetAPIVersion (PANIC)",
			fields: fields{},
			test: func(m *MockSubmitter) {
				_, err := m.GetAPIVersion(context.TODO())
				if err != nil {
					t.Fatalf("MockSubmitter cannot get api version : %s", err)
				}
			},
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
