package scanner

import (
	"context"
	"io"
	"testing"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

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
		test      func(m *mockSubmitter)
	}{
		{
			name: "test ExtractExpertViewURL",
			fields: fields{
				ExtractExpertViewURLMock: func(result *gdetect.Result) (urlExpertView string, err error) { return },
			},
			test: func(m *mockSubmitter) {
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
			test: func(m *mockSubmitter) {
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
			test: func(m *mockSubmitter) {
				_, err := m.GetResultByUUID(t.Context(), "")
				if err != nil {
					t.Fatalf("MockSubmitter cannot get result : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetResultByUUID (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.GetResultByUUID(t.Context(), "")
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
			test: func(m *mockSubmitter) {
				_, err := m.GetResultBySHA256(t.Context(), "")
				if err != nil {
					t.Fatalf("MockSubmitter cannot get result : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetResultBySHA256 (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.GetResultBySHA256(t.Context(), "")
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
			test: func(m *mockSubmitter) {
				_, err := m.GetResults(t.Context(), 0, 0)
				if err != nil {
					t.Fatalf("MockSubmitter cannot get results : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetResults (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.GetResults(t.Context(), 0, 0)
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
			test: func(m *mockSubmitter) {
				_, err := m.SubmitFile(t.Context(), "", gdetect.SubmitOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot submit file : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test SubmitFile (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.SubmitFile(t.Context(), "", gdetect.SubmitOptions{})
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
			test: func(m *mockSubmitter) {
				_, err := m.SubmitReader(t.Context(), nil, gdetect.SubmitOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot submit reader : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test SubmitReader (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.SubmitReader(t.Context(), nil, gdetect.SubmitOptions{})
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
			test: func(m *mockSubmitter) {
				_, err := m.WaitForFile(t.Context(), "", gdetect.WaitForOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot wait for file : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test WaitForFile (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.WaitForFile(t.Context(), "", gdetect.WaitForOptions{})
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
			test: func(m *mockSubmitter) {
				_, err := m.WaitForReader(t.Context(), nil, gdetect.WaitForOptions{})
				if err != nil {
					t.Fatalf("MockSubmitter cannot wait for reader : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test WaitForReader (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.WaitForReader(t.Context(), nil, gdetect.WaitForOptions{})
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
			test: func(m *mockSubmitter) {
				_, err := m.GetProfileStatus(t.Context())
				if err != nil {
					t.Fatalf("MockSubmitter cannot get profile status : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetProfileStatus (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.GetProfileStatus(t.Context())
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
			test: func(m *mockSubmitter) {
				_, err := m.GetAPIVersion(t.Context())
				if err != nil {
					t.Fatalf("MockSubmitter cannot get api version : %s", err)
				}
			},
			wantPanic: false,
		},
		{
			name:   "test GetAPIVersion (PANIC)",
			fields: fields{},
			test: func(m *mockSubmitter) {
				_, err := m.GetAPIVersion(t.Context())
				if err != nil {
					t.Fatalf("MockSubmitter cannot get api version : %s", err)
				}
			},
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &mockSubmitter{
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
