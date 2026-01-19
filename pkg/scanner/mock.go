package scanner

import (
	"context"
	"io"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

var _ Submitter = &mockSubmitter{}

type mockSubmitter struct {
	ExtractExpertViewURLMock func(result *gdetect.Result) (urlExpertView string, err error)
	ExportResultMock         func(ctx context.Context, uuid string, options gdetect.ExportOptions) (data []byte, err error)
	GetResultByUUIDMock      func(ctx context.Context, uuid string) (result gdetect.Result, err error)
	GetResultBySHA256Mock    func(ctx context.Context, sha256 string) (result gdetect.Result, err error)
	GetResultsMock           func(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error)
	SubmitFileMock           func(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error)
	SubmitReaderMock         func(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error)
	WaitForFileMock          func(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error)
	WaitForReaderMock        func(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error)
	GetProfileStatusMock     func(ctx context.Context) (status gdetect.ProfileStatus, err error)
	GetAPIVersionMock        func(ctx context.Context) (version string, err error)

	ReconfigureMock func(ctx context.Context, config gdetect.ClientConfig) (err error)
}

func (m *mockSubmitter) ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error) {
	if m.ExtractExpertViewURLMock != nil {
		return m.ExtractExpertViewURLMock(result)
	}
	panic("ExtractExpertViewURL not implemented")
}

func (m *mockSubmitter) ExportResult(ctx context.Context, uuid string, options gdetect.ExportOptions) (data []byte, err error) {
	if m.ExportResultMock != nil {
		return m.ExportResultMock(ctx, uuid, options)
	}
	panic("ExportResult not implemented")
}

func (m *mockSubmitter) GetResultByUUID(ctx context.Context, uuid string) (result gdetect.Result, err error) {
	if m.GetResultByUUIDMock != nil {
		return m.GetResultByUUIDMock(ctx, uuid)
	}
	panic("GetResultByUUID not implemented")
}

func (m *mockSubmitter) GetResultBySHA256(ctx context.Context, sha256 string) (result gdetect.Result, err error) {
	if m.GetResultBySHA256Mock != nil {
		return m.GetResultBySHA256Mock(ctx, sha256)
	}
	panic("GetResultBySHA256 not implemented")
}

func (m *mockSubmitter) GetResults(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error) {
	if m.GetResultsMock != nil {
		return m.GetResultsMock(ctx, from, size, tags...)
	}
	panic("GetResults not implemented")
}

func (m *mockSubmitter) SubmitFile(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitFileMock != nil {
		return m.SubmitFileMock(ctx, filepath, options)
	}
	panic("SubmitFile not implemented")
}

func (m *mockSubmitter) SubmitReader(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitReaderMock != nil {
		return m.SubmitReaderMock(ctx, r, options)
	}
	panic("SubmitReader not implemented")
}

func (m *mockSubmitter) WaitForFile(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForFileMock != nil {
		return m.WaitForFileMock(ctx, filepath, options)
	}
	panic("WaitForFile not implemented")
}

func (m *mockSubmitter) WaitForReader(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForReaderMock != nil {
		return m.WaitForReaderMock(ctx, r, options)
	}
	panic("WaitForReader not implemented")
}

func (m *mockSubmitter) GetProfileStatus(ctx context.Context) (status gdetect.ProfileStatus, err error) {
	if m.GetProfileStatusMock != nil {
		return m.GetProfileStatusMock(ctx)
	}
	panic("GetProfileStatus not implemented")
}

func (m *mockSubmitter) GetAPIVersion(ctx context.Context) (version string, err error) {
	if m.GetAPIVersionMock != nil {
		return m.GetAPIVersionMock(ctx)
	}
	panic("GetAPIVersion not implemented")
}

func (m *mockSubmitter) Reconfigure(ctx context.Context, config gdetect.ClientConfig) (err error) {
	if m.ReconfigureMock != nil {
		return m.ReconfigureMock(ctx, config)
	}
	panic("Reconfigure not implemented")
}
