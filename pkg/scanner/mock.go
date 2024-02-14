package scanner

import (
	"context"
	"io"
	"os"

	"github.com/glimps-re/go-gdetect/pkg/gdetect"
)

var _ Locker = &MockLock{}

type MockLock struct {
	LockFileMock   func(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error
	UnlockFileMock func(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error)
	GetHeaderMock  func(in io.Reader) (entry LockEntry, err error)
}

func (m *MockLock) LockFile(file string, in io.Reader, info os.FileInfo, reason string, out io.Writer) error {
	if m.LockFileMock != nil {
		return m.LockFileMock(file, in, info, reason, out)
	}
	panic("LockFile not implemented")
}

func (m *MockLock) UnlockFile(in io.Reader, out io.Writer) (file string, info os.FileInfo, reason string, err error) {
	if m.UnlockFileMock != nil {
		return m.UnlockFileMock(in, out)
	}
	panic("UnlockFile not implemented")
}

func (m *MockLock) GetHeader(in io.Reader) (entry LockEntry, err error) {
	if m.GetHeaderMock != nil {
		return m.GetHeaderMock(in)
	}
	panic("GetHeader not implemented")
}

var _ Submitter = &MockSubmitter{}

type MockSubmitter struct {
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

func (m *MockSubmitter) ExtractExpertViewURL(result *gdetect.Result) (urlExpertView string, err error) {
	if m.ExtractExpertViewURLMock != nil {
		return m.ExtractExpertViewURLMock(result)
	}
	panic("ExtractExpertViewURL not implemented")
}

func (m *MockSubmitter) GetResultByUUID(ctx context.Context, uuid string) (result gdetect.Result, err error) {
	if m.GetResultByUUIDMock != nil {
		return m.GetResultByUUIDMock(ctx, uuid)
	}
	panic("GetResultByUUID not implemented")
}

func (m *MockSubmitter) GetResultBySHA256(ctx context.Context, sha256 string) (result gdetect.Result, err error) {
	if m.GetResultBySHA256Mock != nil {
		return m.GetResultBySHA256Mock(ctx, sha256)
	}
	panic("GetResultBySHA256 not implemented")
}

func (m *MockSubmitter) GetResults(ctx context.Context, from int, size int, tags ...string) (submissions []gdetect.Submission, err error) {
	if m.GetResultsMock != nil {
		return m.GetResultsMock(ctx, from, size, tags...)
	}
	panic("GetResults not implemented")
}

func (m *MockSubmitter) SubmitFile(ctx context.Context, filepath string, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitFileMock != nil {
		return m.SubmitFileMock(ctx, filepath, options)
	}
	panic("SubmitFile not implemented")
}

func (m *MockSubmitter) SubmitReader(ctx context.Context, r io.Reader, options gdetect.SubmitOptions) (uuid string, err error) {
	if m.SubmitReaderMock != nil {
		return m.SubmitReaderMock(ctx, r, options)
	}
	panic("SubmitReader not implemented")
}

func (m *MockSubmitter) WaitForFile(ctx context.Context, filepath string, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForFileMock != nil {
		return m.WaitForFileMock(ctx, filepath, options)
	}
	panic("WaitForFile not implemented")
}

func (m *MockSubmitter) WaitForReader(ctx context.Context, r io.Reader, options gdetect.WaitForOptions) (result gdetect.Result, err error) {
	if m.WaitForReaderMock != nil {
		return m.WaitForReaderMock(ctx, r, options)
	}
	panic("WaitForReader not implemented")
}

func (m *MockSubmitter) GetProfileStatus(ctx context.Context) (status gdetect.ProfileStatus, err error) {
	if m.GetProfileStatusMock != nil {
		return m.GetProfileStatusMock(ctx)
	}
	panic("GetProfileStatus not implemented")
}

func (m *MockSubmitter) GetAPIVersion(ctx context.Context) (version string, err error) {
	if m.GetAPIVersionMock != nil {
		return m.GetAPIVersionMock(ctx)
	}
	panic("GetAPIVersion not implemented")
}
