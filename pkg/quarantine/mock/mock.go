package mock

import (
	"context"
	"iter"

	"github.com/glimps-re/host-connector/pkg/quarantine"
)

type QuarantineMock struct {
	QuarantineMock           func(ctx context.Context, file string, fileSHA256 string, malwares []string) (quarantineLocation string, entryID string, err error)
	RestoreMock              func(ctx context.Context, entryID string) (err error)
	ReconfigureMock          func(ctx context.Context, newConfig quarantine.Config) (err error)
	IsRestoredMock           func(ctx context.Context, sha256 string) (restored bool, err error)
	ListQuarantinedFilesMock func(ctx context.Context) iter.Seq2[*quarantine.QuarantinedFile, error]
	CloseMock                func() (err error)
}

func (q *QuarantineMock) Quarantine(ctx context.Context, file string, fileSHA256 string, malwares []string) (quarantineLocation string, entryID string, err error) {
	if q.QuarantineMock != nil {
		return q.QuarantineMock(ctx, file, fileSHA256, malwares)
	}
	panic("QuarantineMock not implemented in current test")
}

func (q *QuarantineMock) Restore(ctx context.Context, entryID string) (err error) {
	if q.RestoreMock != nil {
		return q.RestoreMock(ctx, entryID)
	}
	panic("RestoreMock not implemented in current test")
}

func (q *QuarantineMock) Reconfigure(ctx context.Context, config quarantine.Config) (err error) {
	if q.ReconfigureMock != nil {
		return q.ReconfigureMock(ctx, config)
	}
	panic("ReconfigureMock not implemented in current test")
}

func (q *QuarantineMock) IsRestored(ctx context.Context, sha256 string) (restored bool, err error) {
	if q.IsRestoredMock != nil {
		return q.IsRestoredMock(ctx, sha256)
	}
	panic("IsRestoredMock not implemented in current test")
}

func (q *QuarantineMock) ListQuarantinedFiles(ctx context.Context) iter.Seq2[*quarantine.QuarantinedFile, error] {
	if q.ListQuarantinedFilesMock != nil {
		return q.ListQuarantinedFilesMock(ctx)
	}
	panic("ListQuarantinedFilesMock not implemented in current test")
}

func (q *QuarantineMock) Close() (err error) {
	if q.CloseMock != nil {
		return q.CloseMock()
	}
	panic("CloseMock not implemented in current test")
}
