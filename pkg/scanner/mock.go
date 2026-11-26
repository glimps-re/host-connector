package scanner

import (
	"context"

	"github.com/glimps-re/host-connector/pkg/datamodel"
)

type MockAction struct {
	HandleMock func(ctx context.Context, src Source, result datamodel.Result, analysisReport *datamodel.Report) error
}

func (m *MockAction) Handle(ctx context.Context, src Source, result datamodel.Result, analysisReport *datamodel.Report) (err error) {
	if m.HandleMock != nil {
		return m.HandleMock(ctx, src, result, analysisReport)
	}
	panic("HandleMock() not implemented")
}
