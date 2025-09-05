package cache

import "context"

type MockCache struct {
	SetMock         func(ctx context.Context, entry *Entry) error
	GetMock         func(ctx context.Context, id string) (entry *Entry, err error)
	CloseMock       func() error
	GetBySha256Mock func(ctx context.Context, id string) (*Entry, error)
}

func (m *MockCache) Set(ctx context.Context, entry *Entry) error {
	if m.SetMock != nil {
		return m.SetMock(ctx, entry)
	}
	panic("SetMock not implemented")
}

func (m *MockCache) Get(ctx context.Context, id string) (*Entry, error) {
	if m.GetMock != nil {
		return m.GetMock(ctx, id)
	}
	panic("GetMock not implemented")
}

func (m *MockCache) GetBySha256(ctx context.Context, id string) (*Entry, error) {
	if m.GetBySha256Mock != nil {
		return m.GetBySha256Mock(ctx, id)
	}
	panic("GetBySha256Mock not implemented")
}

func (m *MockCache) Close() error {
	if m.CloseMock != nil {
		return m.CloseMock()
	}
	panic("CloseMock not implemented")
}
