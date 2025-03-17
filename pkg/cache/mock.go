package cache

type MockCache struct {
	SetMock         func(entry *Entry) error
	GetMock         func(id string) (entry *Entry, err error)
	CloseMock       func() error
	GetBySha256Mock func(id string) (*Entry, error)
}

func (m *MockCache) Set(entry *Entry) error {
	if m.SetMock != nil {
		return m.SetMock(entry)
	}
	panic("SetMock not implemented")
}

func (m *MockCache) Get(id string) (*Entry, error) {
	if m.GetMock != nil {
		return m.GetMock(id)
	}
	panic("GetMock not implemented")
}

func (m *MockCache) GetBySha256(id string) (*Entry, error) {
	if m.GetBySha256Mock != nil {
		return m.GetBySha256Mock(id)
	}
	panic("GetBySha256Mock not implemented")
}

func (m *MockCache) Close() error {
	if m.CloseMock != nil {
		return m.CloseMock()
	}
	panic("CloseMock not implemented")
}
