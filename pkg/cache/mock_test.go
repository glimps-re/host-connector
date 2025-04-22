package cache

import (
	"testing"
)

func TestMockCache(t *testing.T) {
	type fields struct {
		SetMock         func(entry *Entry) error
		GetMock         func(id string) (entry *Entry, err error)
		CloseMock       func() (err error)
		GetBySha256Mock func(id string) (entry *Entry, err error)
	}
	tests := []struct {
		name      string
		fields    fields
		test      func(m *MockCache)
		wantPanic bool
	}{
		{
			name: "test Get",
			fields: fields{
				GetMock: func(id string) (entry *Entry, err error) {
					return nil, nil
				},
			},
			test: func(m *MockCache) {
				m.Get("") //nolint:errcheck,gosec // we just test that calling the mock panic or not
			},
		},
		{
			name:   "test Get (PANIC)",
			fields: fields{},
			test: func(m *MockCache) {
				m.Get("") //nolint:errcheck,gosec // we just test that calling the mock panic or not
			},
			wantPanic: true,
		},
		{
			name: "test Set",
			fields: fields{
				SetMock: func(entry *Entry) error { return nil },
			},
			test: func(m *MockCache) { m.Set(nil) }, //nolint:errcheck,gosec // we just test that calling the mock panic or not
		},
		{
			name:      "test Set (PANIC)",
			fields:    fields{},
			test:      func(m *MockCache) { m.Set(nil) }, //nolint:errcheck,gosec // we just test that calling the mock panic or not
			wantPanic: true,
		},
		{
			name: "test GetBySha256",
			fields: fields{
				GetBySha256Mock: func(id string) (entry *Entry, err error) { return },
			},
			test: func(m *MockCache) { m.GetBySha256("") }, //nolint:errcheck,gosec // we just test that calling the mock panic or not
		},
		{
			name:      "test GetBySha256 (PANIC)",
			fields:    fields{},
			test:      func(m *MockCache) { m.GetBySha256("") }, //nolint:errcheck,gosec // we just test that calling the mock panic or not
			wantPanic: true,
		},
		{
			name: "test Close",
			fields: fields{
				CloseMock: func() (err error) { return },
			},
			test: func(m *MockCache) { m.Close() }, //nolint:errcheck,gosec // we just test that calling the mock panic or not
		},
		{
			name:      "test Close (PANIC)",
			fields:    fields{},
			test:      func(m *MockCache) { m.Close() }, //nolint:errcheck,gosec // we just test that calling the mock panic or not
			wantPanic: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockCache{
				SetMock:         tt.fields.SetMock,
				GetMock:         tt.fields.GetMock,
				CloseMock:       tt.fields.CloseMock,
				GetBySha256Mock: tt.fields.GetBySha256Mock,
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
