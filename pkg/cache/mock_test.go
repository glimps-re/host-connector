package cache

import (
	"context"
	"testing"
)

func TestMockCache(t *testing.T) {
	type fields struct {
		SetMock         func(ctx context.Context, entry *Entry) error
		GetMock         func(ctx context.Context, id string) (entry *Entry, err error)
		CloseMock       func() (err error)
		GetBySha256Mock func(ctx context.Context, id string) (entry *Entry, err error)
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
				GetMock: func(ctx context.Context, id string) (entry *Entry, err error) {
					return nil, nil
				},
			},
			test: func(m *MockCache) {
				_, err := m.Get(t.Context(), "")
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
		},
		{
			name:   "test Get (PANIC)",
			fields: fields{},
			test: func(m *MockCache) {
				_, err := m.Get(t.Context(), "")
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test Set",
			fields: fields{
				SetMock: func(ctx context.Context, entry *Entry) error { return nil },
			},
			test: func(m *MockCache) {
				err := m.Set(t.Context(), nil)
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
		},
		{
			name:   "test Set (PANIC)",
			fields: fields{},
			test: func(m *MockCache) {
				err := m.Set(t.Context(), nil)
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test GetBySha256",
			fields: fields{
				GetBySha256Mock: func(ctx context.Context, id string) (entry *Entry, err error) { return },
			},
			test: func(m *MockCache) {
				_, err := m.GetBySha256(t.Context(), "")
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
		},
		{
			name:   "test GetBySha256 (PANIC)",
			fields: fields{},
			test: func(m *MockCache) {
				_, err := m.GetBySha256(t.Context(), "")
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
			wantPanic: true,
		},
		{
			name: "test Close",
			fields: fields{
				CloseMock: func() (err error) { return },
			},
			test: func(m *MockCache) {
				err := m.Close()
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
		},
		{
			name:   "test Close (PANIC)",
			fields: fields{},
			test: func(m *MockCache) {
				err := m.Close()
				if err != nil {
					t.Fatalf("test mock get error : %s", err)
				}
			},
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
