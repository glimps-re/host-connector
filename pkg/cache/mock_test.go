package cache

import (
	"reflect"
	"testing"
)

func TestMockCache_Get(t *testing.T) {
	type fields struct {
		SetMock func(entry *Entry) error
		GetMock func(id string) (entry *Entry, err error)
	}
	type args struct {
		id string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *Entry
		wantErr bool
	}{
		{
			name: "test",
			fields: fields{
				GetMock: func(id string) (entry *Entry, err error) {
					return nil, nil
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockCache{
				SetMock: tt.fields.SetMock,
				GetMock: tt.fields.GetMock,
			}
			got, err := m.Get(tt.args.id)
			if (err != nil) != tt.wantErr {
				t.Errorf("MockCache.Get() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MockCache.Get() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockCache_Set(t *testing.T) {
	type fields struct {
		SetMock func(entry *Entry) error
		GetMock func(id string) (entry *Entry, err error)
	}
	type args struct {
		entry *Entry
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			fields: fields{SetMock: func(entry *Entry) error { return nil }},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MockCache{
				SetMock: tt.fields.SetMock,
				GetMock: tt.fields.GetMock,
			}
			if err := m.Set(tt.args.entry); (err != nil) != tt.wantErr {
				t.Errorf("MockCache.Set() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
