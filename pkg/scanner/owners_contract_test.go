package scanner

import (
	"errors"
	"testing"
)

func TestOwnerOf_cardTable(t *testing.T) {
	tests := []struct {
		name    string
		rules   []OwnerRule
		watched []string
		path    string
		want    string
	}{
		{"depth 2: user folder", []OwnerRule{{"/in", 2}}, []string{"/in"}, "/in/eq1/alice/a/b.txt", "/in/eq1/alice"},
		{"depth 2: exactly at depth", []OwnerRule{{"/in", 2}}, []string{"/in"}, "/in/eq1/alice/f.txt", "/in/eq1/alice"},
		{"depth 2: file in the team folder", []OwnerRule{{"/in", 2}}, []string{"/in"}, "/in/eq1/f.txt", "/in/eq1"},
		{"depth 2: file at the root", []OwnerRule{{"/in", 2}}, []string{"/in"}, "/in/f.txt", "/in"},
		{"depth 1", []OwnerRule{{"/in", 1}}, []string{"/in"}, "/in/alice/deep/f.txt", "/in/alice"},
		{"no declaration: first level under the watched path", nil, []string{"/in"}, "/in/alice/deep/f.txt", "/in/alice"},
		{"no declaration: file at the watched root", nil, []string{"/in"}, "/in/f.txt", "/in"},
		{"nested watched path does not split a user", nil, []string{"/in", "/in/alice"}, "/in/alice/x/f.txt", "/in/alice"},
		{"nested watched path, other order", nil, []string{"/in/alice", "/in"}, "/in/alice/x/f.txt", "/in/alice"},
		{"root deeper than the watched path", []OwnerRule{{"/in/users", 1}}, []string{"/in"}, "/in/users/bob/f.txt", "/in/users/bob"},
		{"outside the declared root: default rule", []OwnerRule{{"/in/users", 1}}, []string{"/in"}, "/in/shared/f.txt", "/in/shared"},
		{"disjoint root", []OwnerRule{{"/srv/drop", 1}}, []string{"/in"}, "/in/carol/f.txt", "/in/carol"},
		{"sibling name sharing a prefix is not under the root", []OwnerRule{{"/in", 1}}, []string{"/in", "/in2"}, "/in2/dave/f.txt", "/in2/dave"},
		{"unclean path", []OwnerRule{{"/in", 2}}, []string{"/in"}, "/in//eq1/./alice/../alice/f.txt", "/in/eq1/alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := OwnerOf(tt.path, tt.rules, tt.watched); got != tt.want {
				t.Errorf("OwnerOf(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestDeclareOwners_cardCases(t *testing.T) {
	declared := []OwnerRule{{"/in", 2}}
	tests := []struct {
		name    string
		rules   []OwnerRule
		root    string
		depth   int
		wantErr bool
	}{
		{"first declaration", nil, "/in", 2, false},
		{"same root twice", declared, "/in", 2, true},
		{"root contained in a declared one", declared, "/in/sub", 1, true},
		{"root containing a declared one", declared, "/", 1, true},
		{"disjoint roots", declared, "/srv/drop", 1, false},
		{"sibling sharing a name prefix", declared, "/in2", 1, false},
		{"depth zero", nil, "/in", 0, true},
		{"negative depth", nil, "/in", -1, true},
		{"relative root", nil, "in", 1, true},
		{"empty root", nil, "", 1, true},
		{"unclean root is normalised before the comparison", declared, "/in/./sub/../", 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DeclareOwners(tt.rules, tt.root, tt.depth)
			if (err != nil) != tt.wantErr {
				t.Fatalf("DeclareOwners() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err != nil {
				if !errors.Is(err, ErrInvalidOwnerRule) {
					t.Errorf("error = %v, want ErrInvalidOwnerRule", err)
				}
				if len(got) != len(tt.rules) {
					t.Errorf("a refused declaration must leave the rules unchanged, got %v", got)
				}
				return
			}
			if len(got) != len(tt.rules)+1 {
				t.Errorf("rules = %v, want the new one appended", got)
			}
		})
	}
}
