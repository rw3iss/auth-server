package domain

import (
	"reflect"
	"testing"
)

func TestExcludeHomeNamespace(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		home string
		want []string
	}{
		{"drops home", []string{"a", "home", "b"}, "home", []string{"a", "b"}},
		{"drops empties", []string{"", "a", "", "b"}, "home", []string{"a", "b"}},
		{"home absent is no-op", []string{"a", "b"}, "home", []string{"a", "b"}},
		{"all home", []string{"home", "home"}, "home", []string{}},
		{"nil input", nil, "home", []string{}},
		{"empty home keeps non-empty", []string{"a", ""}, "", []string{"a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExcludeHomeNamespace(c.in, c.home)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("ExcludeHomeNamespace(%v, %q) = %v, want %v", c.in, c.home, got, c.want)
			}
		})
	}
}

// The result must never alias the home pool — every provisioning path relies
// on the tag set being home-free so users.namespace isn't double-counted.
func TestExcludeHomeNamespaceNeverContainsHome(t *testing.T) {
	got := ExcludeHomeNamespace([]string{"x", "home", "y", "home"}, "home")
	for _, ns := range got {
		if ns == "home" {
			t.Fatalf("home leaked into tag set: %v", got)
		}
	}
}
