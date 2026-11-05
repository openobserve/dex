package grants

import (
	"net/http"
	"testing"
)

func TestUseIntrospectionHeader(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   bool
	}{
		{"absent", http.Header{}, false},
		{"true", http.Header{"X-Use-Introspection": {"true"}}, true},
		{"lower-case name", http.Header{"x-use-introspection": {"true"}}, true},
		{"false", http.Header{"X-Use-Introspection": {"false"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := useIntrospectionHeader(tc.header); got != tc.want {
				t.Fatalf("useIntrospectionHeader(%v) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
