package aws

import (
	"testing"
)

func TestExtractField(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		field   string
		want    string
		wantErr bool
	}{
		{"no field returns raw", "rawvalue", "", "rawvalue", false},
		{"json string field", `{"username":"alice","password":"secret"}`, "username", "alice", false},
		{"json password field", `{"username":"alice","password":"secret"}`, "password", "secret", false},
		{"json missing field", `{"username":"alice"}`, "password", "", true},
		{"non-json with field", "notjson", "key", "", true},
		{"json number field", `{"port":5432}`, "port", "5432", false},
		{"empty value no field", "", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractField(tc.value, tc.field)
			if (err != nil) != tc.wantErr {
				t.Fatalf("extractField(%q, %q) err=%v, wantErr=%v", tc.value, tc.field, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("extractField(%q, %q) = %q, want %q", tc.value, tc.field, got, tc.want)
			}
		})
	}
}
