package gcpsm

import "testing"

func TestBuildResourceName(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"my-proj/mysecret", "projects/my-proj/secrets/mysecret/versions/latest", false},
		{"my-proj/mysecret/5", "projects/my-proj/secrets/mysecret/versions/5", false},
		{"projects/my-proj/secrets/mysecret/versions/7", "projects/my-proj/secrets/mysecret/versions/7", false},
		{"nosep", "", true},
		{"/mysecret", "", true},
		{"my-proj/", "", true},
		{"", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := buildResourceName(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestExtractField(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		field   string
		want    string
		wantErr bool
	}{
		{"raw", "val", "", "val", false},
		{"json", `{"a":"b"}`, "a", "b", false},
		{"missing", `{"a":"b"}`, "c", "", true},
		{"not json", "xx", "k", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractField(tc.value, tc.field)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
