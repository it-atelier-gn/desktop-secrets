package vault

import "testing"

func TestSelectField(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		field   string
		want    string
		wantErr bool
	}{
		{"single key no field", `{"value":"v1"}`, "", "v1", false},
		{"multi keys no field returns raw", `{"a":"x","b":"y"}`, "", `{"a":"x","b":"y"}`, false},
		{"named field", `{"username":"alice","password":"p"}`, "password", "p", false},
		{"missing field", `{"a":"x"}`, "b", "", true},
		{"number field", `{"port":5432}`, "port", "5432", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := selectField(tc.json, tc.field)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
