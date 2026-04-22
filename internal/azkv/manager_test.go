package azkv

import "testing"

func TestSplitVaultAndName(t *testing.T) {
	cases := []struct {
		in         string
		wantVault  string
		wantName   string
		wantErr    bool
	}{
		{"mykv/dbpass", "mykv", "dbpass", false},
		{"https://mykv.vault.azure.net/dbpass", "https://mykv.vault.azure.net", "dbpass", false},
		{"nosep", "", "", true},
		{"/name", "", "", true},
		{"vault/", "", "", true},
		{"", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			v, n, err := splitVaultAndName(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err == nil && (v != tc.wantVault || n != tc.wantName) {
				t.Fatalf("got (%q,%q) want (%q,%q)", v, n, tc.wantVault, tc.wantName)
			}
		})
	}
}

func TestVaultURL(t *testing.T) {
	if got := vaultURL("mykv"); got != "https://mykv.vault.azure.net" {
		t.Fatalf("vaultURL(mykv)=%q", got)
	}
	if got := vaultURL("https://mykv.vault.azure.net"); got != "https://mykv.vault.azure.net" {
		t.Fatalf("vaultURL passthrough failed: %q", got)
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
		{"json string", `{"u":"a","p":"b"}`, "p", "b", false},
		{"json number", `{"port":5432}`, "port", "5432", false},
		{"missing", `{"u":"a"}`, "p", "", true},
		{"not json", "x", "p", "", true},
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
