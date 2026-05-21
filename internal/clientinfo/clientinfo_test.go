package clientinfo

import "testing"

func TestIsTplenvRun(t *testing.T) {
	cases := []struct {
		name    string
		exe     string
		cmdline string
		want    bool
	}{
		{"tplenv run", "/usr/bin/tplenv", "tplenv run -- mycmd arg", true},
		{"tplenv run windows", "C:\\bin\\tplenv.exe", "tplenv.exe run cmd", true},
		{"tplenv with flags before run", "tplenv", "tplenv --only FOO run cmd", true},
		{"tplenv without run", "tplenv", "tplenv --only FOO", false},
		{"tplenv export", "tplenv", "tplenv export", false},
		{"getsec is not tplenv", "getsec", "getsec run", false},
		{"other binary", "python", "python tplenv run", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := Info{ExePath: tc.exe, Cmdline: tc.cmdline}
			if got := info.IsTplenvRun(); got != tc.want {
				t.Fatalf("IsTplenvRun(%q,%q)=%v, want %v", tc.exe, tc.cmdline, got, tc.want)
			}
		})
	}
}
