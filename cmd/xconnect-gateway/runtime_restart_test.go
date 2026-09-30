package main

import "testing"

func TestXrayRestartRequired(t *testing.T) {
	for _, tc := range []struct {
		name, applied, current string
		active, want           bool
	}{
		{"unchanged", "same", "same", true, false},
		{"changed", "old", "new", true, true},
		{"stopped", "same", "same", false, true},
		{"first apply", "", "new", true, true},
		{"failed restart retry", "old", "new", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := xrayRestartRequired(tc.applied, tc.current, tc.active); got != tc.want {
				t.Fatalf("restart=%v want=%v", got, tc.want)
			}
		})
	}
}
