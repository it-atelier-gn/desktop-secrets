package audit

import "testing"

func TestEventForDecision(t *testing.T) {
	cases := []struct {
		d    Decision
		want event
	}{
		{DecisionAllowed, event{ID: 100}},
		{DecisionCached, event{ID: 101}},
		{DecisionDenied, event{ID: 200, Warning: true}},
		{DecisionForgotten, event{ID: 201, Warning: true}},
		{DecisionUnlockFailed, event{ID: 202, Warning: true}},
		{DecisionOSAuthFailed, event{ID: 203, Warning: true}},
		{Decision("unknown"), event{ID: 299, Warning: true}},
	}
	for _, c := range cases {
		if got := eventFor(c.d); got != c.want {
			t.Errorf("eventFor(%q) = %+v, want %+v", c.d, got, c.want)
		}
	}
}

func TestEventIDsFitEventCreate(t *testing.T) {
	for _, d := range []Decision{DecisionAllowed, DecisionCached, DecisionDenied, DecisionForgotten, DecisionUnlockFailed, DecisionOSAuthFailed, "unknown"} {
		if id := eventFor(d).ID; id < 1 || id > 1000 {
			t.Errorf("event ID %d for %q is outside 1..1000", id, d)
		}
	}
	if EventPolicyChanged < 1 || EventPolicyChanged > 1000 {
		t.Errorf("EventPolicyChanged %d is outside 1..1000", EventPolicyChanged)
	}
}
