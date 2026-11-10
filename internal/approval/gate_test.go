package approval

import (
	"reflect"
	"testing"

	"github.com/it-atelier-gn/desktop-secrets/internal/prompt"
)

func TestCheckBatchEmptyDoesNotPrompt(t *testing.T) {
	calls := 0
	g := NewGate(NewStore(), func(prompt.ApprovalRequest) (prompt.ApprovalDecision, error) {
		calls++
		return prompt.ApprovalDecision{Allow: true}, nil
	})
	if _, err := g.CheckBatch(0, nil); err != nil {
		t.Fatalf("CheckBatch: %v", err)
	}
	if calls != 0 {
		t.Fatalf("prompted %d times, want 0", calls)
	}
}

func TestCheckBatchPromptsOnceWithAllRefs(t *testing.T) {
	var reqs []prompt.ApprovalRequest
	g := NewGate(NewStore(), func(req prompt.ApprovalRequest) (prompt.ApprovalDecision, error) {
		reqs = append(reqs, req)
		return prompt.ApprovalDecision{Allow: true}, nil
	})
	items := []BatchItem{{Key: "k1", Ref: "user(a)"}, {Key: "k2", Ref: "user(b)"}}
	factor, err := g.CheckBatch(0, items)
	if err != nil {
		t.Fatalf("CheckBatch: %v", err)
	}
	if factor != "click" {
		t.Fatalf("factor = %q, want click", factor)
	}
	if len(reqs) != 1 {
		t.Fatalf("prompted %d times, want 1", len(reqs))
	}
	if want := []string{"user(a)", "user(b)"}; !reflect.DeepEqual(reqs[0].ProviderRefs, want) {
		t.Fatalf("ProviderRefs = %v, want %v", reqs[0].ProviderRefs, want)
	}
}

func TestCheckBatchDeny(t *testing.T) {
	g := NewGate(NewStore(), func(prompt.ApprovalRequest) (prompt.ApprovalDecision, error) {
		return prompt.ApprovalDecision{Allow: false}, nil
	})
	_, err := g.CheckBatch(0, []BatchItem{{Key: "k1", Ref: "r1"}, {Key: "k2", Ref: "r2"}})
	if err != ErrDenied {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}
