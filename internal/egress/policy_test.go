package egress

import (
	"testing"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

func TestPolicyRequiresExactHostAndPort(t *testing.T) {
	policy, err := NewPolicy([]string{"api.example.com"}, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Check(protocol.Target{Host: "API.EXAMPLE.COM.", Port: 443}); err != nil {
		t.Fatalf("expected target to be allowed: %v", err)
	}
	if err := policy.Check(protocol.Target{Host: "other.example.com", Port: 443}); err == nil {
		t.Fatal("expected host to be rejected")
	}
	if err := policy.Check(protocol.Target{Host: "api.example.com", Port: 80}); err == nil {
		t.Fatal("expected port to be rejected")
	}
}
