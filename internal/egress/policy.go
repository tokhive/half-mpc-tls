package egress

import (
	"fmt"
	"strings"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

type Policy struct {
	hosts map[string]struct{}
	ports map[uint16]struct{}
}

func NewPolicy(hosts []string, ports []uint16) (*Policy, error) {
	policy := &Policy{
		hosts: make(map[string]struct{}, len(hosts)),
		ports: make(map[uint16]struct{}, len(ports)),
	}
	for _, host := range hosts {
		host = normalizeHost(host)
		if host == "" {
			return nil, fmt.Errorf("empty host in egress policy")
		}
		policy.hosts[host] = struct{}{}
	}
	for _, port := range ports {
		if port == 0 {
			return nil, fmt.Errorf("zero port in egress policy")
		}
		policy.ports[port] = struct{}{}
	}
	if len(policy.hosts) == 0 || len(policy.ports) == 0 {
		return nil, fmt.Errorf("egress policy requires at least one host and port")
	}
	return policy, nil
}

func (p *Policy) Check(target protocol.Target) error {
	if err := target.Validate(); err != nil {
		return err
	}
	if _, ok := p.hosts[normalizeHost(target.Host)]; !ok {
		return fmt.Errorf("host %q is not in the egress allowlist", target.Host)
	}
	if _, ok := p.ports[target.Port]; !ok {
		return fmt.Errorf("port %d is not in the egress allowlist", target.Port)
	}
	return nil
}

func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}
