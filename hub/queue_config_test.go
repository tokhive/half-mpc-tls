package hub

import (
	"testing"
)

func TestQueueConfigValidation(t *testing.T) {
	base := Config{APIAddress: "a", ControlAddress: "c", DataAddress: "d", StateDirectory: "s", TrustDomain: "t", HubSidecarSocket: "socket", Routes: []Route{{}}}
	for _, tc := range []struct {
		name             string
		waiters, timeout int
		valid            bool
	}{
		{"defaults", 0, 0, true}, {"explicit", 4, 1500, true}, {"negative queue", -1, 0, false}, {"negative timeout", 0, -1, false}, {"duration overflow", 1, int(^uint(0) >> 1), uint64(^uint(0)>>1) <= uint64((1<<63-1)/1000000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.MaxWaiters = tc.waiters
			cfg.QueueWaitTimeoutMS = tc.timeout
			err := validateConfig(cfg)
			if (err == nil) != tc.valid {
				t.Fatalf("validation: %v", err)
			}
		})
	}
}
