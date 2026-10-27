package providerhealth

import (
	"testing"
	"time"
)

func TestTrackerQuarantinesAndAutomaticallyRecovers(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	config := DefaultConfig()
	config.Threshold = 5
	config.Quarantine = time.Minute
	tracker, err := newTracker(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tracker.Failure("provider-1", FailureProtocol)
	if tracker.Allow("provider-1") {
		t.Fatal("protocol failure should quarantine Provider")
	}
	if snapshot := tracker.Snapshot("provider-1"); snapshot.Score != 5 || snapshot.Failures != 1 {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	now = now.Add(time.Minute)
	if !tracker.Allow("provider-1") {
		t.Fatal("Provider did not recover after quarantine")
	}
	tracker.Success("provider-1")
	if snapshot := tracker.Snapshot("provider-1"); snapshot.Score != 0 || snapshot.Successes != 1 {
		t.Fatalf("unexpected recovery snapshot: %+v", snapshot)
	}
}

func TestTrackerWeightsAuthenticationFailures(t *testing.T) {
	tracker, err := New(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	tracker.Failure("provider-1", FailureAuthentication)
	if tracker.Allow("provider-1") {
		t.Fatal("authentication failure should immediately quarantine Provider")
	}
}
