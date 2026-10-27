package providerhealth

import (
	"path/filepath"
	"testing"
)

func TestDurableTrackerRetainsQuarantineAndLocksWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "provider-health.json")
	tracker, err := Open(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	tracker.Failure("provider-1", FailureAuthentication)
	if tracker.Allow("provider-1") {
		t.Fatal("Provider was not quarantined")
	}
	if _, err := Open(path, DefaultConfig()); err == nil {
		t.Fatal("second writer unexpectedly acquired state")
	}
	if err := tracker.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path, DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if recovered.Allow("provider-1") {
		t.Fatal("quarantine did not survive restart")
	}
	if snapshot := recovered.Snapshot("provider-1"); snapshot.Failures != 1 || snapshot.Score != 10 {
		t.Fatalf("unexpected recovered snapshot: %+v", snapshot)
	}
}
