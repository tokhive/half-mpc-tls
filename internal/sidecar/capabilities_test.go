package sidecar

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestFixtureMatchesWireContract(t *testing.T) {
	data, err := os.ReadFile("../../testdata/sidecar-capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed Capabilities
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	expected := SelectiveMPCCapabilities(RoleHub)
	if !reflect.DeepEqual(parsed, expected) {
		t.Fatalf("fixture mismatch: got %+v, want %+v", parsed, expected)
	}
}

func TestNegotiate(t *testing.T) {
	hub := SelectiveMPCCapabilities(RoleHub)
	provider := SelectiveMPCCapabilities(RoleProvider)
	negotiated, err := Negotiate(hub, provider)
	if err != nil {
		t.Fatal(err)
	}
	if negotiated.TLSVersion != TLS12 || !reflect.DeepEqual(negotiated.CipherSuites, hub.CipherSuites) {
		t.Fatalf("unexpected negotiated capabilities: %+v", negotiated)
	}
}

func TestNegotiateLargePublicBodyCapacity(t *testing.T) {
	hub := SelectiveMPCCapabilitiesWithCapacity(RoleHub, LargeMPCCapacity())
	provider := SelectiveMPCCapabilitiesWithCapacity(RoleProvider, LargeMPCCapacity())
	negotiated, err := Negotiate(hub, provider)
	if err != nil {
		t.Fatal(err)
	}
	if negotiated.MPCCapacity != LargeMPCCapacity() || negotiated.MPCCapacity.MaxRequestBytes != 5<<20 {
		t.Fatalf("unexpected large capacity: %+v", negotiated.MPCCapacity)
	}
}

func TestNegotiateRejectsTLS13(t *testing.T) {
	hub := SelectiveMPCCapabilities(RoleHub)
	provider := SelectiveMPCCapabilities(RoleProvider)
	provider.TLSVersions = append(provider.TLSVersions, "1.3")
	if _, err := Negotiate(hub, provider); err == nil {
		t.Fatal("expected TLS 1.3 advertisement to be rejected")
	}
}

func TestNegotiateRejectsUnsupportedCapacity(t *testing.T) {
	hub := SelectiveMPCCapabilities(RoleHub)
	provider := SelectiveMPCCapabilities(RoleProvider)
	provider.MPCCapacity.MaxRequestBytes++
	if _, err := Negotiate(hub, provider); err == nil {
		t.Fatal("expected unsupported MPC capacity to be rejected")
	}
	if err := ValidateCapabilities(provider, RoleProvider); err == nil {
		t.Fatal("expected local capability validation to reject unsupported capacity")
	}
}

func TestCapacityProfilesMatchCrossLanguageFixture(t *testing.T) {
	data, err := os.ReadFile("../../testdata/mpc-capacities.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Name     string      `json:"name"`
		Capacity MPCCapacity `json:"capacity"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != len(CapacityProfiles()) {
		t.Fatal("profile count differs")
	}
	for _, fixture := range fixtures {
		profile, err := CapacityProfile(fixture.Name)
		if err != nil || profile != fixture.Capacity {
			t.Fatalf("profile %s differs: %+v", fixture.Name, profile)
		}
		hub := SelectiveMPCCapabilitiesWithCapacity(RoleHub, profile)
		provider := SelectiveMPCCapabilitiesWithCapacity(RoleProvider, profile)
		if _, err := Negotiate(hub, provider); err != nil {
			t.Fatal(err)
		}
		provider.MPCCapacity.MaxRequestRecords++
		if _, err := Negotiate(hub, provider); err == nil {
			t.Fatal("record budget mismatch accepted")
		}
	}
}

func TestNegotiateRejectsOnlineAESPeer(t *testing.T) {
	hub := SelectiveMPCCapabilities(RoleHub)
	provider := SelectiveMPCCapabilities(RoleProvider)
	provider.Features = provider.Features[:len(provider.Features)-1]
	if _, err := Negotiate(hub, provider); err == nil {
		t.Fatal("accepted incompatible MPC evaluation schedule")
	}
	if err := ValidateCapabilities(provider, RoleProvider); err == nil {
		t.Fatal("accepted peer without precomputed-client-aes")
	}
}

func TestTLS13FixtureAndNegotiation(t *testing.T) {
	data, err := os.ReadFile("../../testdata/sidecar-capabilities-tls13.json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed Capabilities
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	hub := TLS13CapabilitiesWithCapacity(RoleHub, BaselineMPCCapacity())
	if !reflect.DeepEqual(parsed, hub) {
		t.Fatalf("fixture mismatch: %+v", parsed)
	}
	for _, profile := range CapacityProfiles() {
		capacity, err := CapacityProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		hub := TLS13CapabilitiesWithCapacity(RoleHub, capacity)
		provider := TLS13CapabilitiesWithCapacity(RoleProvider, capacity)
		selected, err := Negotiate(hub, provider)
		if err != nil || selected.TLSVersion != TLS13 || selected.MPCCapacity != capacity {
			t.Fatalf("negotiation: %+v %v", selected, err)
		}
	}
}

func TestTLS13RejectsIncompatiblePeers(t *testing.T) {
	hub := TLS13CapabilitiesWithCapacity(RoleHub, BaselineMPCCapacity())
	for _, feature := range []string{FeatureTLS13KeyUpdate, FeatureAuthenticatedMPCOutput, FeatureTLS13KeyedHMACState, FeatureProviderDeliveryACK} {
		provider := TLS13CapabilitiesWithCapacity(RoleProvider, BaselineMPCCapacity())
		features := make([]string, 0)
		for _, f := range provider.Features {
			if f != feature {
				features = append(features, f)
			}
		}
		provider.Features = features
		if _, err := Negotiate(hub, provider); err == nil {
			t.Fatalf("accepted missing feature %s", feature)
		}
	}
	for _, mutate := range []func(*Capabilities){
		func(p *Capabilities) { *p = SelectiveMPCCapabilities(RoleProvider) },
		func(p *Capabilities) { p.TLSVersions = []string{TLS12, TLS13} },
		func(p *Capabilities) { p.CipherSuites = []string{"TLS_AES_256_GCM_SHA384"} },
		func(p *Capabilities) { p.MPCCapacity = LargeMPCCapacity() },
	} {
		provider := TLS13CapabilitiesWithCapacity(RoleProvider, BaselineMPCCapacity())
		mutate(&provider)
		if _, err := Negotiate(hub, provider); err == nil {
			t.Fatalf("accepted incompatible peer: %+v", provider)
		}
	}
}

func TestCompatibleV1ReleasesCanAdvertiseOptionalFeaturesIndependently(t *testing.T) {
	for _, tls13 := range []bool{false, true} {
		for _, upgradedRole := range []string{RoleHub, RoleProvider} {
			hub := SelectiveMPCCapabilities(RoleHub)
			provider := SelectiveMPCCapabilities(RoleProvider)
			if tls13 {
				hub = TLS13CapabilitiesWithCapacity(RoleHub, LargeMPCCapacity())
				provider = TLS13CapabilitiesWithCapacity(RoleProvider, LargeMPCCapacity())
			}
			if upgradedRole == RoleHub {
				hub.Features = append(hub.Features, "optional-warm-stage-metrics")
			} else {
				provider.Features = append(provider.Features, "optional-warm-stage-metrics")
			}
			if _, err := Negotiate(hub, provider); err != nil {
				t.Fatalf("compatible v1 mixed release tls13=%v upgraded=%s: %v", tls13, upgradedRole, err)
			}
			provider.ProtocolVersion++
			if _, err := Negotiate(hub, provider); err == nil {
				t.Fatal("accepted an unimplemented frame protocol merely because features overlap")
			}
		}
	}
}
