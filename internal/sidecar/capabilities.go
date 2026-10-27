package sidecar

import (
	"errors"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

const (
	ProtocolVersion = 1
	TLS12           = "1.2"
	TLS13           = "1.3"

	RoleHub      = "hub"
	RoleProvider = "provider"

	ModeTLS12SelectiveMPC         = "tls12-selective-mpc"
	ModeTLS13SelectiveMPC         = "tls13-selective-mpc"
	FeatureTLS13KeyUpdate         = "tls13-keyupdate"
	FeatureAuthenticatedMPCOutput = "authenticated-mpc-output"
	FeatureTLS13KeyedHMACState    = "tls13-keyed-hmac-state"

	FeatureServerKeyRelease         = "server-key-release"
	FeatureSelectiveRequest         = "selective-request-encryption"
	FeaturePublicRequestBody        = "public-request-body-keystream"
	FeatureBidirectionalAttachments = "bidirectional-attachments"
	FeatureAuthenticatedResponse    = "authenticated-response-channel"
	FeatureProviderDeliveryACK      = "provider-delivery-ack"
	FeaturePrecomputedClientAES     = "precomputed-client-aes"

	BaselineMaxRequestBytes          = protocol.BaselineMaxRequestBytes
	BaselineMaxRequestRecords        = protocol.BaselineMaxRequestRecords
	LargeMaxRequestBytes             = protocol.LargeMaxRequestBytes
	LargeMaxRequestRecords           = protocol.LargeMaxRequestRecords
	BaselineMaxResponseBytes         = protocol.BaselineMaxResponseBytes
	BaselineMaxResponseRecordsOnline = protocol.BaselineMaxResponseRecordsOnline
)

var SupportedCipherSuites = []string{
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
}

type Capabilities struct {
	ProtocolVersion uint16      `json:"protocol_version"`
	Role            string      `json:"role"`
	EngineMode      string      `json:"engine_mode"`
	TLSVersions     []string    `json:"tls_versions"`
	CipherSuites    []string    `json:"cipher_suites"`
	Features        []string    `json:"features"`
	MPCCapacity     MPCCapacity `json:"mpc_capacity"`
}

// MPCCapacity contains the exact preprocessing and response resource bounds
// committed by both MPC parties.
type MPCCapacity struct {
	MaxRequestBytes          uint32 `json:"max_request_bytes"`
	MaxRequestRecords        uint16 `json:"max_request_records"`
	MaxResponseBytes         uint32 `json:"max_response_bytes"`
	MaxResponseRecordsOnline uint16 `json:"max_response_records_online"`
}

func BaselineMPCCapacity() MPCCapacity {
	return MPCCapacity{
		MaxRequestBytes:          BaselineMaxRequestBytes,
		MaxRequestRecords:        BaselineMaxRequestRecords,
		MaxResponseBytes:         BaselineMaxResponseBytes,
		MaxResponseRecordsOnline: BaselineMaxResponseRecordsOnline,
	}
}

func LargeMPCCapacity() MPCCapacity {
	return MPCCapacity{
		MaxRequestBytes:          LargeMaxRequestBytes,
		MaxRequestRecords:        LargeMaxRequestRecords,
		MaxResponseBytes:         BaselineMaxResponseBytes,
		MaxResponseRecordsOnline: BaselineMaxResponseRecordsOnline,
	}
}

func IsSupportedMPCCapacity(capacity MPCCapacity) bool {
	for _, name := range CapacityProfiles() {
		profile, _ := CapacityProfile(name)
		if capacity == profile {
			return true
		}
	}
	return false
}

// CapacityProfiles lists exact profiles, ordered by request budget.
func CapacityProfiles() []string { return []string{"baseline", "16k", "64k", "256k", "1m", "5m"} }

func CapacityProfile(name string) (MPCCapacity, error) {
	var size uint32
	switch name {
	case "baseline":
		size = 4 << 10
	case "16k":
		size = 16 << 10
	case "64k":
		size = 64 << 10
	case "256k":
		size = 256 << 10
	case "1m":
		size = 1 << 20
	case "5m":
		size = 5 << 20
	default:
		return MPCCapacity{}, errors.New("unsupported MPC capacity profile")
	}
	return MPCCapacity{MaxRequestBytes: size, MaxRequestRecords: uint16((size+16383)/16384 + 3),
		MaxResponseBytes: BaselineMaxResponseBytes, MaxResponseRecordsOnline: BaselineMaxResponseRecordsOnline}, nil
}

func CapacityName(capacity MPCCapacity) (string, error) {
	for _, name := range CapacityProfiles() {
		profile, _ := CapacityProfile(name)
		if capacity == profile {
			return name, nil
		}
	}
	return "", errors.New("unsupported MPC capacity profile")
}

type NegotiatedCapabilities struct {
	ProtocolVersion uint16
	TLSVersion      string
	CipherSuites    []string
	MPCCapacity     MPCCapacity
}

func SelectiveMPCCapabilities(role string) Capabilities {
	return SelectiveMPCCapabilitiesWithCapacity(role, BaselineMPCCapacity())
}

func SelectiveMPCCapabilitiesWithCapacity(role string, capacity MPCCapacity) Capabilities {
	return Capabilities{
		ProtocolVersion: ProtocolVersion,
		Role:            role,
		EngineMode:      ModeTLS12SelectiveMPC,
		TLSVersions:     []string{TLS12},
		CipherSuites:    append([]string(nil), SupportedCipherSuites...),
		Features: []string{
			FeatureServerKeyRelease,
			FeatureSelectiveRequest,
			FeaturePublicRequestBody,
			FeatureBidirectionalAttachments,
			FeatureAuthenticatedResponse,
			FeatureProviderDeliveryACK,
			FeaturePrecomputedClientAES,
		},
		MPCCapacity: capacity,
	}
}

func TLS13CapabilitiesWithCapacity(role string, capacity MPCCapacity) Capabilities {
	version, suites, features, _ := engineRequirements(ModeTLS13SelectiveMPC)
	return Capabilities{ProtocolVersion: ProtocolVersion, Role: role, EngineMode: ModeTLS13SelectiveMPC, TLSVersions: []string{version}, CipherSuites: suites, Features: features, MPCCapacity: capacity}
}

func engineRequirements(mode string) (string, []string, []string, error) {
	features := []string{FeatureServerKeyRelease, FeatureSelectiveRequest, FeatureBidirectionalAttachments, FeatureAuthenticatedResponse, FeatureProviderDeliveryACK}
	switch mode {
	case ModeTLS12SelectiveMPC:
		return TLS12, SupportedCipherSuites, append(features, FeaturePublicRequestBody, FeaturePrecomputedClientAES), nil
	case ModeTLS13SelectiveMPC:
		return TLS13, []string{"TLS_AES_128_GCM_SHA256"}, append(features, FeatureTLS13KeyUpdate, FeatureAuthenticatedMPCOutput, FeatureTLS13KeyedHMACState), nil
	default:
		return "", nil, nil, errors.New("unsupported sidecar engine mode")
	}
}

func Negotiate(hub, provider Capabilities) (NegotiatedCapabilities, error) {
	if err := ValidateCapabilities(hub, RoleHub); err != nil {
		return NegotiatedCapabilities{}, err
	}
	if err := ValidateCapabilities(provider, RoleProvider); err != nil {
		return NegotiatedCapabilities{}, err
	}
	if hub.EngineMode != provider.EngineMode {
		return NegotiatedCapabilities{}, errors.New("Hub and Provider TLS engine modes do not match")
	}
	if hub.MPCCapacity != provider.MPCCapacity {
		return NegotiatedCapabilities{}, errors.New("Hub and Provider MPC capacity profiles do not match")
	}
	version, supported, _, _ := engineRequirements(hub.EngineMode)
	var suites []string
	for _, suite := range hub.CipherSuites {
		if contains(supported, suite) && contains(provider.CipherSuites, suite) {
			suites = append(suites, suite)
		}
	}
	if len(suites) == 0 {
		return NegotiatedCapabilities{}, errors.New("no mutually supported cipher suite")
	}
	return NegotiatedCapabilities{ProtocolVersion: ProtocolVersion, TLSVersion: version, CipherSuites: suites, MPCCapacity: hub.MPCCapacity}, nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
