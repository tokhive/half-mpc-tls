package protocol

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Target struct {
	Host string `json:"host"`
	Port uint16 `json:"port"`
	SNI  string `json:"sni,omitempty"`
}

func (t Target) Validate() error {
	if strings.TrimSpace(t.Host) == "" {
		return fmt.Errorf("target host is required")
	}
	if t.Port == 0 {
		return fmt.Errorf("target port is required")
	}
	if strings.ContainsAny(t.Host, "\x00\r\n") || strings.ContainsAny(t.SNI, "\x00\r\n") {
		return fmt.Errorf("target contains control characters")
	}
	return nil
}

func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

func EncodeTarget(target Target) ([]byte, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(target)
}

func DecodeTarget(payload []byte) (Target, error) {
	var target Target
	if err := json.Unmarshal(payload, &target); err != nil {
		return Target{}, fmt.Errorf("decode target: %w", err)
	}
	if err := target.Validate(); err != nil {
		return Target{}, err
	}
	return target, nil
}
