package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
)

var ErrInvalidAPIKeys = errors.New("invalid Consumer API key configuration")

type keyEntry struct {
	digest     [sha256.Size]byte
	consumerID string
}

// APIKeys stores only SHA-256 digests after construction. Consumer keys are
// independent TokenHive credentials and are never forwarded upstream.
type APIKeys struct {
	entries []keyEntry
}

// NewAPIKeys accepts token -> Consumer ID entries from a deployment secret
// source. Tokens must carry at least 128 bits of printable entropy.
func NewAPIKeys(keys map[string]string) (*APIKeys, error) {
	if len(keys) == 0 {
		return nil, ErrInvalidAPIKeys
	}
	store := &APIKeys{entries: make([]keyEntry, 0, len(keys))}
	for token, consumerID := range keys {
		if !validToken(token) || !validID(consumerID) {
			return nil, ErrInvalidAPIKeys
		}
		store.entries = append(store.entries, keyEntry{digest: sha256.Sum256([]byte(token)), consumerID: consumerID})
	}
	return store, nil
}

func (a *APIKeys) Authenticate(header string) (string, bool) {
	if a == nil || !strings.HasPrefix(header, "Bearer ") || strings.Count(header, " ") != 1 {
		return "", false
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if !validToken(token) {
		return "", false
	}
	digest := sha256.Sum256([]byte(token))
	match := -1
	for index := range a.entries {
		if subtle.ConstantTimeCompare(digest[:], a.entries[index].digest[:]) == 1 {
			match = index
		}
	}
	if match < 0 {
		return "", false
	}
	return a.entries[match].consumerID, true
}

func validToken(token string) bool {
	if len(token) < 32 || len(token) > 256 {
		return false
	}
	for _, character := range []byte(token) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}
