package providerhealth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const stateFileMode = 0o600

type stateDocument struct {
	Version uint16                    `json:"version"`
	States  map[string]persistedState `json:"states"`
	Hash    string                    `json:"hash"`
}

type persistedState struct {
	Score                 uint32 `json:"score"`
	Failures              uint64 `json:"failures"`
	Successes             uint64 `json:"successes"`
	QuarantinedUntilMilli int64  `json:"quarantined_until_unix_milli,omitempty"`
}

type statePayload struct {
	Version uint16                    `json:"version"`
	States  map[string]persistedState `json:"states"`
}

// Open creates a fail-closed Tracker whose penalties survive Hub restarts.
// The state file is atomically replaced and its separate lock prevents two
// Hub processes from updating the same Provider scores.
func Open(path string, config Config) (*Tracker, error) {
	if path == "" || filepath.Clean(path) == "." {
		return nil, ErrInvalidConfig
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if err := validateExisting(path); err != nil {
		return nil, err
	}
	if err := validateExisting(path + ".lock"); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, stateFileMode)
	if err != nil {
		return nil, fmt.Errorf("open Provider health lock: %w", err)
	}
	if err := lockProviderHealthFile(lock); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("lock Provider health state: %w", err)
	}
	states, err := loadStates(path)
	if err != nil {
		_ = unlockProviderHealthFile(lock)
		_ = lock.Close()
		return nil, err
	}
	tracker, err := newTracker(config, time.Now)
	if err != nil {
		_ = unlockProviderHealthFile(lock)
		_ = lock.Close()
		return nil, err
	}
	tracker.states = states
	tracker.persist = func(states map[string]*state) error { return persistStates(path, states) }
	tracker.close = func() error { return errors.Join(unlockProviderHealthFile(lock), lock.Close()) }
	return tracker, nil
}

func validateExisting(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("unsafe Provider health state file")
	}
	return nil
}

func loadStates(path string) (map[string]*state, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]*state), nil
	}
	if err != nil {
		return nil, err
	}
	var document stateDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&document) != nil {
		return nil, errors.New("Provider health state is corrupt")
	}
	if _, err := decoder.Token(); err != io.EOF || document.Version != 1 || document.States == nil {
		return nil, errors.New("Provider health state is corrupt")
	}
	payload := statePayload{Version: document.Version, States: document.States}
	expected, err := hashState(payload)
	if err != nil || expected != document.Hash {
		return nil, errors.New("Provider health state is corrupt")
	}
	states := make(map[string]*state, len(document.States))
	for providerID, persisted := range document.States {
		if providerID == "" || persisted.QuarantinedUntilMilli < 0 {
			return nil, errors.New("Provider health state is corrupt")
		}
		states[providerID] = &state{
			score: persisted.Score, failures: persisted.Failures, successes: persisted.Successes,
			quarantine: time.UnixMilli(persisted.QuarantinedUntilMilli),
		}
		if persisted.QuarantinedUntilMilli == 0 {
			states[providerID].quarantine = time.Time{}
		}
	}
	return states, nil
}

func persistStates(path string, states map[string]*state) error {
	persisted := make(map[string]persistedState, len(states))
	for providerID, value := range states {
		persisted[providerID] = persistedState{
			Score: value.score, Failures: value.failures, Successes: value.successes,
			QuarantinedUntilMilli: value.quarantine.UnixMilli(),
		}
		if value.quarantine.IsZero() {
			entry := persisted[providerID]
			entry.QuarantinedUntilMilli = 0
			persisted[providerID] = entry
		}
	}
	payload := statePayload{Version: 1, States: persisted}
	hash, err := hashState(payload)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(stateDocument{Version: 1, States: persisted, Hash: hash})
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".provider-health-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(stateFileMode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func hashState(payload statePayload) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
