// Package settlement persists authenticated response receipts as an
// idempotent outbox for the account ledger.
package settlement

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tokenhive.local/half-mpc-tls/internal/gateway"
)

const (
	journalVersion   = 1
	maxRecordBytes   = 1 << 20
	genesisHash      = "0000000000000000000000000000000000000000000000000000000000000000"
	journalFileMode  = 0o600
	unsafePermission = 0o077
)

var (
	ErrInvalidReceipt = errors.New("invalid settlement receipt")
	ErrTaskConflict   = errors.New("settlement task already has different evidence")
	ErrJournalCorrupt = errors.New("settlement journal is corrupt")
	ErrJournalClosed  = errors.New("settlement journal is closed")
	ErrJournalLocked  = errors.New("settlement journal is locked by another process")
)

type Record struct {
	Version             uint16          `json:"version"`
	Sequence            uint64          `json:"sequence"`
	PreviousHash        string          `json:"previous_hash"`
	RecordedAtUnixMilli int64           `json:"recorded_at_unix_milli"`
	Receipt             gateway.Receipt `json:"receipt"`
	Hash                string          `json:"hash"`
}

type recordPayload struct {
	Version             uint16          `json:"version"`
	Sequence            uint64          `json:"sequence"`
	PreviousHash        string          `json:"previous_hash"`
	RecordedAtUnixMilli int64           `json:"recorded_at_unix_milli"`
	Receipt             gateway.Receipt `json:"receipt"`
}

type Journal struct {
	mu       sync.Mutex
	file     *os.File
	byTask   map[string]Record
	records  []Record
	lastHash string
	now      func() time.Time
	failed   error
}

func OpenJournal(path string) (*Journal, error) {
	return openJournal(path, time.Now)
}

func openJournal(path string, now func() time.Time) (*Journal, error) {
	if path == "" || filepath.Clean(path) == "." || now == nil {
		return nil, fmt.Errorf("open settlement journal: invalid path")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&unsafePermission != 0 {
			return nil, fmt.Errorf("open settlement journal: unsafe existing file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("open settlement journal: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, journalFileMode)
	if err != nil {
		return nil, fmt.Errorf("open settlement journal: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&unsafePermission != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("open settlement journal: unsafe file")
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrJournalLocked, err)
	}
	journal := &Journal{
		file:     file,
		byTask:   make(map[string]Record),
		lastHash: genesisHash,
		now:      now,
	}
	if err := journal.recover(); err != nil {
		_ = unlockFile(file)
		_ = file.Close()
		return nil, err
	}
	return journal, nil
}

// Append stores one receipt durably. Repeating the exact same task and receipt
// is idempotent; reusing a task ID with different evidence fails closed.
func (j *Journal) Append(receipt gateway.Receipt) (Record, bool, error) {
	if j == nil || !validReceipt(receipt) {
		return Record{}, false, ErrInvalidReceipt
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return Record{}, false, ErrJournalClosed
	}
	if j.failed != nil {
		return Record{}, false, j.failed
	}
	if existing, exists := j.byTask[receipt.TaskID]; exists {
		if existing.Receipt == receipt {
			return existing, false, nil
		}
		return Record{}, false, ErrTaskConflict
	}

	payload := recordPayload{
		Version:             journalVersion,
		Sequence:            uint64(len(j.records) + 1),
		PreviousHash:        j.lastHash,
		RecordedAtUnixMilli: j.now().UnixMilli(),
		Receipt:             receipt,
	}
	if payload.RecordedAtUnixMilli <= 0 {
		return Record{}, false, ErrInvalidReceipt
	}
	hash, err := hashPayload(payload)
	if err != nil {
		return Record{}, false, err
	}
	record := Record{
		Version:             payload.Version,
		Sequence:            payload.Sequence,
		PreviousHash:        payload.PreviousHash,
		RecordedAtUnixMilli: payload.RecordedAtUnixMilli,
		Receipt:             payload.Receipt,
		Hash:                hash,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return Record{}, false, fmt.Errorf("encode settlement record: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxRecordBytes {
		return Record{}, false, ErrInvalidReceipt
	}
	if written, err := j.file.Write(encoded); err != nil || written != len(encoded) {
		if err == nil {
			err = io.ErrShortWrite
		}
		j.failed = fmt.Errorf("append settlement journal: %w", err)
		return Record{}, false, j.failed
	}
	if err := j.file.Sync(); err != nil {
		j.failed = fmt.Errorf("sync settlement journal: %w", err)
		return Record{}, false, j.failed
	}
	j.records = append(j.records, record)
	j.byTask[receipt.TaskID] = record
	j.lastHash = record.Hash
	return record, true, nil
}

// RecordReceipt implements gateway.ReceiptSink.
func (j *Journal) RecordReceipt(receipt gateway.Receipt) error {
	_, _, err := j.Append(receipt)
	return err
}

func (j *Journal) Records() []Record {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]Record(nil), j.records...)
}

func (j *Journal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file == nil {
		return nil
	}
	unlockErr := unlockFile(j.file)
	err := j.file.Close()
	j.file = nil
	if unlockErr != nil {
		return unlockErr
	}
	return err
}

func (j *Journal) recover() error {
	if _, err := j.file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("read settlement journal: %w", err)
	}
	reader := bufio.NewReaderSize(j.file, 64<<10)
	var validBytes int64
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > maxRecordBytes {
			return ErrJournalCorrupt
		}
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				if truncateErr := j.file.Truncate(validBytes); truncateErr != nil {
					return fmt.Errorf("recover torn settlement record: %w", truncateErr)
				}
				if syncErr := j.file.Sync(); syncErr != nil {
					return fmt.Errorf("sync recovered settlement journal: %w", syncErr)
				}
			}
			break
		}
		if err != nil || len(line) == 0 {
			return ErrJournalCorrupt
		}
		validBytes += int64(len(line))
		var record Record
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decodeErr := decoder.Decode(&record); decodeErr != nil {
			return ErrJournalCorrupt
		}
		if token, decodeErr := decoder.Token(); decodeErr != io.EOF {
			_ = token
			return ErrJournalCorrupt
		}
		if err := j.validateRecovered(record); err != nil {
			return err
		}
		j.records = append(j.records, record)
		j.byTask[record.Receipt.TaskID] = record
		j.lastHash = record.Hash
	}
	_, err := j.file.Seek(0, io.SeekEnd)
	return err
}

func (j *Journal) validateRecovered(record Record) error {
	if record.Version != journalVersion || record.Sequence != uint64(len(j.records)+1) ||
		record.PreviousHash != j.lastHash || record.RecordedAtUnixMilli <= 0 ||
		!validReceipt(record.Receipt) || !validHash(record.Hash) {
		return ErrJournalCorrupt
	}
	if _, exists := j.byTask[record.Receipt.TaskID]; exists {
		return ErrJournalCorrupt
	}
	expected, err := hashPayload(recordPayload{
		Version:             record.Version,
		Sequence:            record.Sequence,
		PreviousHash:        record.PreviousHash,
		RecordedAtUnixMilli: record.RecordedAtUnixMilli,
		Receipt:             record.Receipt,
	})
	if err != nil || expected != record.Hash {
		return ErrJournalCorrupt
	}
	return nil
}

func hashPayload(payload recordPayload) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func validReceipt(receipt gateway.Receipt) bool {
	if !validIdentifier(receipt.TaskID, 128) || !validIdentifier(receipt.ProviderID, 128) ||
		!validHash(receipt.RequestHash) || !validHash(receipt.ResponseHash) ||
		!validModel(receipt.RequestedModel) || !boundedASCII(receipt.UpstreamRequestID, 256, true) ||
		receipt.StatusCode < 200 || receipt.StatusCode > 599 ||
		receipt.BodyBytes < 0 || receipt.BodyBytes > 16<<20 {
		return false
	}
	usage := receipt.Usage
	if usage.InputTokens < 0 || usage.OutputTokens < 0 || usage.TotalTokens < 0 ||
		usage.InputTokens > math.MaxInt64-usage.OutputTokens ||
		usage.InputTokens+usage.OutputTokens != usage.TotalTokens {
		return false
	}
	if receipt.Billable {
		return receipt.StatusCode < 300 && validModel(receipt.ResponseModel) &&
			boundedASCII(receipt.UpstreamResponseID, 256, false) && usage.TotalTokens <= 1_000_000_000
	}
	return receipt.StatusCode >= 300 && receipt.ResponseModel == "" &&
		receipt.UpstreamResponseID == "" && usage.TotalTokens == 0
}

func validIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func validModel(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._:/", rune(character))) {
			return false
		}
	}
	return true
}

func boundedASCII(value string, maximum int, optional bool) bool {
	if value == "" {
		return optional
	}
	if len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func validHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
