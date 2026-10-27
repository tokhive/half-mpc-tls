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
	"os"
	"path/filepath"
	"sort"
	"sync"

	"tokenhive.local/half-mpc-tls/internal/gateway"
)

const (
	ledgerLogVersion = 1
	maxLedgerEvent   = 1 << 20
)

var (
	ErrDurableLedgerCorrupt = errors.New("durable account ledger is corrupt")
	ErrDurableLedgerClosed  = errors.New("durable account ledger is closed")
	ErrDurableLedgerLocked  = errors.New("durable account ledger is locked by another process")
)

type ledgerEvent struct {
	Version           uint16          `json:"version"`
	Sequence          uint64          `json:"sequence"`
	PreviousHash      string          `json:"previous_hash"`
	PlatformAccountID string          `json:"platform_account_id"`
	Kind              string          `json:"kind"`
	Payload           json.RawMessage `json:"payload"`
	Hash              string          `json:"hash"`
}

type ledgerEventPayload struct {
	Version           uint16          `json:"version"`
	Sequence          uint64          `json:"sequence"`
	PreviousHash      string          `json:"previous_hash"`
	PlatformAccountID string          `json:"platform_account_id"`
	Kind              string          `json:"kind"`
	Payload           json.RawMessage `json:"payload"`
}

type fundEvent struct {
	TransactionID string `json:"transaction_id"`
	ConsumerID    string `json:"consumer_id"`
	Currency      string `json:"currency"`
	AmountMicros  int64  `json:"amount_micros"`
}

type cancelEvent struct {
	TaskID     string `json:"task_id"`
	ReasonCode string `json:"reason_code"`
}

// DurableLedger is the deployed account-ledger adapter. Every accepted state
// transition is appended to a hash-chained, mode-0600, single-writer log and
// synced before success is returned.
type DurableLedger struct {
	mu                sync.Mutex
	file              *os.File
	ledger            *Ledger
	platformAccountID string
	sequence          uint64
	lastHash          string
	failed            error
}

func OpenDurableLedger(path, platformAccountID string) (*DurableLedger, error) {
	if path == "" || filepath.Clean(path) == "." || !validIdentifier(platformAccountID, 128) {
		return nil, ErrInvalidLedgerInput
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&unsafePermission != 0 {
			return nil, fmt.Errorf("open durable ledger: unsafe existing file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("open durable ledger: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, journalFileMode)
	if err != nil {
		return nil, fmt.Errorf("open durable ledger: %w", err)
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&unsafePermission != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("open durable ledger: unsafe file")
	}
	if err := lockFile(file); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrDurableLedgerLocked, err)
	}
	inner, err := NewLedger(platformAccountID)
	if err != nil {
		_ = unlockFile(file)
		_ = file.Close()
		return nil, err
	}
	durable := &DurableLedger{file: file, ledger: inner, platformAccountID: platformAccountID, lastHash: genesisHash}
	if err := durable.recover(); err != nil {
		_ = unlockFile(file)
		_ = file.Close()
		return nil, err
	}
	return durable, nil
}

func (d *DurableLedger) FundConsumer(transactionID, consumerID, currency string, amountMicros int64) (bool, error) {
	if d == nil {
		return false, ErrDurableLedgerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.available(); err != nil {
		return false, err
	}
	created, err := d.ledger.FundConsumer(transactionID, consumerID, currency, amountMicros)
	if err != nil || !created {
		return created, err
	}
	if err := d.append("fund", fundEvent{transactionID, consumerID, currency, amountMicros}); err != nil {
		return false, err
	}
	return true, nil
}

func (d *DurableLedger) Reserve(request ReserveRequest) (Reservation, bool, error) {
	if d == nil {
		return Reservation{}, false, ErrDurableLedgerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.available(); err != nil {
		return Reservation{}, false, err
	}
	result, created, err := d.ledger.Reserve(request)
	if err != nil || !created {
		return result, created, err
	}
	if err := d.append("reserve", request); err != nil {
		return Reservation{}, false, err
	}
	return result, true, nil
}

func (d *DurableLedger) Settle(receipt gateway.Receipt) (Settlement, bool, error) {
	if d == nil {
		return Settlement{}, false, ErrDurableLedgerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.available(); err != nil {
		return Settlement{}, false, err
	}
	result, applied, err := d.ledger.Settle(receipt)
	if err != nil || !applied {
		return result, applied, err
	}
	if err := d.append("settle", receipt); err != nil {
		return Settlement{}, false, err
	}
	return result, true, nil
}

func (d *DurableLedger) Cancel(taskID, reasonCode string) (Cancellation, bool, error) {
	if d == nil {
		return Cancellation{}, false, ErrDurableLedgerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.available(); err != nil {
		return Cancellation{}, false, err
	}
	result, applied, err := d.ledger.Cancel(taskID, reasonCode)
	if err != nil || !applied {
		return result, applied, err
	}
	if err := d.append("cancel", cancelEvent{TaskID: taskID, ReasonCode: reasonCode}); err != nil {
		return Cancellation{}, false, err
	}
	return result, true, nil
}

// CancelPending refunds reservations left by an interrupted Hub. Call only at
// startup, after replaying every durable receipt and before admitting requests.
// The exclusive ledger file lock excludes a still-running previous Hub. Missing
// evidence cannot be billed; cancelled task IDs remain bound and cannot replay.
func (d *DurableLedger) CancelPending(reasonCode string) (int, error) {
	if d == nil {
		return 0, ErrDurableLedgerClosed
	}
	if !validIdentifier(reasonCode, 64) {
		return 0, ErrInvalidLedgerInput
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.available(); err != nil {
		return 0, err
	}
	d.ledger.mu.Lock()
	var tasks []string
	for id, entry := range d.ledger.tasks {
		if entry.reservation.State == ReservationPending {
			tasks = append(tasks, id)
		}
	}
	d.ledger.mu.Unlock()
	sort.Strings(tasks)
	completed := 0
	for _, id := range tasks {
		if _, _, err := d.ledger.Cancel(id, reasonCode); err != nil {
			return completed, err
		}
		if err := d.append("cancel", cancelEvent{TaskID: id, ReasonCode: reasonCode}); err != nil {
			return completed, err
		}
		completed++
	}
	return completed, nil
}

func (d *DurableLedger) Balance(role AccountRole, accountID, currency string) (int64, error) {
	if d == nil {
		return 0, ErrDurableLedgerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.available(); err != nil {
		return 0, err
	}
	return d.ledger.Balance(role, accountID, currency)
}

func (d *DurableLedger) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.file == nil {
		return nil
	}
	unlockErr := unlockFile(d.file)
	closeErr := d.file.Close()
	d.file = nil
	return errors.Join(unlockErr, closeErr)
}

func (d *DurableLedger) available() error {
	if d.file == nil {
		return ErrDurableLedgerClosed
	}
	return d.failed
}

func (d *DurableLedger) append(kind string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	eventPayload := ledgerEventPayload{
		Version: ledgerLogVersion, Sequence: d.sequence + 1, PreviousHash: d.lastHash,
		PlatformAccountID: d.platformAccountID, Kind: kind, Payload: payload,
	}
	hash, err := hashLedgerEvent(eventPayload)
	if err != nil {
		return err
	}
	event := ledgerEvent{
		Version: eventPayload.Version, Sequence: eventPayload.Sequence, PreviousHash: eventPayload.PreviousHash,
		PlatformAccountID: eventPayload.PlatformAccountID, Kind: eventPayload.Kind, Payload: eventPayload.Payload, Hash: hash,
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxLedgerEvent {
		return ErrInvalidLedgerInput
	}
	if written, writeErr := d.file.Write(encoded); writeErr != nil || written != len(encoded) {
		if writeErr == nil {
			writeErr = io.ErrShortWrite
		}
		d.failed = fmt.Errorf("append durable ledger: %w", writeErr)
		return d.failed
	}
	if err := d.file.Sync(); err != nil {
		d.failed = fmt.Errorf("sync durable ledger: %w", err)
		return d.failed
	}
	d.sequence = event.Sequence
	d.lastHash = event.Hash
	return nil
}

func (d *DurableLedger) recover() error {
	if _, err := d.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(d.file, 64<<10)
	var validBytes int64
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > maxLedgerEvent {
			return ErrDurableLedgerCorrupt
		}
		if errors.Is(err, io.EOF) {
			if len(line) > 0 {
				if err := d.file.Truncate(validBytes); err != nil {
					return fmt.Errorf("recover torn durable ledger event: %w", err)
				}
				if err := d.file.Sync(); err != nil {
					return err
				}
			}
			break
		}
		if err != nil || len(line) == 0 {
			return ErrDurableLedgerCorrupt
		}
		var event ledgerEvent
		if err := decodeStrict(line, &event); err != nil || d.validateEvent(event) != nil || d.replay(event) != nil {
			return ErrDurableLedgerCorrupt
		}
		d.sequence = event.Sequence
		d.lastHash = event.Hash
		validBytes += int64(len(line))
	}
	_, err := d.file.Seek(0, io.SeekEnd)
	return err
}

func (d *DurableLedger) validateEvent(event ledgerEvent) error {
	if event.Version != ledgerLogVersion || event.Sequence != d.sequence+1 || event.PreviousHash != d.lastHash ||
		event.PlatformAccountID != d.platformAccountID || !validHash(event.Hash) || len(event.Payload) == 0 {
		return ErrDurableLedgerCorrupt
	}
	expected, err := hashLedgerEvent(ledgerEventPayload{
		Version: event.Version, Sequence: event.Sequence, PreviousHash: event.PreviousHash,
		PlatformAccountID: event.PlatformAccountID, Kind: event.Kind, Payload: event.Payload,
	})
	if err != nil || expected != event.Hash {
		return ErrDurableLedgerCorrupt
	}
	return nil
}

func (d *DurableLedger) replay(event ledgerEvent) error {
	switch event.Kind {
	case "fund":
		var value fundEvent
		if err := decodeStrict(event.Payload, &value); err != nil {
			return err
		}
		created, err := d.ledger.FundConsumer(value.TransactionID, value.ConsumerID, value.Currency, value.AmountMicros)
		if err != nil || !created {
			return ErrDurableLedgerCorrupt
		}
	case "reserve":
		var value ReserveRequest
		if err := decodeStrict(event.Payload, &value); err != nil {
			return err
		}
		_, created, err := d.ledger.Reserve(value)
		if err != nil || !created {
			return ErrDurableLedgerCorrupt
		}
	case "settle":
		var value gateway.Receipt
		if err := decodeStrict(event.Payload, &value); err != nil {
			return err
		}
		_, applied, err := d.ledger.Settle(value)
		if err != nil || !applied {
			return ErrDurableLedgerCorrupt
		}
	case "cancel":
		var value cancelEvent
		if err := decodeStrict(event.Payload, &value); err != nil {
			return err
		}
		_, applied, err := d.ledger.Cancel(value.TaskID, value.ReasonCode)
		if err != nil || !applied {
			return ErrDurableLedgerCorrupt
		}
	default:
		return ErrDurableLedgerCorrupt
	}
	return nil
}

func hashLedgerEvent(payload ledgerEventPayload) (string, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrDurableLedgerCorrupt
	}
	return nil
}
