package settlement

import (
	"errors"
	"fmt"
	"sync"

	"tokenhive.local/half-mpc-tls/internal/gateway"
)

var ErrInvalidProcessor = errors.New("invalid settlement processor")

// ReceiptLedger is implemented by the reference Ledger and by a production
// transactional database adapter.
type ReceiptLedger interface {
	Settle(gateway.Receipt) (Settlement, bool, error)
	HoldForReview(gateway.Receipt) (bool, error)
}

// Processor is the production ReceiptSink ordering boundary: evidence reaches
// the durable outbox before the account ledger is asked to settle it.
type Processor struct {
	mu      sync.Mutex
	journal *Journal
	ledger  ReceiptLedger
}

func NewProcessor(journal *Journal, ledger ReceiptLedger) (*Processor, error) {
	if journal == nil || ledger == nil {
		return nil, ErrInvalidProcessor
	}
	return &Processor{journal: journal, ledger: ledger}, nil
}

// RecordReceipt implements gateway.ReceiptSink. If ledger application fails,
// the durable journal still retains the receipt for ReplayPending.
func (p *Processor) RecordReceipt(receipt gateway.Receipt) error {
	if p == nil || p.journal == nil || p.ledger == nil {
		return ErrInvalidProcessor
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, _, err := p.journal.Append(receipt); err != nil {
		return fmt.Errorf("persist receipt: %w", err)
	}
	review, err := p.applyReceipt(receipt)
	if err != nil {
		return err
	}
	if review {
		// The evidence is safe, but callers must not expose successful completion.
		return ErrUsageExceedsReservation
	}
	return nil
}

// ReplayPending reapplies every durable receipt. Ledger task idempotency makes
// this safe after a crash at any point between journal fsync and ledger commit.
func (p *Processor) ReplayPending() error {
	if p == nil || p.journal == nil || p.ledger == nil {
		return ErrInvalidProcessor
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, record := range p.journal.Records() {
		if _, err := p.applyReceipt(record.Receipt); err != nil {
			return fmt.Errorf("replay settlement task %s: %w", record.Receipt.TaskID, err)
		}
	}
	return nil
}

// Only a durably held over-budget task is recoverable independently of other
// tasks. Storage failures, missing reservations and binding conflicts still stop
// recovery; they must never be mistaken for a successfully isolated receipt.
func (p *Processor) applyReceipt(receipt gateway.Receipt) (bool, error) {
	if _, _, err := p.ledger.Settle(receipt); err != nil {
		if !errors.Is(err, ErrUsageExceedsReservation) {
			return false, fmt.Errorf("apply receipt to ledger: %w", err)
		}
		if _, err := p.ledger.HoldForReview(receipt); err != nil {
			return false, fmt.Errorf("hold receipt for review: %w", err)
		}
		return true, nil
	}
	return false, nil
}
