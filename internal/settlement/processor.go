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
	if _, _, err := p.ledger.Settle(receipt); err != nil {
		return fmt.Errorf("apply receipt to ledger: %w", err)
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
		if _, _, err := p.ledger.Settle(record.Receipt); err != nil {
			return fmt.Errorf("replay settlement task %s: %w", record.Receipt.TaskID, err)
		}
	}
	return nil
}
