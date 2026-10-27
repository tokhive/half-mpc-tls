package settlement

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestStartupReplaysEvidenceBeforeRefundingInterruptedReservations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.jsonl")
	ledger, err := OpenDurableLedger(path, "tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ledger.FundConsumer("fund", "consumer-1", "USD", 2000)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"evidence", "interrupted"} {
		if _, _, err = ledger.Reserve(reserveRequest(id)); err != nil {
			t.Fatal(err)
		}
	}
	journal, err := OpenJournal(filepath.Join(dir, "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	if _, _, err = journal.Append(billableReceipt("evidence")); err != nil {
		t.Fatal(err)
	}
	// Crash boundary: receipt persisted, no corresponding account settlement.
	if err = ledger.Close(); err != nil {
		t.Fatal(err)
	}
	for restart := 0; restart < 2; restart++ {
		ledger, err = OpenDurableLedger(path, "tokenhive")
		if err != nil {
			t.Fatal(err)
		}
		processor, err := NewProcessor(journal, ledger)
		if err != nil {
			t.Fatal(err)
		}
		if err = processor.ReplayPending(); err != nil {
			t.Fatal(err)
		}
		n, err := ledger.CancelPending("hub_restarted")
		if err != nil {
			t.Fatal(err)
		}
		if n != 1-restart {
			t.Fatalf("restart %d cancelled %d tasks", restart, n)
		}
		for _, tc := range []struct {
			id             string
			state          ReservationState
			charge, refund int64
		}{
			{"evidence", ReservationSettled, 28, 472}, {"interrupted", ReservationCancelled, 0, 500},
		} {
			status, ok, err := ledger.Task("consumer-1", tc.id)
			if err != nil || !ok || status.State != tc.state || status.ChargeMicros != tc.charge || status.RefundMicros != tc.refund {
				t.Fatalf("task: %+v %v", status, err)
			}
			if _, created, err := ledger.Reserve(reserveRequest(tc.id)); err != nil || created {
				t.Fatalf("replayed task: %v %v", created, err)
			}
		}
		balance, err := ledger.Balance(AccountConsumer, "consumer-1", "USD")
		if err != nil || balance != 1972 {
			t.Fatalf("balance %d %v", balance, err)
		}
		if _, err = ledger.CancelPending(""); !errors.Is(err, ErrInvalidLedgerInput) {
			t.Fatalf("invalid reason: %v", err)
		}
		if err = ledger.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = ledger.CancelPending("hub_restarted"); !errors.Is(err, ErrDurableLedgerClosed) {
			t.Fatalf("closed ledger: %v", err)
		}
	}
}
