package settlement

import (
	"errors"
	"fmt"
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

func TestStartupIsolatesOverBudgetReceiptAndRetainsReserve(t *testing.T) {
	for _, applyBeforeRestart := range []bool{false, true} {
		t.Run(fmt.Sprintf("applied-before-restart=%t", applyBeforeRestart), func(t *testing.T) {
			dir := t.TempDir()
			ledgerPath, journalPath := filepath.Join(dir, "accounts.jsonl"), filepath.Join(dir, "receipts.jsonl")
			ledger, err := OpenDurableLedger(ledgerPath, "tokenhive")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ledger.Close() }()
			if _, err := ledger.FundConsumer("fund", "consumer-1", "USD", 2000); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"over-budget", "normal", "interrupted"} {
				if _, _, err := ledger.Reserve(reserveRequest(id)); err != nil {
					t.Fatal(err)
				}
			}
			journal, err := OpenJournal(journalPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = journal.Close() }()
			receipt := billableReceipt("over-budget")
			receipt.Usage.InputTokens = 101
			receipt.Usage.TotalTokens = receipt.Usage.InputTokens + receipt.Usage.OutputTokens
			if applyBeforeRestart {
				processor, err := NewProcessor(journal, ledger)
				if err != nil {
					t.Fatal(err)
				}
				if err := processor.RecordReceipt(receipt); !errors.Is(err, ErrUsageExceedsReservation) {
					t.Fatalf("over-budget request must not report successful settlement: %v", err)
				}
				status, _, _ := ledger.Task("consumer-1", receipt.TaskID)
				if status.State != "review_required" {
					t.Fatalf("over-budget task was not isolated: %+v", status)
				}
			} else if _, _, err := journal.Append(receipt); err != nil {
				t.Fatal(err)
			}
			// A later, valid receipt must still be replayed past the exceptional one.
			if _, _, err := journal.Append(billableReceipt("normal")); err != nil {
				t.Fatal(err)
			}
			for restart := 0; restart < 2; restart++ {
				if err := journal.Close(); err != nil {
					t.Fatal(err)
				}
				if err := ledger.Close(); err != nil {
					t.Fatal(err)
				}
				journal, err = OpenJournal(journalPath)
				if err != nil {
					t.Fatal(err)
				}
				ledger, err = OpenDurableLedger(ledgerPath, "tokenhive")
				if err != nil {
					t.Fatal(err)
				}
				processor, err := NewProcessor(journal, ledger)
				if err != nil {
					t.Fatal(err)
				}
				if err := processor.ReplayPending(); err != nil {
					t.Fatalf("restart %d blocked on exceptional receipt: %v", restart, err)
				}
				if n, err := ledger.CancelPending("hub_restarted"); err != nil || n != 1-restart {
					t.Fatalf("interrupted refunds: %d %v", n, err)
				}
				status, ok, err := ledger.Task("consumer-1", receipt.TaskID)
				if err != nil || !ok || status.State != "review_required" || status.ChargeMicros != 0 || status.RefundMicros != 0 || status.InputTokens != 101 || status.ReviewReason != "usage_exceeds_reservation" {
					t.Fatalf("review state not retained: %+v %v", status, err)
				}
				if _, _, err := ledger.Cancel(receipt.TaskID, "task_failed"); !errors.Is(err, ErrLedgerStateConflict) {
					t.Fatalf("review reserve was refundable without reconciliation: %v", err)
				}
				if _, _, err := ledger.Settle(billableReceipt(receipt.TaskID)); !errors.Is(err, ErrLedgerStateConflict) {
					t.Fatalf("conflicting receipt replaced review evidence: %v", err)
				}
				balance, err := ledger.Balance(AccountConsumer, "consumer-1", "USD")
				if err != nil || balance != 1472 {
					t.Fatalf("review reserve or normal settlement changed: %d %v", balance, err)
				}
				provider, err := ledger.Balance(AccountProvider, "provider-7", "USD")
				if err != nil || provider != 20 || len(journal.Records()) != 2 {
					t.Fatalf("payout or evidence changed: %d %v", provider, err)
				}
				if err := processor.RecordReceipt(receipt); !errors.Is(err, ErrUsageExceedsReservation) {
					t.Fatalf("repeated review receipt: %v", err)
				}
			}
		})
	}
}
