package settlement

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestProcessorPersistsBeforeApplyingAndReplaysIdempotently(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ledger := fundedLedger(t, 1_000)
	if _, _, err := ledger.Reserve(reserveRequest("task-processor")); err != nil {
		t.Fatal(err)
	}
	processor, err := NewProcessor(journal, ledger)
	if err != nil {
		t.Fatal(err)
	}
	receipt := billableReceipt("task-processor")
	if err := processor.RecordReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	if len(journal.Records()) != 1 {
		t.Fatalf("durable receipts = %d, want 1", len(journal.Records()))
	}
	assertBalance(t, ledger, AccountProvider, "provider-7", 20)
	if err := processor.RecordReceipt(receipt); err != nil {
		t.Fatalf("idempotent processor retry: %v", err)
	}
	if err := processor.ReplayPending(); err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	assertBalance(t, ledger, AccountProvider, "provider-7", 20)
}

func TestProcessorRecoversJournaledButUnappliedReceipt(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	receipt := billableReceipt("task-recovery")
	if _, _, err := journal.Append(receipt); err != nil {
		t.Fatal(err)
	}
	ledger := fundedLedger(t, 1_000)
	if _, _, err := ledger.Reserve(reserveRequest("task-recovery")); err != nil {
		t.Fatal(err)
	}
	processor, err := NewProcessor(journal, ledger)
	if err != nil {
		t.Fatal(err)
	}
	if err := processor.ReplayPending(); err != nil {
		t.Fatal(err)
	}
	assertBalance(t, ledger, AccountConsumer, "consumer-1", 972)
	assertBalance(t, ledger, AccountProvider, "provider-7", 20)
}

func TestProcessorKeepsReceiptWhenLedgerApplicationFails(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	ledger := fundedLedger(t, 1_000)
	processor, err := NewProcessor(journal, ledger)
	if err != nil {
		t.Fatal(err)
	}
	receipt := billableReceipt("task-missing-reservation")
	err = processor.RecordReceipt(receipt)
	if !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("expected missing reservation, got %v", err)
	}
	if records := journal.Records(); len(records) != 1 || records[0].Receipt != receipt {
		t.Fatalf("receipt was not retained for recovery: %+v", records)
	}
}
