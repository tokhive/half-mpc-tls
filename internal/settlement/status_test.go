package settlement

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestTaskStatusIsolationDurabilityAndClosedLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.jsonl")
	ledger, err := OpenDurableLedger(path, "tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.FundConsumer("fund", "consumer-1", "USD", 2000); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"settled", "cancelled", "pending"} {
		if _, _, err := ledger.Reserve(reserveRequest(id)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := ledger.Settle(billableReceipt("settled")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Cancel("cancelled", "test"); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Task("consumer-1", "settled"); !errors.Is(err, ErrDurableLedgerClosed) {
		t.Fatal(err)
	}
	ledger, err = OpenDurableLedger(path, "tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	settled, ok, err := ledger.Task("consumer-1", "settled")
	if err != nil || !ok || settled.State != ReservationSettled || settled.ChargeMicros != 28 || settled.RefundMicros != 472 {
		t.Fatalf("%+v %v %v", settled, ok, err)
	}
	cancelled, ok, err := ledger.Task("consumer-1", "cancelled")
	if err != nil || !ok || cancelled.State != ReservationCancelled || cancelled.ChargeMicros != 0 || cancelled.RefundMicros != 500 {
		t.Fatalf("%+v %v %v", cancelled, ok, err)
	}
	pending, ok, err := ledger.Task("consumer-1", "pending")
	if err != nil || !ok || pending.State != ReservationPending {
		t.Fatalf("%+v %v %v", pending, ok, err)
	}
	for _, id := range []string{"settled", "cancelled", "pending", "missing"} {
		if _, ok, err := ledger.Task("consumer-2", id); err != nil || ok {
			t.Fatalf("foreign task leaked: %s %v", id, err)
		}
	}
}
