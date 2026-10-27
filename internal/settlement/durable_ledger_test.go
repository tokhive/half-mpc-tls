package settlement

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDurableLedgerRecoversCompleteAccountingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	ledger, err := OpenDurableLedger(path, "tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	if created, err := ledger.FundConsumer("funding-1", "consumer-1", "USD", 1_000); err != nil || !created {
		t.Fatalf("fund: created=%v err=%v", created, err)
	}
	if _, created, err := ledger.Reserve(reserveRequest("task-durable-settle")); err != nil || !created {
		t.Fatalf("reserve: created=%v err=%v", created, err)
	}
	if _, applied, err := ledger.Settle(billableReceipt("task-durable-settle")); err != nil || !applied {
		t.Fatalf("settle: applied=%v err=%v", applied, err)
	}
	if _, created, err := ledger.Reserve(reserveRequest("task-durable-cancel")); err != nil || !created {
		t.Fatalf("reserve cancel task: created=%v err=%v", created, err)
	}
	if _, applied, err := ledger.Cancel("task-durable-cancel", "request_failed"); err != nil || !applied {
		t.Fatalf("cancel: applied=%v err=%v", applied, err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := OpenDurableLedger(path, "tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	consumer, _ := recovered.Balance(AccountConsumer, "consumer-1", "USD")
	provider, _ := recovered.Balance(AccountProvider, "provider-7", "USD")
	platform, _ := recovered.Balance(AccountPlatform, "ignored", "USD")
	if consumer != 972 || provider != 20 || platform != 8 {
		t.Fatalf("recovered balances: consumer=%d provider=%d platform=%d", consumer, provider, platform)
	}
	if _, applied, err := recovered.Settle(billableReceipt("task-durable-settle")); err != nil || applied {
		t.Fatalf("settlement replay: applied=%v err=%v", applied, err)
	}
}

func TestDurableLedgerRejectsSecondWriterAndTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	ledger, err := OpenDurableLedger(path, "tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableLedger(path, "tokenhive"); !errors.Is(err, ErrDurableLedgerLocked) {
		t.Fatalf("expected writer lock, got %v", err)
	}
	if _, err := ledger.FundConsumer("funding-1", "consumer-1", "USD", 1_000); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for index := range data {
		if data[index] == '1' {
			data[index] = '2'
			break
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableLedger(path, "tokenhive"); !errors.Is(err, ErrDurableLedgerCorrupt) {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
}
