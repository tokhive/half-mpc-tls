package settlement

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/gateway"
	"tokenhive.local/half-mpc-tls/internal/response"
)

const (
	testRequestHash  = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testResponseHash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func billableReceipt(taskID string) gateway.Receipt {
	return gateway.Receipt{
		TaskID:             taskID,
		ProviderID:         "provider-7",
		RequestHash:        testRequestHash,
		ResponseHash:       testResponseHash,
		RequestedModel:     "gpt-5",
		ResponseModel:      "gpt-5-2026-08-01",
		UpstreamRequestID:  "req_1",
		UpstreamResponseID: "chatcmpl_1",
		StatusCode:         200,
		BodyBytes:          128,
		Usage: response.TokenUsage{
			InputTokens:  8,
			OutputTokens: 2,
			TotalTokens:  10,
		},
		Billable: true,
	}
}

func TestJournalIsDurableChainedAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settlement.jsonl")
	now := time.UnixMilli(1_800_000_000_000)
	journal, err := openJournal(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	firstReceipt := billableReceipt("task-1")
	first, created, err := journal.Append(firstReceipt)
	if err != nil || !created {
		t.Fatalf("append first: created=%v err=%v", created, err)
	}
	replayed, created, err := journal.Append(firstReceipt)
	if err != nil || created || replayed != first {
		t.Fatalf("idempotent append: created=%v record=%+v err=%v", created, replayed, err)
	}

	now = now.Add(time.Second)
	second, created, err := journal.Append(billableReceipt("task-2"))
	if err != nil || !created || second.Sequence != 2 || second.PreviousHash != first.Hash {
		t.Fatalf("append second: created=%v record=%+v err=%v", created, second, err)
	}
	conflict := firstReceipt
	conflict.ResponseHash = strings.Repeat("1", 64)
	if _, _, err := journal.Append(conflict); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("expected task conflict, got %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if records := reopened.Records(); len(records) != 2 || records[0] != first || records[1] != second {
		t.Fatalf("unexpected recovered records: %+v", records)
	}
}

func TestJournalSerializesConcurrentTaskRetries(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "settlement.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	receipt := billableReceipt("task-concurrent")
	var wait sync.WaitGroup
	created := make(chan bool, 16)
	errorsSeen := make(chan error, 16)
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, wasCreated, appendErr := journal.Append(receipt)
			created <- wasCreated
			errorsSeen <- appendErr
		}()
	}
	wait.Wait()
	close(created)
	close(errorsSeen)
	createdCount := 0
	for value := range created {
		if value {
			createdCount++
		}
	}
	for appendErr := range errorsSeen {
		if appendErr != nil {
			t.Fatal(appendErr)
		}
	}
	if createdCount != 1 || len(journal.Records()) != 1 {
		t.Fatalf("created=%d records=%d", createdCount, len(journal.Records()))
	}
}

func TestJournalRejectsSecondProcessWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settlement.jsonl")
	first, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := OpenJournal(path); !errors.Is(err, ErrJournalLocked) {
		t.Fatalf("expected writer lock rejection, got %v", err)
	}
}

func TestJournalRecoversOnlyTornFinalRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settlement.jsonl")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Append(billableReceipt("task-1")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"version":1,"sequence":2`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(recovered.Records()) != 1 {
		t.Fatalf("unexpected recovered record count %d", len(recovered.Records()))
	}
	if _, created, err := recovered.Append(billableReceipt("task-2")); err != nil || !created {
		t.Fatalf("append after recovery: created=%v err=%v", created, err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJournalRejectsTamperingAndUnsafePermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "settlement.jsonl")
	journal, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Append(billableReceipt("task-1")); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded = []byte(strings.Replace(string(encoded), `"body_bytes":128`, `"body_bytes":129`, 1))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(path); !errors.Is(err, ErrJournalCorrupt) {
		t.Fatalf("expected corruption rejection, got %v", err)
	}

	unsafePath := filepath.Join(directory, "unsafe.jsonl")
	if err := os.WriteFile(unsafePath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(unsafePath); err == nil {
		t.Fatal("expected unsafe permissions rejection")
	}
}

func TestJournalRejectsInvalidBillingSemantics(t *testing.T) {
	journal, err := OpenJournal(filepath.Join(t.TempDir(), "settlement.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	invalid := billableReceipt("task-invalid")
	invalid.Usage.TotalTokens++
	if _, _, err := journal.Append(invalid); !errors.Is(err, ErrInvalidReceipt) {
		t.Fatalf("expected invalid usage rejection, got %v", err)
	}
	nonBillable := billableReceipt("task-error")
	nonBillable.StatusCode = 429
	nonBillable.Billable = false
	nonBillable.ResponseModel = ""
	nonBillable.UpstreamResponseID = ""
	nonBillable.Usage = response.TokenUsage{}
	if _, created, err := journal.Append(nonBillable); err != nil || !created {
		t.Fatalf("append non-billable: created=%v err=%v", created, err)
	}
}
