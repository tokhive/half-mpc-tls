package settlement

import (
	"errors"
	"sync"
	"testing"

	"tokenhive.local/half-mpc-tls/internal/response"
)

func testPrice() PriceSnapshot {
	return PriceSnapshot{
		ID:                             "price-2026-08",
		Currency:                       "USD",
		ConsumerInputMicrosPerMillion:  2_000_000,
		ConsumerOutputMicrosPerMillion: 6_000_000,
		ProviderInputMicrosPerMillion:  1_500_000,
		ProviderOutputMicrosPerMillion: 4_000_000,
	}
}

func reserveRequest(taskID string) ReserveRequest {
	return ReserveRequest{
		TaskID:                taskID,
		ConsumerID:            "consumer-1",
		ProviderID:            "provider-7",
		RequestHash:           testRequestHash,
		RequestedModel:        "gpt-5",
		AllowedResponseModels: []string{"gpt-5-2026-08-01", "gpt-5"},
		MaxInputTokens:        100,
		MaxOutputTokens:       50,
		Price:                 testPrice(),
	}
}

func fundedLedger(t *testing.T, amount int64) *Ledger {
	t.Helper()
	ledger, err := NewLedger("tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	if created, err := ledger.FundConsumer("funding-1", "consumer-1", "USD", amount); err != nil || !created {
		t.Fatalf("fund consumer: created=%v err=%v", created, err)
	}
	return ledger
}

func TestLedgerReservesSettlesAndSplitsFundsAtomically(t *testing.T) {
	ledger := fundedLedger(t, 1_000)
	request := reserveRequest("task-ledger-1")
	reservation, created, err := ledger.Reserve(request)
	if err != nil || !created {
		t.Fatalf("reserve: created=%v err=%v", created, err)
	}
	if reservation.ReservedMicros != 500 || reservation.State != ReservationPending {
		t.Fatalf("unexpected reservation: %+v", reservation)
	}
	if balance, _ := ledger.Balance(AccountConsumer, "consumer-1", "USD"); balance != 500 {
		t.Fatalf("consumer available after reserve = %d, want 500", balance)
	}

	receipt := billableReceipt("task-ledger-1")
	settled, applied, err := ledger.Settle(receipt)
	if err != nil || !applied {
		t.Fatalf("settle: applied=%v err=%v", applied, err)
	}
	if settled.ConsumerChargeMicros != 28 || settled.ProviderCreditMicros != 20 ||
		settled.PlatformFeeMicros != 8 || settled.ConsumerRefundMicros != 472 {
		t.Fatalf("unexpected split: %+v", settled)
	}
	assertBalance(t, ledger, AccountConsumer, "consumer-1", 972)
	assertBalance(t, ledger, AccountProvider, "provider-7", 20)
	assertBalance(t, ledger, AccountPlatform, "ignored", 8)

	replayed, applied, err := ledger.Settle(receipt)
	if err != nil || applied || replayed != settled {
		t.Fatalf("idempotent settlement: applied=%v result=%+v err=%v", applied, replayed, err)
	}
	if repeated, created, err := ledger.Reserve(request); err != nil || created || repeated.State != ReservationSettled {
		t.Fatalf("idempotent reserve after settlement: created=%v reservation=%+v err=%v", created, repeated, err)
	}
}

func TestLedgerRefundsAuthenticatedNonBillableResponse(t *testing.T) {
	ledger := fundedLedger(t, 1_000)
	if _, _, err := ledger.Reserve(reserveRequest("task-error")); err != nil {
		t.Fatal(err)
	}
	receipt := billableReceipt("task-error")
	receipt.StatusCode = 429
	receipt.Billable = false
	receipt.ResponseModel = ""
	receipt.UpstreamResponseID = ""
	receipt.Usage = response.TokenUsage{}
	settled, applied, err := ledger.Settle(receipt)
	if err != nil || !applied {
		t.Fatalf("settle error response: applied=%v err=%v", applied, err)
	}
	if settled.ConsumerChargeMicros != 0 || settled.ConsumerRefundMicros != 500 || settled.ProviderCreditMicros != 0 {
		t.Fatalf("unexpected error settlement: %+v", settled)
	}
	assertBalance(t, ledger, AccountConsumer, "consumer-1", 1_000)
	assertBalance(t, ledger, AccountProvider, "provider-7", 0)
}

func TestLedgerCancelsUnreceiptedTaskAndRejectsLateSettlement(t *testing.T) {
	ledger := fundedLedger(t, 1_000)
	if _, _, err := ledger.Reserve(reserveRequest("task-timeout")); err != nil {
		t.Fatal(err)
	}
	cancelled, applied, err := ledger.Cancel("task-timeout", "response_timeout")
	if err != nil || !applied || cancelled.RefundMicros != 500 {
		t.Fatalf("cancel: applied=%v result=%+v err=%v", applied, cancelled, err)
	}
	if replayed, applied, err := ledger.Cancel("task-timeout", "response_timeout"); err != nil || applied || replayed != cancelled {
		t.Fatalf("idempotent cancel: applied=%v result=%+v err=%v", applied, replayed, err)
	}
	assertBalance(t, ledger, AccountConsumer, "consumer-1", 1_000)
	if _, _, err := ledger.Settle(billableReceipt("task-timeout")); !errors.Is(err, ErrLedgerStateConflict) {
		t.Fatalf("expected late settlement rejection, got %v", err)
	}
}

func TestLedgerRejectsOveruseBindingMismatchAndInsufficientFunds(t *testing.T) {
	ledger := fundedLedger(t, 499)
	if _, _, err := ledger.Reserve(reserveRequest("task-poor")); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("expected insufficient funds, got %v", err)
	}
	if _, err := ledger.FundConsumer("funding-2", "consumer-1", "USD", 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ledger.Reserve(reserveRequest("task-guarded")); err != nil {
		t.Fatal(err)
	}
	overuse := billableReceipt("task-guarded")
	overuse.Usage = response.TokenUsage{InputTokens: 101, OutputTokens: 2, TotalTokens: 103}
	if _, _, err := ledger.Settle(overuse); !errors.Is(err, ErrUsageExceedsReservation) {
		t.Fatalf("expected overuse rejection, got %v", err)
	}
	mismatch := billableReceipt("task-guarded")
	mismatch.RequestHash = testResponseHash
	if _, _, err := ledger.Settle(mismatch); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("expected binding rejection, got %v", err)
	}
	modelSwap := billableReceipt("task-guarded")
	modelSwap.ResponseModel = "cheap-model"
	if _, _, err := ledger.Settle(modelSwap); !errors.Is(err, ErrTaskConflict) {
		t.Fatalf("expected model allowlist rejection, got %v", err)
	}
}

func TestLedgerFundingAndConcurrentSettlementAreIdempotent(t *testing.T) {
	ledger := fundedLedger(t, 1_000)
	if created, err := ledger.FundConsumer("funding-1", "consumer-1", "USD", 1_000); err != nil || created {
		t.Fatalf("funding replay: created=%v err=%v", created, err)
	}
	if _, err := ledger.FundConsumer("funding-1", "consumer-1", "USD", 999); !errors.Is(err, ErrFundingConflict) {
		t.Fatalf("expected funding conflict, got %v", err)
	}
	if _, _, err := ledger.Reserve(reserveRequest("task-concurrent-ledger")); err != nil {
		t.Fatal(err)
	}
	receipt := billableReceipt("task-concurrent-ledger")
	var wait sync.WaitGroup
	applied := make(chan bool, 16)
	errorsSeen := make(chan error, 16)
	for range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, wasApplied, settleErr := ledger.Settle(receipt)
			applied <- wasApplied
			errorsSeen <- settleErr
		}()
	}
	wait.Wait()
	close(applied)
	close(errorsSeen)
	count := 0
	for value := range applied {
		if value {
			count++
		}
	}
	for settleErr := range errorsSeen {
		if settleErr != nil {
			t.Fatal(settleErr)
		}
	}
	if count != 1 {
		t.Fatalf("settlement applied %d times", count)
	}
	assertBalance(t, ledger, AccountProvider, "provider-7", 20)
}

func TestRoundedTokenCostUsesMicrosWithoutFloatingPoint(t *testing.T) {
	if cost, err := roundedTokenCost(1, 1); err != nil || cost != 1 {
		t.Fatalf("minimum rounded cost = %d, err=%v", cost, err)
	}
	if cost, err := roundedTokenCost(1_000_000, 2_000_000); err != nil || cost != 2_000_000 {
		t.Fatalf("unit cost = %d, err=%v", cost, err)
	}
	price := testPrice()
	price.ProviderInputMicrosPerMillion = price.ConsumerInputMicrosPerMillion + 1
	request := reserveRequest("task-invalid-price")
	request.Price = price
	if _, _, err := fundedLedger(t, 1_000).Reserve(request); !errors.Is(err, ErrInvalidLedgerInput) {
		t.Fatalf("expected inverted price rejection, got %v", err)
	}
}

func assertBalance(t *testing.T, ledger *Ledger, role AccountRole, accountID string, expected int64) {
	t.Helper()
	actual, err := ledger.Balance(role, accountID, "USD")
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("%s balance = %d, want %d", role, actual, expected)
	}
}
