package settlement

import (
	"errors"
	"math"
	"sort"
	"sync"

	"tokenhive.local/half-mpc-tls/internal/gateway"
)

const (
	pricingTokenUnit = int64(1_000_000)
	maxPricingRate   = int64(1_000_000_000)
	maxLedgerTokens  = int64(1_000_000_000)
)

var (
	ErrInvalidLedgerInput      = errors.New("invalid ledger input")
	ErrInsufficientFunds       = errors.New("insufficient consumer funds")
	ErrFundingConflict         = errors.New("funding transaction conflicts with existing transaction")
	ErrReservationNotFound     = errors.New("settlement reservation not found")
	ErrUsageExceedsReservation = errors.New("receipt usage exceeds reservation")
	ErrLedgerStateConflict     = errors.New("ledger task is already finalized differently")
)

type AccountRole string

const (
	AccountConsumer AccountRole = "consumer"
	AccountProvider AccountRole = "provider"
	AccountPlatform AccountRole = "platform"
)

type ReservationState string

const (
	ReservationPending   ReservationState = "pending"
	ReservationSettled   ReservationState = "settled"
	ReservationCancelled ReservationState = "cancelled"
)

// PriceSnapshot freezes both the Consumer price and Provider payout for one
// task. Rates are integer currency micros per one million tokens.
type PriceSnapshot struct {
	ID                             string `json:"id"`
	Currency                       string `json:"currency"`
	ConsumerInputMicrosPerMillion  int64  `json:"consumer_input_micros_per_million"`
	ConsumerOutputMicrosPerMillion int64  `json:"consumer_output_micros_per_million"`
	ProviderInputMicrosPerMillion  int64  `json:"provider_input_micros_per_million"`
	ProviderOutputMicrosPerMillion int64  `json:"provider_output_micros_per_million"`
}

type ReserveRequest struct {
	TaskID                string
	ConsumerID            string
	ProviderID            string
	RequestHash           string
	RequestedModel        string
	AllowedResponseModels []string
	MaxInputTokens        int64
	MaxOutputTokens       int64
	Price                 PriceSnapshot
}

type Reservation struct {
	TaskID                string           `json:"task_id"`
	ConsumerID            string           `json:"consumer_id"`
	ProviderID            string           `json:"provider_id"`
	RequestHash           string           `json:"request_hash"`
	RequestedModel        string           `json:"requested_model"`
	AllowedResponseModels []string         `json:"allowed_response_models"`
	MaxInputTokens        int64            `json:"max_input_tokens"`
	MaxOutputTokens       int64            `json:"max_output_tokens"`
	ReservedMicros        int64            `json:"reserved_micros"`
	Price                 PriceSnapshot    `json:"price"`
	State                 ReservationState `json:"state"`
}

type Settlement struct {
	TaskID               string          `json:"task_id"`
	Receipt              gateway.Receipt `json:"receipt"`
	PriceSnapshotID      string          `json:"price_snapshot_id"`
	Currency             string          `json:"currency"`
	ConsumerChargeMicros int64           `json:"consumer_charge_micros"`
	ConsumerRefundMicros int64           `json:"consumer_refund_micros"`
	ProviderCreditMicros int64           `json:"provider_credit_micros"`
	PlatformFeeMicros    int64           `json:"platform_fee_micros"`
}

type Cancellation struct {
	TaskID       string `json:"task_id"`
	ReasonCode   string `json:"reason_code"`
	RefundMicros int64  `json:"refund_micros"`
	Currency     string `json:"currency"`
}

type funding struct {
	ConsumerID string
	Currency   string
	Amount     int64
}

type accountKey struct {
	Role     AccountRole
	ID       string
	Currency string
}

type taskEntry struct {
	reservation  Reservation
	settlement   *Settlement
	cancellation *Cancellation
}

// Ledger is the concurrency-safe reference state machine for account-ledger
// transactions. Production storage should execute each method in a database
// transaction using transaction_id or task_id as its unique key.
type Ledger struct {
	mu                sync.Mutex
	platformAccountID string
	balances          map[accountKey]int64
	fundings          map[string]funding
	tasks             map[string]*taskEntry
}

func NewLedger(platformAccountID string) (*Ledger, error) {
	if !validIdentifier(platformAccountID, 128) {
		return nil, ErrInvalidLedgerInput
	}
	return &Ledger{
		platformAccountID: platformAccountID,
		balances:          make(map[accountKey]int64),
		fundings:          make(map[string]funding),
		tasks:             make(map[string]*taskEntry),
	}, nil
}

// FundConsumer adds externally confirmed funds. transactionID makes retries
// idempotent and must be unique across the ledger.
func (l *Ledger) FundConsumer(transactionID, consumerID, currency string, amountMicros int64) (bool, error) {
	if l == nil || !validIdentifier(transactionID, 128) || !validIdentifier(consumerID, 128) ||
		!validCurrency(currency) || amountMicros <= 0 {
		return false, ErrInvalidLedgerInput
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	next := funding{ConsumerID: consumerID, Currency: currency, Amount: amountMicros}
	if existing, exists := l.fundings[transactionID]; exists {
		if existing == next {
			return false, nil
		}
		return false, ErrFundingConflict
	}
	key := accountKey{Role: AccountConsumer, ID: consumerID, Currency: currency}
	if !canAdd(l.balances[key], amountMicros) {
		return false, ErrInvalidLedgerInput
	}
	l.balances[key] += amountMicros
	l.fundings[transactionID] = next
	return true, nil
}

// Reserve removes the maximum task cost from the Consumer's available
// balance before any upstream bytes are sent.
func (l *Ledger) Reserve(request ReserveRequest) (Reservation, bool, error) {
	reservation, err := buildReservation(request)
	if l == nil || err != nil {
		return Reservation{}, false, ErrInvalidLedgerInput
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, exists := l.tasks[request.TaskID]; exists {
		if equalReservation(existing.reservation, reservation) {
			return cloneReservation(existing.reservation), false, nil
		}
		return Reservation{}, false, ErrTaskConflict
	}
	consumer := accountKey{Role: AccountConsumer, ID: request.ConsumerID, Currency: request.Price.Currency}
	if l.balances[consumer] < reservation.ReservedMicros {
		return Reservation{}, false, ErrInsufficientFunds
	}
	l.balances[consumer] -= reservation.ReservedMicros
	l.tasks[request.TaskID] = &taskEntry{reservation: reservation}
	return cloneReservation(reservation), true, nil
}

// Settle consumes a durable authenticated receipt. It refunds unused reserve,
// credits the Provider, and assigns the difference to the platform atomically.
func (l *Ledger) Settle(receipt gateway.Receipt) (Settlement, bool, error) {
	if l == nil || !validReceipt(receipt) {
		return Settlement{}, false, ErrInvalidReceipt
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.tasks[receipt.TaskID]
	if !exists {
		return Settlement{}, false, ErrReservationNotFound
	}
	if entry.settlement != nil {
		if entry.settlement.Receipt == receipt {
			return *entry.settlement, false, nil
		}
		return Settlement{}, false, ErrLedgerStateConflict
	}
	if entry.cancellation != nil {
		return Settlement{}, false, ErrLedgerStateConflict
	}
	reservation := &entry.reservation
	if receipt.ProviderID != reservation.ProviderID || receipt.RequestHash != reservation.RequestHash ||
		receipt.RequestedModel != reservation.RequestedModel {
		return Settlement{}, false, ErrTaskConflict
	}

	consumerCharge := int64(0)
	providerCredit := int64(0)
	if receipt.Billable {
		if !modelAllowed(receipt.ResponseModel, reservation.AllowedResponseModels) {
			return Settlement{}, false, ErrTaskConflict
		}
		if receipt.Usage.InputTokens > reservation.MaxInputTokens || receipt.Usage.OutputTokens > reservation.MaxOutputTokens {
			return Settlement{}, false, ErrUsageExceedsReservation
		}
		var err error
		consumerCharge, err = usageCost(
			receipt.Usage.InputTokens,
			receipt.Usage.OutputTokens,
			reservation.Price.ConsumerInputMicrosPerMillion,
			reservation.Price.ConsumerOutputMicrosPerMillion,
		)
		if err != nil {
			return Settlement{}, false, err
		}
		providerCredit, err = usageCost(
			receipt.Usage.InputTokens,
			receipt.Usage.OutputTokens,
			reservation.Price.ProviderInputMicrosPerMillion,
			reservation.Price.ProviderOutputMicrosPerMillion,
		)
		if err != nil {
			return Settlement{}, false, err
		}
	}
	if consumerCharge > reservation.ReservedMicros || providerCredit > consumerCharge {
		return Settlement{}, false, ErrUsageExceedsReservation
	}
	refund := reservation.ReservedMicros - consumerCharge
	platformFee := consumerCharge - providerCredit
	consumerKey := accountKey{Role: AccountConsumer, ID: reservation.ConsumerID, Currency: reservation.Price.Currency}
	providerKey := accountKey{Role: AccountProvider, ID: reservation.ProviderID, Currency: reservation.Price.Currency}
	platformKey := accountKey{Role: AccountPlatform, ID: l.platformAccountID, Currency: reservation.Price.Currency}
	if !canAdd(l.balances[consumerKey], refund) || !canAdd(l.balances[providerKey], providerCredit) ||
		!canAdd(l.balances[platformKey], platformFee) {
		return Settlement{}, false, ErrInvalidLedgerInput
	}

	result := Settlement{
		TaskID:               receipt.TaskID,
		Receipt:              receipt,
		PriceSnapshotID:      reservation.Price.ID,
		Currency:             reservation.Price.Currency,
		ConsumerChargeMicros: consumerCharge,
		ConsumerRefundMicros: refund,
		ProviderCreditMicros: providerCredit,
		PlatformFeeMicros:    platformFee,
	}
	l.balances[consumerKey] += refund
	l.balances[providerKey] += providerCredit
	l.balances[platformKey] += platformFee
	reservation.State = ReservationSettled
	entry.settlement = &result
	return result, true, nil
}

// Cancel refunds a pending reservation when no authenticated receipt can be
// produced. reasonCode is stable audit metadata, not a free-form error string.
func (l *Ledger) Cancel(taskID, reasonCode string) (Cancellation, bool, error) {
	if l == nil || !validIdentifier(taskID, 128) || !validIdentifier(reasonCode, 64) {
		return Cancellation{}, false, ErrInvalidLedgerInput
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, exists := l.tasks[taskID]
	if !exists {
		return Cancellation{}, false, ErrReservationNotFound
	}
	if entry.cancellation != nil {
		if entry.cancellation.ReasonCode == reasonCode {
			return *entry.cancellation, false, nil
		}
		return Cancellation{}, false, ErrLedgerStateConflict
	}
	if entry.settlement != nil {
		return Cancellation{}, false, ErrLedgerStateConflict
	}
	reservation := &entry.reservation
	consumerKey := accountKey{Role: AccountConsumer, ID: reservation.ConsumerID, Currency: reservation.Price.Currency}
	if !canAdd(l.balances[consumerKey], reservation.ReservedMicros) {
		return Cancellation{}, false, ErrInvalidLedgerInput
	}
	result := Cancellation{
		TaskID:       taskID,
		ReasonCode:   reasonCode,
		RefundMicros: reservation.ReservedMicros,
		Currency:     reservation.Price.Currency,
	}
	l.balances[consumerKey] += reservation.ReservedMicros
	reservation.State = ReservationCancelled
	entry.cancellation = &result
	return result, true, nil
}

func (l *Ledger) Balance(role AccountRole, accountID, currency string) (int64, error) {
	if l == nil || !validCurrency(currency) ||
		(role != AccountConsumer && role != AccountProvider && role != AccountPlatform) {
		return 0, ErrInvalidLedgerInput
	}
	if role == AccountPlatform {
		accountID = l.platformAccountID
	} else if !validIdentifier(accountID, 128) {
		return 0, ErrInvalidLedgerInput
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.balances[accountKey{Role: role, ID: accountID, Currency: currency}], nil
}

func buildReservation(request ReserveRequest) (Reservation, error) {
	if !validIdentifier(request.TaskID, 128) || !validIdentifier(request.ConsumerID, 128) ||
		!validIdentifier(request.ProviderID, 128) || !validHash(request.RequestHash) ||
		!validModel(request.RequestedModel) || !validPrice(request.Price) ||
		request.MaxInputTokens < 0 || request.MaxOutputTokens < 0 ||
		request.MaxInputTokens > maxLedgerTokens || request.MaxOutputTokens > maxLedgerTokens ||
		request.MaxInputTokens > maxLedgerTokens-request.MaxOutputTokens ||
		request.MaxInputTokens+request.MaxOutputTokens == 0 ||
		len(request.AllowedResponseModels) == 0 || len(request.AllowedResponseModels) > 32 {
		return Reservation{}, ErrInvalidLedgerInput
	}
	allowed := append([]string(nil), request.AllowedResponseModels...)
	sort.Strings(allowed)
	seen := make(map[string]struct{}, len(allowed))
	for _, model := range allowed {
		if !validModel(model) {
			return Reservation{}, ErrInvalidLedgerInput
		}
		if _, exists := seen[model]; exists {
			return Reservation{}, ErrInvalidLedgerInput
		}
		seen[model] = struct{}{}
	}
	reserved, err := usageCost(
		request.MaxInputTokens,
		request.MaxOutputTokens,
		request.Price.ConsumerInputMicrosPerMillion,
		request.Price.ConsumerOutputMicrosPerMillion,
	)
	if err != nil {
		return Reservation{}, err
	}
	return Reservation{
		TaskID:                request.TaskID,
		ConsumerID:            request.ConsumerID,
		ProviderID:            request.ProviderID,
		RequestHash:           request.RequestHash,
		RequestedModel:        request.RequestedModel,
		AllowedResponseModels: allowed,
		MaxInputTokens:        request.MaxInputTokens,
		MaxOutputTokens:       request.MaxOutputTokens,
		ReservedMicros:        reserved,
		Price:                 request.Price,
		State:                 ReservationPending,
	}, nil
}

func validPrice(price PriceSnapshot) bool {
	if !validIdentifier(price.ID, 128) || !validCurrency(price.Currency) {
		return false
	}
	rates := []int64{
		price.ConsumerInputMicrosPerMillion,
		price.ConsumerOutputMicrosPerMillion,
		price.ProviderInputMicrosPerMillion,
		price.ProviderOutputMicrosPerMillion,
	}
	for _, rate := range rates {
		if rate < 0 || rate > maxPricingRate {
			return false
		}
	}
	return price.ProviderInputMicrosPerMillion <= price.ConsumerInputMicrosPerMillion &&
		price.ProviderOutputMicrosPerMillion <= price.ConsumerOutputMicrosPerMillion
}

func usageCost(inputTokens, outputTokens, inputRate, outputRate int64) (int64, error) {
	inputCost, err := roundedTokenCost(inputTokens, inputRate)
	if err != nil {
		return 0, err
	}
	outputCost, err := roundedTokenCost(outputTokens, outputRate)
	if err != nil || inputCost > math.MaxInt64-outputCost {
		return 0, ErrInvalidLedgerInput
	}
	return inputCost + outputCost, nil
}

func roundedTokenCost(tokens, rate int64) (int64, error) {
	if tokens < 0 || tokens > maxLedgerTokens || rate < 0 || rate > maxPricingRate {
		return 0, ErrInvalidLedgerInput
	}
	if tokens == 0 || rate == 0 {
		return 0, nil
	}
	product := tokens * rate
	return (product + pricingTokenUnit - 1) / pricingTokenUnit, nil
}

func validCurrency(currency string) bool {
	if len(currency) < 3 || len(currency) > 8 {
		return false
	}
	for _, character := range []byte(currency) {
		if character < 'A' || character > 'Z' {
			return false
		}
	}
	return true
}

func modelAllowed(model string, allowed []string) bool {
	for _, candidate := range allowed {
		if model == candidate {
			return true
		}
	}
	return false
}

func canAdd(current, delta int64) bool {
	return delta >= 0 && current <= math.MaxInt64-delta
}

func equalReservation(left, right Reservation) bool {
	if left.TaskID != right.TaskID || left.ConsumerID != right.ConsumerID || left.ProviderID != right.ProviderID ||
		left.RequestHash != right.RequestHash || left.RequestedModel != right.RequestedModel ||
		left.MaxInputTokens != right.MaxInputTokens || left.MaxOutputTokens != right.MaxOutputTokens ||
		left.ReservedMicros != right.ReservedMicros || left.Price != right.Price ||
		len(left.AllowedResponseModels) != len(right.AllowedResponseModels) {
		return false
	}
	for index := range left.AllowedResponseModels {
		if left.AllowedResponseModels[index] != right.AllowedResponseModels[index] {
			return false
		}
	}
	return true
}

func cloneReservation(reservation Reservation) Reservation {
	reservation.AllowedResponseModels = append([]string(nil), reservation.AllowedResponseModels...)
	return reservation
}
