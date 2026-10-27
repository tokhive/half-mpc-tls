package settlement

// TaskStatus is a Consumer-only view of committed billing state. It excludes
// Provider identity, payout rates, credentials and request/response bodies.
type TaskStatus struct {
	TaskID         string           `json:"task_id"`
	State          ReservationState `json:"state"`
	Model          string           `json:"model"`
	Currency       string           `json:"currency"`
	ReservedMicros int64            `json:"reserved_micros"`
	ChargeMicros   int64            `json:"charge_micros"`
	RefundMicros   int64            `json:"refund_micros"`
	InputTokens    int64            `json:"input_tokens"`
	OutputTokens   int64            `json:"output_tokens"`
	ReviewReason   string           `json:"review_reason,omitempty"`
}

// Task returns the same not-found result for unknown and foreign tasks.
func (l *Ledger) Task(consumerID, taskID string) (TaskStatus, bool, error) {
	if l == nil {
		return TaskStatus{}, false, ErrInvalidLedgerInput
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, ok := l.tasks[taskID]
	if !ok || entry.reservation.ConsumerID != consumerID {
		return TaskStatus{}, false, nil
	}
	r := entry.reservation
	status := TaskStatus{TaskID: taskID, State: r.State, Model: r.RequestedModel, Currency: r.Price.Currency, ReservedMicros: r.ReservedMicros}
	if settled := entry.settlement; settled != nil {
		status.ChargeMicros = settled.ConsumerChargeMicros
		status.RefundMicros = settled.ConsumerRefundMicros
		status.InputTokens = settled.Receipt.Usage.InputTokens
		status.OutputTokens = settled.Receipt.Usage.OutputTokens
	}
	if cancelled := entry.cancellation; cancelled != nil {
		status.RefundMicros = cancelled.RefundMicros
	}
	if review := entry.review; review != nil {
		status.ReviewReason = "usage_exceeds_reservation"
		status.InputTokens = review.Usage.InputTokens
		status.OutputTokens = review.Usage.OutputTokens
	}
	return status, true, nil
}

// Task only exposes state whose journal transition has completed successfully.
func (d *DurableLedger) Task(consumerID, taskID string) (TaskStatus, bool, error) {
	if d == nil {
		return TaskStatus{}, false, ErrDurableLedgerClosed
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.available(); err != nil {
		return TaskStatus{}, false, err
	}
	return d.ledger.Task(consumerID, taskID)
}
