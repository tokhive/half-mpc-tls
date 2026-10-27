package session

import (
	"errors"
	"fmt"
	"sync"
)

type State uint8

const (
	StateNew State = iota
	StateTCPConnecting
	StateMPCHandshaking
	StateReady
	StateEncryptingRequest
	StateWaitingResponse
	StateDraining
	StateClosed
)

func (s State) String() string {
	switch s {
	case StateNew:
		return "NEW"
	case StateTCPConnecting:
		return "TCP_CONNECTING"
	case StateMPCHandshaking:
		return "MPC_HANDSHAKING"
	case StateReady:
		return "READY"
	case StateEncryptingRequest:
		return "ENCRYPTING_REQUEST"
	case StateWaitingResponse:
		return "WAITING_RESPONSE"
	case StateDraining:
		return "DRAINING"
	case StateClosed:
		return "CLOSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", s)
	}
}

var ErrInvalidTransition = errors.New("invalid session state transition")

var allowedTransitions = map[State]map[State]bool{
	StateNew:               {StateTCPConnecting: true, StateClosed: true},
	StateTCPConnecting:     {StateMPCHandshaking: true, StateClosed: true},
	StateMPCHandshaking:    {StateReady: true, StateClosed: true},
	StateReady:             {StateEncryptingRequest: true, StateDraining: true, StateClosed: true},
	StateEncryptingRequest: {StateWaitingResponse: true, StateClosed: true},
	StateWaitingResponse:   {StateReady: true, StateDraining: true, StateClosed: true},
	StateDraining:          {StateClosed: true},
	StateClosed:            {},
}

type Machine struct {
	mu               sync.Mutex
	state            State
	requestWritten   bool
	responseComplete bool
	clientSequence   uint64
	serverSequence   uint64
}

func NewMachine() *Machine {
	return &Machine{state: StateNew}
}

func (m *Machine) Transition(next State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !allowedTransitions[m.state][next] {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, m.state, next)
	}
	if m.state == StateWaitingResponse && next == StateReady && !m.responseComplete {
		return fmt.Errorf("%w: response is not complete", ErrInvalidTransition)
	}
	m.state = next
	if next == StateEncryptingRequest {
		m.requestWritten = false
	}
	if next == StateWaitingResponse {
		m.responseComplete = false
	}
	return nil
}

func (m *Machine) MarkResponseComplete() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateWaitingResponse {
		return fmt.Errorf("cannot complete response in state %s", m.state)
	}
	m.responseComplete = true
	return nil
}

func (m *Machine) Snapshot() (State, uint64, uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state, m.clientSequence, m.serverSequence, m.requestWritten
}

func (m *Machine) MarkRequestWritten() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateEncryptingRequest && m.state != StateWaitingResponse {
		return fmt.Errorf("cannot mark request written in state %s", m.state)
	}
	m.requestWritten = true
	return nil
}

func (m *Machine) NextClientSequence() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateEncryptingRequest {
		return 0, fmt.Errorf("cannot consume client sequence in state %s", m.state)
	}
	current := m.clientSequence
	m.clientSequence++
	return current, nil
}

func (m *Machine) NextServerSequence() (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != StateWaitingResponse {
		return 0, fmt.Errorf("cannot consume server sequence in state %s", m.state)
	}
	current := m.serverSequence
	m.serverSequence++
	return current, nil
}

func (m *Machine) RetrySafe() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return !m.requestWritten
}
