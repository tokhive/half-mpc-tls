package session

import (
	"errors"
	"testing"
)

func TestHappyPath(t *testing.T) {
	machine := NewMachine()
	for _, state := range []State{
		StateTCPConnecting,
		StateMPCHandshaking,
		StateReady,
		StateEncryptingRequest,
	} {
		if err := machine.Transition(state); err != nil {
			t.Fatalf("transition to %s: %v", state, err)
		}
	}

	sequence, err := machine.NextClientSequence()
	if err != nil || sequence != 0 {
		t.Fatalf("client sequence: %d, %v", sequence, err)
	}
	if err := machine.MarkRequestWritten(); err != nil {
		t.Fatal(err)
	}
	if machine.RetrySafe() {
		t.Fatal("request must not be retryable after bytes are written")
	}

	if err := machine.Transition(StateWaitingResponse); err != nil {
		t.Fatal(err)
	}
	sequence, err = machine.NextServerSequence()
	if err != nil || sequence != 0 {
		t.Fatalf("server sequence: %d, %v", sequence, err)
	}
	if err := machine.Transition(StateReady); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected incomplete response rejection, got %v", err)
	}
	if err := machine.MarkResponseComplete(); err != nil {
		t.Fatal(err)
	}
	if err := machine.Transition(StateReady); err != nil {
		t.Fatal(err)
	}
}

func TestResponseCompletionOnlyAppliesWhileWaiting(t *testing.T) {
	machine := NewMachine()
	if err := machine.MarkResponseComplete(); err == nil {
		t.Fatal("expected response completion state error")
	}
	for _, state := range []State{
		StateTCPConnecting,
		StateMPCHandshaking,
		StateReady,
		StateEncryptingRequest,
		StateWaitingResponse,
	} {
		if err := machine.Transition(state); err != nil {
			t.Fatal(err)
		}
	}
	if err := machine.MarkResponseComplete(); err != nil {
		t.Fatal(err)
	}
	if err := machine.Transition(StateDraining); err != nil {
		t.Fatal(err)
	}
	if err := machine.Transition(StateClosed); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsInvalidTransition(t *testing.T) {
	machine := NewMachine()
	err := machine.Transition(StateReady)
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
}
