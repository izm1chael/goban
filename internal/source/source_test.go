package source

import (
	"testing"
	"time"
)

func TestHub_SubscribeUnsubscribe(t *testing.T) {
	h := NewHub()
	ch := h.Subscribe("rule-a", 4)

	// A Broadcast while subscribed should deliver.
	h.Broadcast(LogLine{Source: "test", Text: "hello"})
	select {
	case line := <-ch:
		if line.Text != "hello" {
			t.Errorf("got %q, want %q", line.Text, "hello")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for broadcast")
	}

	if h.SubscriberCount() != 1 {
		t.Errorf("SubscriberCount before unsubscribe = %d, want 1", h.SubscriberCount())
	}

	h.Unsubscribe("rule-a")

	if h.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount after unsubscribe = %d, want 0", h.SubscriberCount())
	}

	// The channel must be closed — consumer's range over it should terminate.
	if _, ok := <-ch; ok {
		t.Error("channel should be closed after Unsubscribe")
	}

	// Subsequent Broadcasts don't deliver to the removed subscriber.
	h.Broadcast(LogLine{Source: "test", Text: "after-unsub"})
	if _, ok := <-ch; ok {
		t.Error("channel must remain closed after re-broadcast")
	}
}

func TestHub_UnsubscribeUnknownIsNoOp(t *testing.T) {
	h := NewHub()
	// Unsubscribing a name that was never subscribed must not panic.
	h.Unsubscribe("never-subscribed")
	if h.SubscriberCount() != 0 {
		t.Errorf("SubscriberCount = %d, want 0", h.SubscriberCount())
	}
}

func TestHub_UnsubscribeTwiceIsNoOp(t *testing.T) {
	// Double-unsubscribe must NOT double-close (would panic).
	h := NewHub()
	_ = h.Subscribe("rule", 1)
	h.Unsubscribe("rule")
	h.Unsubscribe("rule") // should not panic
}

func TestHub_CloseAfterUnsubscribe(t *testing.T) {
	// Hub.Close() must tolerate already-unsubscribed subscribers.
	h := NewHub()
	_ = h.Subscribe("a", 1)
	_ = h.Subscribe("b", 1)
	h.Unsubscribe("a")
	h.Close() // should close "b" without panicking on the missing "a"
}

func TestHub_BroadcastDropsOnFullBuffer(t *testing.T) {
	h := NewHub()
	ch := h.Subscribe("slow", 1)
	// Fill the buffer
	h.Broadcast(LogLine{Text: "1"})
	// Next broadcast must drop (non-blocking send)
	delivered := h.Broadcast(LogLine{Text: "2"})
	if delivered != 0 {
		t.Errorf("delivered = %d on full buffer, want 0", delivered)
	}
	// First line is still there
	if line := <-ch; line.Text != "1" {
		t.Errorf("got %q, want 1", line.Text)
	}
}
