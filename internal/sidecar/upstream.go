package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

// BridgeProviderUpstream relays a Provider sidecar's TLS byte stream over an
// upstream connection. Each sidecar-originated frame is acknowledged only
// after all of its bytes have been accepted by upstream.Write.
func BridgeProviderUpstream(ctx context.Context, attachment *Attachment, upstream net.Conn) error {
	if ctx == nil || attachment == nil || upstream == nil {
		return fmt.Errorf("%w: context, attachment, and upstream connection are required", ErrRPCProtocol)
	}
	if attachment.operation != OperationAttachUpstreamChannel {
		return fmt.Errorf("%w: attachment is not a Provider upstream channel", ErrRPCProtocol)
	}

	abort := func() {
		_ = upstream.Close()
		// Close the transport first so a concurrent framed write cannot keep
		// Attachment.Close blocked before it reaches the underlying socket.
		if attachment.closer != nil {
			_ = attachment.closer.Close()
		}
		_ = attachment.Close()
	}
	defer abort()
	stopCancellation := context.AfterFunc(ctx, abort)
	defer stopCancellation()

	results := make(chan error, 2)
	go func() {
		results <- relaySidecarToUpstream(attachment, upstream)
	}()
	go func() {
		_, err := io.CopyBuffer(attachment, upstream, make([]byte, protocol.MaxDataFrameSize))
		if closeErr := attachment.CloseWrite(); err == nil {
			err = closeErr
		}
		results <- err
	}()

	first := <-results
	if first != nil {
		abort()
	}
	second := <-results
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if first != nil || second != nil {
		return errors.Join(first, second)
	}
	return nil
}

func relaySidecarToUpstream(attachment *Attachment, upstream net.Conn) error {
	hasher := sha256.New()
	var delivered uint64
	for {
		chunk, err := attachment.ReadChunk()
		if errors.Is(err, io.EOF) {
			if closeWriter, ok := upstream.(interface{ CloseWrite() error }); ok {
				return closeWriter.CloseWrite()
			}
			return nil
		}
		if err != nil {
			return err
		}
		if err := writeFull(upstream, chunk); err != nil {
			return fmt.Errorf("write Provider upstream: %w", err)
		}
		if _, err := hasher.Write(chunk); err != nil {
			return err
		}
		if uint64(len(chunk)) > ^uint64(0)-delivered {
			return fmt.Errorf("%w: delivery byte count overflow", ErrRPCProtocol)
		}
		delivered += uint64(len(chunk))
		var digest [sha256.Size]byte
		copy(digest[:], hasher.Sum(nil))
		if err := attachment.AcknowledgeDelivery(protocol.DeliveryAck{
			Bytes:  delivered,
			SHA256: digest,
		}); err != nil {
			return fmt.Errorf("acknowledge Provider upstream delivery: %w", err)
		}
	}
}

func writeFull(destination io.Writer, source []byte) error {
	for len(source) > 0 {
		written, err := destination.Write(source)
		if written > 0 {
			source = source[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
