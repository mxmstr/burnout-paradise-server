// Package bpserver provides the first-stage Burnout Paradise EASO handshake.
package bpserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/local/reorigin-burnout-paradise/easo"
)

func (s *Server) write(logger *slog.Logger, writeFrame func(easo.Frame) error, frame easo.Frame) error {

	if err := writeFrame(frame); err != nil {
		logger.Warn("write failed", "type", frame.Type, "error", err)
		return err
	}

	logger.Info("outbound frame", "type", frame.Type, "id", frame.ID, "payload_bytes", len(frame.Payload))

	return nil

}

func (s *Server) personaIDFor(persona string) int {

	s.lobbyMu.Lock()
	defer s.lobbyMu.Unlock()

	if id := s.personaIDs[persona]; id != 0 {
		return id
	}

	id := s.nextPersonaID
	s.nextPersonaID++
	s.personaIDs[persona] = id

	return id

}

func ParseSessionID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(value, 10, 32)
	return uint32(parsed), err
}

// Serve accepts connections until the listener closes or ctx is cancelled.
func (s *Server) Serve(ctx context.Context, listener net.Listener, role string) error {

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {

		conn, err := listener.Accept()
		if err != nil {

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return err

		}

		go s.handleConnection(ctx, conn, role)

	}

}

func New(config Config) (*Server, error) {

	if net.ParseIP(config.AdvertiseAddress) == nil {
		return nil, fmt.Errorf("advertise address %q is not an IP address", config.AdvertiseAddress)
	}

	if config.GamePort < 1 || config.GamePort > 65535 {
		return nil, fmt.Errorf("game port %d is invalid", config.GamePort)
	}

	if _, err := hex.DecodeString(config.Mask); err != nil || len(config.Mask) != 32 {
		return nil, errors.New("mask must contain exactly 32 hexadecimal characters")
	}

	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	return &Server{
		config:          config,
		keepalivePeriod: serviceKeepalivePeriod,
		nextPersonaID:   localPersonaID,
		personaIDs:      make(map[string]int),
	}, nil

}
