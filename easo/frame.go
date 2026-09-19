// Package easo implements the 12-byte framing used by Burnout Paradise's
// pre-Blaze EA online-services client.
package easo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	HeaderSize   = 12
	MaxFrameSize = 1 << 20
)

var ErrInvalidFrame = errors.New("invalid EASO frame")

// Frame is laid out as a four-byte ASCII type, a big-endian identifier/flags
// word, a big-endian total length, and the payload.
type Frame struct {
	Type    string
	ID      uint32
	Payload []byte
}

func Read(r io.Reader) (Frame, error) {

	var header [HeaderSize]byte

	if _, err := io.ReadFull(r, header[:]); err != nil {
		return Frame{}, err
	}

	length := binary.BigEndian.Uint32(header[8:12])

	if length < HeaderSize || length > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: length %d", ErrInvalidFrame, length)
	}

	payload := make([]byte, int(length)-HeaderSize)

	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}

	return Frame{
		Type:    string(header[0:4]),
		ID:      binary.BigEndian.Uint32(header[4:8]),
		Payload: payload,
	}, nil

}

func Write(w io.Writer, frame Frame) error {

	if len(frame.Type) != 4 {
		return fmt.Errorf("%w: type must contain four bytes", ErrInvalidFrame)
	}

	if len(frame.Payload)+HeaderSize > MaxFrameSize {
		return fmt.Errorf("%w: payload too large", ErrInvalidFrame)
	}

	packet := make([]byte, HeaderSize+len(frame.Payload))
	copy(packet[0:4], frame.Type)
	binary.BigEndian.PutUint32(packet[4:8], frame.ID)
	binary.BigEndian.PutUint32(packet[8:12], uint32(len(packet)))
	copy(packet[12:], frame.Payload)

	for len(packet) != 0 {

		n, err := w.Write(packet)
		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrShortWrite
		}

		packet = packet[n:]

	}

	return nil

}
