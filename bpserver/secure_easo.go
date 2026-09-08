package bpserver

import (
	"crypto/md5" //nolint:gosec // Protocol compatibility with DirtySDK 6.4.
	"crypto/rc4" //nolint:staticcheck // Protocol compatibility with DirtySDK 6.4.
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/local/reorigin-burnout-paradise/easo"
)

const secureFrameMACSize = 8

// secureEASO implements DirtySDK's RC4+MD5-V2 framing. The ordinary 12-byte
// EASO header stores the encrypted frame's total size, including an eight-byte
// prefix of MD5(frame-without-MAC), and then the entire frame is RC4 encrypted.
// Both RC4 streams are continuous across frames.
type secureEASO struct {
	stream      io.ReadWriter
	readCipher  *rc4.Cipher
	writeCipher *rc4.Cipher
}

func newSecureEASO(stream io.ReadWriter, readKey, writeKey []byte) (*secureEASO, error) {
	readCipher, err := rc4.NewCipher(readKey)
	if err != nil {
		return nil, fmt.Errorf("create read cipher: %w", err)
	}
	writeCipher, err := rc4.NewCipher(writeKey)
	if err != nil {
		return nil, fmt.Errorf("create write cipher: %w", err)
	}
	return &secureEASO{stream: stream, readCipher: readCipher, writeCipher: writeCipher}, nil
}

func (s *secureEASO) Read() (easo.Frame, error) {
	header := make([]byte, easo.HeaderSize)
	if _, err := io.ReadFull(s.stream, header); err != nil {
		return easo.Frame{}, err
	}
	s.readCipher.XORKeyStream(header, header)

	wireLength := binary.BigEndian.Uint32(header[8:12])
	if wireLength < easo.HeaderSize+secureFrameMACSize || wireLength > easo.MaxFrameSize+secureFrameMACSize {
		return easo.Frame{}, fmt.Errorf("%w: secure length %d", easo.ErrInvalidFrame, wireLength)
	}
	body := make([]byte, int(wireLength)-easo.HeaderSize)
	if _, err := io.ReadFull(s.stream, body); err != nil {
		return easo.Frame{}, err
	}
	s.readCipher.XORKeyStream(body, body)

	packet := append(header, body...)
	plainLength := len(packet) - secureFrameMACSize
	digest := md5.Sum(packet[:plainLength]) //nolint:gosec // Required by RC4+MD5-V2.
	if subtle.ConstantTimeCompare(packet[plainLength:], digest[:secureFrameMACSize]) != 1 {
		return easo.Frame{}, fmt.Errorf("%w: secure MD5 mismatch", easo.ErrInvalidFrame)
	}
	return easo.Frame{
		Type:    string(packet[0:4]),
		ID:      binary.BigEndian.Uint32(packet[4:8]),
		Payload: append([]byte(nil), packet[easo.HeaderSize:plainLength]...),
	}, nil
}

func (s *secureEASO) Write(frame easo.Frame) error {
	if len(frame.Type) != 4 {
		return fmt.Errorf("%w: type must contain four bytes", easo.ErrInvalidFrame)
	}
	wireLength := easo.HeaderSize + len(frame.Payload) + secureFrameMACSize
	if wireLength > easo.MaxFrameSize+secureFrameMACSize {
		return fmt.Errorf("%w: payload too large", easo.ErrInvalidFrame)
	}

	packet := make([]byte, wireLength)
	copy(packet[0:4], frame.Type)
	binary.BigEndian.PutUint32(packet[4:8], frame.ID)
	binary.BigEndian.PutUint32(packet[8:12], uint32(wireLength))
	copy(packet[easo.HeaderSize:], frame.Payload)
	digest := md5.Sum(packet[:wireLength-secureFrameMACSize]) //nolint:gosec // Required by RC4+MD5-V2.
	copy(packet[wireLength-secureFrameMACSize:], digest[:secureFrameMACSize])
	s.writeCipher.XORKeyStream(packet, packet)
	return writeAll(s.stream, packet)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}
