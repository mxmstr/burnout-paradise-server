package easo

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestTicFixtureRoundTrip(t *testing.T) {
	want, err := hex.DecodeString("4074696300000000000000175243342b4d44352d563200")
	if err != nil {
		t.Fatal(err)
	}

	frame, err := Read(bytes.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != "@tic" || frame.ID != 0 || string(frame.Payload) != "RC4+MD5-V2\x00" {
		t.Fatalf("decoded frame = %#v", frame)
	}

	var got bytes.Buffer
	if err := Write(&got, frame); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Bytes(), want) {
		t.Fatalf("encoded %x, want %x", got.Bytes(), want)
	}
}

func TestReadRejectsInvalidLength(t *testing.T) {
	_, err := Read(bytes.NewReader([]byte("@tic\x00\x00\x00\x00\x00\x00\x00\x0b")))
	if !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("error = %v, want ErrInvalidFrame", err)
	}
}
