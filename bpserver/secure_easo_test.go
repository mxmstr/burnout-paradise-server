package bpserver

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/local/reorigin-burnout-paradise/easo"
)

func TestSecureEASODecryptsCapturedAddressFrame(t *testing.T) {
	ciphertext, err := hex.DecodeString("73a7d9707742341eeb00cf15410174f4d17f496bfb0478b5e8ba44f9f29b912f8a906ab2ce5c819e74511b4b834d6f")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := newSecureEASO(bytes.NewBuffer(ciphertext), serverChallenge[:16], serverChallenge[16:32])
	if err != nil {
		t.Fatal(err)
	}
	frame, err := channel.Read()
	if err != nil {
		t.Fatal(err)
	}
	if frame.Type != "addr" || frame.ID != 0 || string(frame.Payload) != "ADDR=127.0.0.1\nPORT=54577\n\x00" {
		t.Fatalf("decrypted frame = %#v", frame)
	}
}

func TestSecureEASORoundTrip(t *testing.T) {
	var wire bytes.Buffer
	sender, err := newSecureEASO(&wire, serverChallenge[16:32], serverChallenge[:16])
	if err != nil {
		t.Fatal(err)
	}
	want := easo.Frame{Type: "skey", ID: 7, Payload: []byte("SKEY=$5075626c6963204b6579\n\x00")}
	if err := sender.Write(want); err != nil {
		t.Fatal(err)
	}
	receiver, err := newSecureEASO(&wire, serverChallenge[:16], serverChallenge[16:32])
	if err != nil {
		t.Fatal(err)
	}
	got, err := receiver.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.ID != want.ID || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("round trip = %#v, want %#v", got, want)
	}
}
