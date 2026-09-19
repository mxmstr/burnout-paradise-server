package easo

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustDecodeHex(value string) []byte {

	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}

	return decoded

}

var serverChallenge = mustDecodeHex(
	"ba55778b9e10d44294388f79f770afe3cec0ddfffba532a61ff67726dc862f51" +
		"04b224c1b76d7e1d649c57c7ae5071a1651b988d1baabfd3c3c77b4c0c08c998" +
		"e6ccd21cea00f94b90bdd38cd08838fd5d4506e2",
)

func TestSecureEASODecryptsCapturedAddressFrame(t *testing.T) {
	ciphertext, err := hex.DecodeString("73a7d9707742341eeb00cf15410174f4d17f496bfb0478b5e8ba44f9f29b912f8a906ab2ce5c819e74511b4b834d6f")
	if err != nil {
		t.Fatal(err)
	}
	channel, err := NewSecureEASO(bytes.NewBuffer(ciphertext), serverChallenge[:16], serverChallenge[16:32])
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
	sender, err := NewSecureEASO(&wire, serverChallenge[16:32], serverChallenge[:16])
	if err != nil {
		t.Fatal(err)
	}
	want := Frame{Type: "skey", ID: 7, Payload: []byte("SKEY=$5075626c6963204b6579\n\x00")}
	if err := sender.Write(want); err != nil {
		t.Fatal(err)
	}
	receiver, err := NewSecureEASO(&wire, serverChallenge[:16], serverChallenge[16:32])
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
