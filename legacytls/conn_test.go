package legacytls

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestHandshakeAndApplicationData(t *testing.T) {
	for _, suite := range []uint16{suiteRC4MD5, suiteRC4SHA} {
		t.Run(string(rune(suite)), func(t *testing.T) { testHandshake(t, suite, tls10, tls10) })
		t.Run(string(rune(suite))+"_ssl3_record", func(t *testing.T) { testHandshake(t, suite, tls10, ssl30) })
		t.Run(string(rune(suite))+"_ssl3", func(t *testing.T) { testHandshake(t, suite, ssl30, ssl30) })
	}
}

func TestGeneratedCertificateIsDirtySDKCompatible(t *testing.T) {
	config, err := GenerateSelfSigned("gosredirector.ea.com")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(config.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if cert.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatalf("signature algorithm = %v, want SHA1-RSA", cert.SignatureAlgorithm)
	}
	if cert.Subject.CommonName != "gosredirector.ea.com" {
		t.Fatalf("common name = %q", cert.Subject.CommonName)
	}
}

func testHandshake(t *testing.T, suite, handshakeVersion, initialRecordVersion uint16) {
	config, err := GenerateSelfSigned("localhost")
	if err != nil {
		t.Fatal(err)
	}
	serverNet, clientNet := net.Pipe()
	_ = clientNet.SetDeadline(time.Now().Add(3 * time.Second))
	server := Server(serverNet, config)
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- server.Handshake() }()
	client := &Conn{Conn: clientNet, firstRecord: true, version: handshakeVersion}

	clientRandom := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, clientRandom); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, 41)
	binary.BigEndian.PutUint16(body, handshakeVersion)
	copy(body[2:34], clientRandom)
	body[34] = 0
	binary.BigEndian.PutUint16(body[35:37], 2)
	binary.BigEndian.PutUint16(body[37:39], suite)
	body[39] = 1
	body[40] = 0
	ch := handshakeMessage(1, body)
	if err := writeRawRecordVersion(clientNet, recordHandshake, initialRecordVersion, ch); err != nil {
		t.Fatal(err)
	}
	typ, flight, err := client.readRecord()
	if err != nil || typ != recordHandshake {
		t.Fatalf("server flight: type=%d err=%v", typ, err)
	}
	msgs, err := splitHandshake(flight)
	if err != nil || len(msgs) != 3 {
		t.Fatalf("server messages: %d, %v", len(msgs), err)
	}
	serverRandom := msgs[0][6:38]
	certBody := msgs[1][4:]
	certLen := int(certBody[3])<<16 | int(certBody[4])<<8 | int(certBody[5])
	cert, err := x509.ParseCertificate(certBody[6 : 6+certLen])
	if err != nil {
		t.Fatal(err)
	}
	pub := cert.PublicKey.(*rsa.PublicKey)
	premaster := make([]byte, 48)
	binary.BigEndian.PutUint16(premaster, handshakeVersion)
	if _, err := io.ReadFull(rand.Reader, premaster[2:]); err != nil {
		t.Fatal(err)
	}
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, premaster)
	if err != nil {
		t.Fatal(err)
	}
	ckxBody := make([]byte, 2+len(enc))
	binary.BigEndian.PutUint16(ckxBody, uint16(len(enc)))
	copy(ckxBody[2:], enc)
	ckx := handshakeMessage(16, ckxBody)
	if err := client.writeRawRecord(recordHandshake, ckx); err != nil {
		t.Fatal(err)
	}
	master := masterSecret(handshakeVersion, premaster, clientRandom, serverRandom)
	macLen := 20
	newHash := sha1.New
	if suite == suiteRC4MD5 {
		macLen = 16
		newHash = md5.New
	}
	kb := expandKeys(handshakeVersion, master, clientRandom, serverRandom, 2*macLen+32)
	client.out = makeCipher(kb[2*macLen:2*macLen+16], kb[:macLen], newHash, handshakeVersion)
	serverCipher := makeCipher(kb[2*macLen+16:], kb[macLen:2*macLen], newHash, handshakeVersion)
	if err := client.writeRawRecord(recordChangeCipherSpec, []byte{1}); err != nil {
		t.Fatal(err)
	}
	transcript := append(append(append([]byte{}, ch...), flight...), ckx...)
	clientFinished := handshakeMessage(20, finishedVerify(handshakeVersion, master, transcript, true))
	if err := client.writeRecord(recordHandshake, clientFinished); err != nil {
		t.Fatal(err)
	}
	typ, ccs, err := client.readRecord()
	if err != nil || typ != recordChangeCipherSpec || !bytes.Equal(ccs, []byte{1}) {
		select {
		case serverErr := <-handshakeDone:
			t.Fatalf("server CCS: %x, %v (server: %v)", ccs, err, serverErr)
		default:
			t.Fatalf("server CCS: %x, %v", ccs, err)
		}
	}
	client.in = serverCipher
	typ, sf, err := client.readRecord()
	if err != nil || typ != recordHandshake {
		t.Fatalf("server Finished: %x, %v", sf, err)
	}
	want := handshakeMessage(20, finishedVerify(handshakeVersion, master, append(transcript, clientFinished...), false))
	if !bytes.Equal(sf, want) {
		t.Fatalf("server Finished mismatch: %x != %x", sf, want)
	}
	if err := <-handshakeDone; err != nil {
		t.Fatal(err)
	}

	go func() { _ = client.writeRecord(recordApplicationData, []byte("ping")) }()
	b := make([]byte, 4)
	if _, err := io.ReadFull(server, b); err != nil || string(b) != "ping" {
		t.Fatalf("server read %q: %v", b, err)
	}
	go func() { _, _ = server.Write([]byte("pong")) }()
	typ, b, err = client.readRecord()
	if err != nil || typ != recordApplicationData || string(b) != "pong" {
		t.Fatalf("client read %q: %v", b, err)
	}
	server.Close()
	client.Close()
}

func writeRawRecordVersion(w io.Writer, typ byte, version uint16, data []byte) error {
	header := []byte{typ, byte(version >> 8), byte(version), byte(len(data) >> 8), byte(len(data))}
	_, err := w.Write(append(header, data...))
	return err
}
