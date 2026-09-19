// Package legacytls implements the deliberately small TLS 1.0 server subset
// used by the HP2010 PC client's embedded ProtoSSL implementation.
package legacytls

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"time"
)

func Server(conn net.Conn, config *Config) *Conn {
	return &Conn{Conn: conn, config: config, firstRecord: true, version: tls10}
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

func NewListener(inner net.Listener, config *Config) net.Listener {
	return &listener{Listener: inner, config: config}
}

func (c *Conn) Handshake() error {
	c.once.Do(func() { c.hsErr = c.handshake() })
	return c.hsErr
}

func (c *Conn) trace(event string, attrs ...any) {

	if c.config == nil || c.config.Trace == nil {
		return
	}

	base := []any{"remote", c.RemoteAddr()}
	c.config.Trace(event, append(base, attrs...)...)

}

func (c *Conn) Read(p []byte) (int, error) {

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.readBuf.Len() == 0 {

		typ, data, err := c.readRecord()
		if err != nil {
			return 0, err
		}

		switch typ {
		case recordApplicationData:
			c.readBuf.Write(data)

		case recordAlert:
			if len(data) >= 2 && data[1] == 0 {
				return 0, io.EOF
			}
			return 0, fmt.Errorf("legacytls: peer alert %x", data)

		default:
			return 0, fmt.Errorf("legacytls: unexpected record type %d", typ)
		}

	}

	return c.readBuf.Read(p)

}

func (c *Conn) Write(p []byte) (int, error) {

	if err := c.Handshake(); err != nil {
		return 0, err
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	written := 0

	for len(p) > 0 {

		n := len(p)
		if n > 16384 {
			n = 16384
		}

		if err := c.writeRecord(recordApplicationData, p[:n]); err != nil {
			return written, err
		}

		written += n
		p = p[n:]

	}

	return written, nil

}

func (c *Conn) handshake() error {

	c.trace("handshake started")

	if c.config == nil || c.config.PrivateKey == nil || len(c.config.Certificate) == 0 {
		return errors.New("legacytls: certificate and RSA private key required")
	}

	typ, clientHello, err := c.readRecord()
	if err != nil {
		return err
	}

	if typ != recordHandshake {
		return fmt.Errorf("legacytls: expected ClientHello, got record %d", typ)
	}

	msgs, err := splitHandshake(clientHello)
	if err != nil || len(msgs) != 1 || msgs[0][0] != 1 {
		return errors.New("legacytls: malformed ClientHello")
	}

	ch := msgs[0]
	if len(ch) < 4+2+32+1 {
		return errors.New("legacytls: short ClientHello")
	}

	body := ch[4:]
	clientVersion := binary.BigEndian.Uint16(body[:2])

	if clientVersion != ssl30 && clientVersion != tls10 {
		return fmt.Errorf("legacytls: unsupported ClientHello version %04x", clientVersion)
	}

	c.version = clientVersion
	clientRandom := append([]byte(nil), body[2:34]...)
	off := 34
	sidLen := int(body[off])
	off++

	if off+sidLen+2 > len(body) {
		return errors.New("legacytls: malformed session id")
	}

	off += sidLen
	csLen := int(binary.BigEndian.Uint16(body[off:]))
	off += 2

	if csLen%2 != 0 || off+csLen+1 > len(body) {
		return errors.New("legacytls: malformed cipher suites")
	}

	suite := uint16(0)

	for i := off; i < off+csLen; i += 2 {
		s := binary.BigEndian.Uint16(body[i:])
		if s == suiteRC4SHA {
			suite = s
			break
		}
		if s == suiteRC4MD5 {
			suite = s
		}
	}

	if suite == 0 {
		return errors.New("legacytls: client did not offer RSA/RC4")
	}

	versionName := "TLS1.0"
	if c.version == ssl30 {
		versionName = "SSL3.0"
	}

	suiteName := "TLS_RSA_WITH_RC4_128_SHA"
	if suite == suiteRC4MD5 {
		suiteName = "TLS_RSA_WITH_RC4_128_MD5"
	}

	c.trace("ClientHello accepted", "version", versionName, "cipher", suiteName,
		"session_id_bytes", sidLen)

	serverRandom := make([]byte, 32)
	binary.BigEndian.PutUint32(serverRandom, uint32(time.Now().Unix()))
	if _, err := io.ReadFull(rand.Reader, serverRandom[4:]); err != nil {
		return err
	}

	shBody := make([]byte, 38)
	binary.BigEndian.PutUint16(shBody, c.version)
	copy(shBody[2:34], serverRandom)
	shBody[34] = 0
	binary.BigEndian.PutUint16(shBody[35:37], suite)
	shBody[37] = 0
	sh := handshakeMessage(2, shBody)

	certLen := 0
	for _, cert := range c.config.Certificate {
		certLen += 3 + len(cert)
	}

	certBody := make([]byte, 3+certLen)
	putUint24(certBody, certLen)

	pos := 3
	for _, cert := range c.config.Certificate {

		putUint24(certBody[pos:], len(cert))
		pos += 3
		copy(certBody[pos:], cert)
		pos += len(cert)

	}

	certMsg := handshakeMessage(11, certBody)
	done := handshakeMessage(14, nil)
	transcript := append(append(append([]byte{}, ch...), sh...), certMsg...)
	transcript = append(transcript, done...)

	if err := c.writeRawRecord(recordHandshake, append(append(sh, certMsg...), done...)); err != nil {
		return err
	}

	c.trace("server certificate flight sent", "chain_certificates", len(c.config.Certificate),
		"chain_bytes", certLen)

	typ, ckxData, err := c.readRecord()
	if err != nil {
		return fmt.Errorf("legacytls: waiting for ClientKeyExchange: %w", err)
	}
	if typ != recordHandshake {
		return errors.New("legacytls: expected ClientKeyExchange")
	}

	ckxMsgs, err := splitHandshake(ckxData)
	if err != nil || len(ckxMsgs) != 1 || ckxMsgs[0][0] != 16 {
		return errors.New("legacytls: malformed ClientKeyExchange")
	}

	ckx := ckxMsgs[0]
	transcript = append(transcript, ckx...)

	enc := ckx[4:]
	if len(enc) >= 2 && int(binary.BigEndian.Uint16(enc)) == len(enc)-2 {
		enc = enc[2:]
	}

	premaster, err := rsa.DecryptPKCS1v15(rand.Reader, c.config.PrivateKey, enc)
	if err != nil || len(premaster) != 48 {
		return errors.New("legacytls: RSA premaster decryption failed")
	}

	c.trace("ClientKeyExchange accepted")

	master := masterSecret(c.version, premaster, clientRandom, serverRandom)
	macLen := 20
	newHash := sha1.New
	if suite == suiteRC4MD5 {
		macLen = 16
		newHash = md5.New
	}

	keyBlock := expandKeys(c.version, master, clientRandom, serverRandom, 2*macLen+32)
	clientMAC := keyBlock[:macLen]
	serverMAC := keyBlock[macLen : 2*macLen]
	clientKey := keyBlock[2*macLen : 2*macLen+16]
	serverKey := keyBlock[2*macLen+16:]

	typ, ccs, err := c.readRecord()
	if err != nil {
		return fmt.Errorf("legacytls: waiting for ChangeCipherSpec: %w", err)
	}
	if typ != recordChangeCipherSpec || !bytes.Equal(ccs, []byte{1}) {
		return errors.New("legacytls: expected ChangeCipherSpec")
	}

	c.trace("client ChangeCipherSpec received")

	c.in = makeCipher(clientKey, clientMAC, newHash, c.version)

	typ, finData, err := c.readRecord()
	if err != nil {
		return fmt.Errorf("legacytls: waiting for encrypted Finished: %w", err)
	}
	if typ != recordHandshake {
		return errors.New("legacytls: expected encrypted Finished")
	}

	finMsgs, err := splitHandshake(finData)

	finishedLen := 12
	if c.version == ssl30 {
		finishedLen = 36
	}

	if err != nil || len(finMsgs) != 1 || finMsgs[0][0] != 20 || len(finMsgs[0]) != 4+finishedLen {
		return errors.New("legacytls: malformed client Finished")
	}

	want := finishedVerify(c.version, master, transcript, true)

	if subtle.ConstantTimeCompare(finMsgs[0][4:], want) != 1 {
		return errors.New("legacytls: client Finished verification failed")
	}

	c.trace("client Finished verified")

	transcript = append(transcript, finMsgs[0]...)
	if err := c.writeRawRecord(recordChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	c.out = makeCipher(serverKey, serverMAC, newHash, c.version)
	serverFinished := handshakeMessage(20, finishedVerify(c.version, master, transcript, false))

	if err := c.writeRecord(recordHandshake, serverFinished); err != nil {
		return err
	}

	c.trace("handshake complete")

	return nil

}

func makeCipher(key, macKey []byte, newHash func() hash.Hash, version uint16) cipherState {
	s, _ := rc4.NewCipher(key)
	return cipherState{active: true, stream: s, macKey: append([]byte(nil), macKey...), newHash: newHash, version: version}
}

func (c *Conn) readRecord() (byte, []byte, error) {

	h := make([]byte, 5)

	if _, err := io.ReadFull(c.Conn, h); err != nil {
		return 0, nil, err
	}

	version := binary.BigEndian.Uint16(h[1:3])
	if version != c.version && !(c.firstRecord && version == ssl30 && h[0] == recordHandshake) {
		return 0, nil, fmt.Errorf("legacytls: unsupported record version %x", h[1:3])
	}

	c.firstRecord = false

	n := int(binary.BigEndian.Uint16(h[3:5]))
	if n > 18432 {
		return 0, nil, errors.New("legacytls: oversized record")
	}

	b := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, b); err != nil {
		return 0, nil, err
	}

	if c.in.active {

		c.in.stream.XORKeyStream(b, b)

		macLen := c.in.newHash().Size()
		if len(b) < macLen {
			return 0, nil, errors.New("legacytls: short encrypted record")
		}

		plain, got := b[:len(b)-macLen], b[len(b)-macLen:]
		want := recordMAC(&c.in, h[0], plain)
		if subtle.ConstantTimeCompare(got, want) != 1 {
			return 0, nil, errors.New("legacytls: bad record MAC")
		}

		b = plain
		c.in.seq++

	}

	if h[0] == recordAlert {

		if len(b) >= 2 {
			c.trace("peer alert received", "level", b[0], "description", b[1])
		} else {
			c.trace("malformed peer alert received", "bytes", len(b))
		}

	}

	return h[0], b, nil

}

func (c *Conn) writeRawRecord(typ byte, data []byte) error {

	h := []byte{typ, byte(c.version >> 8), byte(c.version), byte(len(data) >> 8), byte(len(data))}
	packet := append(h, data...)

	for len(packet) != 0 {

		n, err := c.Conn.Write(packet)
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

func (c *Conn) writeRecord(typ byte, plain []byte) error {

	data := append([]byte(nil), plain...)

	if c.out.active {

		data = append(data, recordMAC(&c.out, typ, plain)...)
		c.out.stream.XORKeyStream(data, data)
		c.out.seq++

	}

	return c.writeRawRecord(typ, data)

}

func recordMAC(s *cipherState, typ byte, data []byte) []byte {

	if s.version == ssl30 {

		padLen := 40
		if s.newHash().Size() == md5.Size {
			padLen = 48
		}

		var seq [8]byte
		binary.BigEndian.PutUint64(seq[:], s.seq)
		inner := s.newHash()
		inner.Write(s.macKey)
		inner.Write(bytes.Repeat([]byte{0x36}, padLen))
		inner.Write(seq[:])
		inner.Write([]byte{typ, byte(len(data) >> 8), byte(len(data))})
		inner.Write(data)
		outer := s.newHash()
		outer.Write(s.macKey)
		outer.Write(bytes.Repeat([]byte{0x5c}, padLen))
		outer.Write(inner.Sum(nil))

		return outer.Sum(nil)

	}

	var seq [8]byte
	h := hmac.New(s.newHash, s.macKey)

	binary.BigEndian.PutUint64(seq[:], s.seq)
	h.Write(seq[:])
	h.Write([]byte{typ, 3, 1, byte(len(data) >> 8), byte(len(data))})
	h.Write(data)

	return h.Sum(nil)
}

func handshakeMessage(typ byte, body []byte) []byte {

	b := make([]byte, 4+len(body))
	b[0] = typ
	putUint24(b[1:], len(body))
	copy(b[4:], body)

	return b

}

func putUint24(b []byte, n int) { b[0] = byte(n >> 16); b[1] = byte(n >> 8); b[2] = byte(n) }

func splitHandshake(b []byte) ([][]byte, error) {

	var out [][]byte

	for len(b) > 0 {

		if len(b) < 4 {
			return nil, io.ErrUnexpectedEOF
		}

		n := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
		if n+4 > len(b) {
			return nil, io.ErrUnexpectedEOF
		}

		out = append(out, b[:n+4])
		b = b[n+4:]

	}

	return out, nil

}

func handshakeHash(b []byte) []byte { m := md5.Sum(b); s := sha1.Sum(b); return append(m[:], s[:]...) }

func masterSecret(version uint16, premaster, clientRandom, serverRandom []byte) []byte {

	if version == tls10 {
		return prf(premaster, "master secret", concat(clientRandom, serverRandom), 48)
	}

	return ssl3Generate(premaster, concat(clientRandom, serverRandom), 48)

}

func expandKeys(version uint16, master, clientRandom, serverRandom []byte, n int) []byte {

	if version == tls10 {
		return prf(master, "key expansion", concat(serverRandom, clientRandom), n)
	}

	return ssl3Generate(master, concat(serverRandom, clientRandom), n)

}

func concat(a, b []byte) []byte {

	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)

	return append(out, b...)

}

func ssl3Generate(secret, randoms []byte, n int) []byte {

	out := make([]byte, 0, n)

	for i := 1; len(out) < n; i++ {

		letter := byte('A' + i - 1)
		s := sha1.New()
		s.Write(bytes.Repeat([]byte{letter}, i))
		s.Write(secret)
		s.Write(randoms)
		m := md5.New()
		m.Write(secret)
		m.Write(s.Sum(nil))
		out = append(out, m.Sum(nil)...)

	}

	return out[:n]

}

func finishedVerify(version uint16, master, transcript []byte, client bool) []byte {

	if version == tls10 {

		label := "server finished"

		if client {
			label = "client finished"
		}

		return prf(master, label, handshakeHash(transcript), 12)

	}

	sender := []byte("SRVR")

	if client {
		sender = []byte("CLNT")
	}

	return append(ssl3FinishedHash(md5.New, 48, master, transcript, sender), ssl3FinishedHash(sha1.New, 40, master, transcript, sender)...)

}

func ssl3FinishedHash(newHash func() hash.Hash, padLen int, master, transcript, sender []byte) []byte {

	inner := newHash()
	inner.Write(transcript)
	inner.Write(sender)
	inner.Write(master)
	inner.Write(bytes.Repeat([]byte{0x36}, padLen))

	outer := newHash()
	outer.Write(master)
	outer.Write(bytes.Repeat([]byte{0x5c}, padLen))
	outer.Write(inner.Sum(nil))

	return outer.Sum(nil)

}

func prf(secret []byte, label string, seed []byte, n int) []byte {

	full := append([]byte(label), seed...)
	half := (len(secret) + 1) / 2
	a := pHash(md5.New, secret[:half], full, n)
	b := pHash(sha1.New, secret[len(secret)-half:], full, n)

	for i := range a {
		a[i] ^= b[i]
	}

	return a

}

func pHash(newHash func() hash.Hash, secret, seed []byte, n int) []byte {

	out := make([]byte, 0, n)
	a := seed

	for len(out) < n {

		h := hmac.New(newHash, secret)
		h.Write(a)
		a = h.Sum(nil)
		h = hmac.New(newHash, secret)
		h.Write(a)
		h.Write(seed)
		out = append(out, h.Sum(nil)...)

	}

	return out[:n]

}

// GenerateSelfSigned creates a local certificate compatible with the 2010
// DirtySDK X.509 parser. That parser recognizes RSA/MD2, RSA/MD5 and RSA/SHA-1
// signatures only, and matches hosts against Subject.CommonName rather than
// subjectAltName.
func GenerateSelfSigned(hosts ...string) (*Config, error) {

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	commonName := "localhost"

	if len(hosts) != 0 && hosts[0] != "" {
		commonName = hosts[0]
	}

	tmpl := &x509.Certificate{
		SerialNumber:       new(big.Int).SetInt64(now.UnixNano()),
		Subject:            pkix.Name{CommonName: commonName, Organization: []string{"ReOrigin Local Emulator"}},
		NotBefore:          now.Add(-time.Hour),
		NotAfter:           now.AddDate(10, 0, 0),
		SignatureAlgorithm: x509.SHA1WithRSA,
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:           hosts,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return &Config{Certificate: [][]byte{der}, PrivateKey: key}, nil

}
