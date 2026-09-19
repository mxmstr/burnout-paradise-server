package legacytls

import (
	"bytes"
	"crypto/rc4"
	"crypto/rsa"
	"hash"
	"net"
	"sync"
)

const (
	recordChangeCipherSpec = 20
	recordAlert            = 21
	recordHandshake        = 22
	recordApplicationData  = 23

	ssl30       = 0x0300
	tls10       = 0x0301
	suiteRC4MD5 = 0x0004
	suiteRC4SHA = 0x0005
)

type Config struct {
	Certificate [][]byte
	PrivateKey  *rsa.PrivateKey
	// Trace receives handshake milestones. It must not retain or modify attrs.
	Trace func(event string, attrs ...any)
}

// Conn converts a TLS_RSA_WITH_RC4_* ProtoSSL connection into a net.Conn.
// Handshake is lazy, matching crypto/tls.Conn.
type Conn struct {
	net.Conn
	config          *Config
	once            sync.Once
	hsErr           error
	readMu, writeMu sync.Mutex
	in, out         cipherState
	readBuf         bytes.Buffer
	// Old ProtoSSL uses an SSLv3 record header on its TLS 1.0 ClientHello.
	// The version inside ClientHello remains authoritative.
	firstRecord bool
	version     uint16
}

type cipherState struct {
	active  bool
	stream  *rc4.Cipher
	macKey  []byte
	newHash func() hash.Hash
	seq     uint64
	version uint16
}

type listener struct {
	net.Listener
	config *Config
}
