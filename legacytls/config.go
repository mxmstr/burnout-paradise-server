package legacytls

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
)

func LoadKeyPair(certFile, keyFile string) (*Config, error) {

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	var certs [][]byte

	for len(certPEM) != 0 {

		var b *pem.Block
		b, certPEM = pem.Decode(certPEM)

		if b == nil {
			break
		}

		if b.Type == "CERTIFICATE" {
			certs = append(certs, b.Bytes)
		}

	}

	if len(certs) == 0 {
		return nil, errors.New("legacytls: no certificates in PEM file")
	}

	b, _ := pem.Decode(keyPEM)
	if b == nil {
		return nil, errors.New("legacytls: no private key in PEM file")
	}

	var key *rsa.PrivateKey
	if k, e := x509.ParsePKCS1PrivateKey(b.Bytes); e == nil {
		key = k
	} else if k, e := x509.ParsePKCS8PrivateKey(b.Bytes); e == nil {
		key, _ = k.(*rsa.PrivateKey)
	}

	if key == nil {
		return nil, errors.New("legacytls: private key is not RSA")
	}

	return &Config{Certificate: certs, PrivateKey: key}, nil

}
