package bpserver

import (
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/local/reorigin-hotpursuit/legacytls"
)

func TestGenerateDirtySDK64SelfSigned(t *testing.T) {
	config, err := GenerateDirtySDK64SelfSigned("pcburnout08.ea.com", "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateDirtySDK64Certificate(config); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(config.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("certificate public key is not RSA")
	}
	if publicKey.N.BitLen() != dirtySDK64RSAKeyBits {
		t.Fatalf("RSA key has %d bits, want %d", publicKey.N.BitLen(), dirtySDK64RSAKeyBits)
	}
	if leaf.Subject.CommonName != "pcburnout08.ea.com" {
		t.Fatalf("common name is %q", leaf.Subject.CommonName)
	}
	if leaf.SignatureAlgorithm != x509.SHA1WithRSA {
		t.Fatalf("signature algorithm is %v", leaf.SignatureAlgorithm)
	}
}

func TestValidateDirtySDK64CertificateRejects2048BitKey(t *testing.T) {
	config, err := legacytls.GenerateSelfSigned("pcburnout08.ea.com")
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateDirtySDK64Certificate(config)
	if err == nil || !strings.Contains(err.Error(), "at most 1024 bits") {
		t.Fatalf("got %v, want RSA size error", err)
	}
}
