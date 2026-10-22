package ca

import (
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLeafVerifiesAgainstCA(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := a.Leaf("gitlab.com")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(leaf.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(a.Cert())
	if _, err := c.Verify(x509.VerifyOptions{DNSName: "gitlab.com", Roots: pool}); err != nil {
		t.Fatal(err)
	}
	// Reload from disk yields the same CA.
	b, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !b.Cert().Equal(a.Cert()) {
		t.Fatal("CA changed on reload")
	}
	if err := b.WriteBundle(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(b.BundlePath())
	if len(data) < 10000 {
		t.Fatalf("bundle suspiciously small: %d bytes", len(data))
	}
}

func TestSSHHostCert(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := a.SSHHostSigner("gitlab.com")
	if err != nil {
		t.Fatal(err)
	}
	cert := s.PublicKey().(*ssh.Certificate)
	checker := &ssh.CertChecker{IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
		return string(k.Marshal()) == string(a.sshCA.PublicKey().Marshal())
	}}
	if err := checker.CheckHostKey("gitlab.com:22", nil, cert); err != nil {
		t.Fatal(err)
	}
	if err := checker.CheckHostKey("github.com:22", nil, cert); err == nil {
		t.Fatal("cert should not be valid for another host")
	}
}

func TestLeafCacheBounded(t *testing.T) {
	a, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxLeaves+50; i++ {
		if _, err := a.Leaf(fmt.Sprintf("h%d.example.com", i)); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(a.leaves); n > maxLeaves {
		t.Fatalf("leaf cache grew to %d", n)
	}
}
