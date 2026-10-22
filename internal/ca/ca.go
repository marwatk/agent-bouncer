// Package ca manages bouncer's local certificate authorities: an X.509 CA
// used to mint leaf certificates for intercepted TLS hosts, and an SSH CA
// used to sign host certificates for terminated SSH connections.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	certFile    = "ca.pem"
	keyFile     = "ca-key.pem"
	sshCAFile   = "ssh-ca"
	sshHostFile = "ssh-host-key"
	leafTTL     = 7 * 24 * time.Hour
)

// Authority holds the TLS and SSH CAs.
type Authority struct {
	dir     string
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer

	leaves sync.Map // host -> *leaf

	sshCA      ssh.Signer
	sshHostKey ssh.Signer
	sshCerts   sync.Map // host -> ssh.Signer
}

type leaf struct {
	cert   *tls.Certificate
	expiry time.Time
}

// LoadOrCreate loads the CAs from dir, generating them on first use.
func LoadOrCreate(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	a := &Authority{dir: dir}
	if err := a.loadTLS(); err != nil {
		return nil, err
	}
	var err error
	if a.sshCA, err = loadOrCreateSSHKey(filepath.Join(dir, sshCAFile)); err != nil {
		return nil, err
	}
	if a.sshHostKey, err = loadOrCreateSSHKey(filepath.Join(dir, sshHostFile)); err != nil {
		return nil, err
	}
	return a, nil
}

// CertPath is the PEM file containing just the bouncer CA certificate.
func (a *Authority) CertPath() string { return filepath.Join(a.dir, certFile) }

// CertPEM returns the CA certificate in PEM form.
func (a *Authority) CertPEM() []byte { return a.certPEM }

// Cert returns the parsed CA certificate.
func (a *Authority) Cert() *x509.Certificate { return a.cert }

func (a *Authority) loadTLS() error {
	cp, kp := filepath.Join(a.dir, certFile), filepath.Join(a.dir, keyFile)
	certPEM, cerr := os.ReadFile(cp)
	keyPEM, kerr := os.ReadFile(kp)
	if errors.Is(cerr, os.ErrNotExist) && errors.Is(kerr, os.ErrNotExist) {
		return a.createTLS(cp, kp)
	}
	if cerr != nil {
		return cerr
	}
	if kerr != nil {
		return kerr
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}
	a.cert, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	a.key = pair.PrivateKey.(crypto.Signer)
	a.certPEM = certPEM
	return nil
}

func (a *Authority) createTLS(cp, kp string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "agent-bouncer local CA (" + host + ")", Organization: []string{"agent-bouncer"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(cp, certPEM, 0o644); err != nil {
		return err
	}
	a.cert, _ = x509.ParseCertificate(der)
	a.key = key
	a.certPEM = certPEM
	return nil
}

// Leaf returns a TLS certificate for host signed by the CA, cached in memory.
func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	if v, ok := a.leaves.Load(host); ok {
		l := v.(*leaf)
		if time.Until(l.expiry) > time.Hour {
			return l.cert, nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafTTL),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, key.Public(), a.key)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: key}
	a.leaves.Store(host, &leaf{cert: cert, expiry: tmpl.NotAfter})
	return cert, nil
}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func loadOrCreateSSHKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return ssh.ParsePrivateKey(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "agent-bouncer")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// SSHKnownHostsLine is a known_hosts entry trusting the bouncer SSH CA for all hosts.
func (a *Authority) SSHKnownHostsLine() string {
	return "@cert-authority * " + string(ssh.MarshalAuthorizedKey(a.sshCA.PublicKey()))
}

// SSHHostSigner returns a host-certificate signer valid for host.
func (a *Authority) SSHHostSigner(host string) (ssh.Signer, error) {
	if v, ok := a.sshCerts.Load(host); ok {
		return v.(ssh.Signer), nil
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             a.sshHostKey.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "agent-bouncer:" + host,
		ValidPrincipals: []string{host},
		ValidAfter:      uint64(now.Add(-time.Hour).Unix()),
		ValidBefore:     uint64(now.AddDate(1, 0, 0).Unix()),
	}
	if err := cert.SignCert(rand.Reader, a.sshCA); err != nil {
		return nil, err
	}
	s, err := ssh.NewCertSigner(cert, a.sshHostKey)
	if err != nil {
		return nil, err
	}
	a.sshCerts.Store(host, s)
	return s, nil
}

// SSHCAPublicKey is the SSH CA's public key.
func (a *Authority) SSHCAPublicKey() ssh.PublicKey { return a.sshCA.PublicKey() }
