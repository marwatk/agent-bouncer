// Package bitwarden syncs a Bitwarden vault and unlocks it for the life of
// the process. The crypto follows Bitwarden's cipherstring format, the same
// scheme the rbw CLI implements: a KDF'd master key unwraps the account
// key, which unwraps each item.
package bitwarden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	kdfPBKDF2   = 0
	kdfArgon2id = 1

	// Caps keep a hostile or misconfigured server from stalling unlock.
	maxPBKDF2Iterations = 10_000_000
	maxArgon2MemoryMB   = 2048
)

var (
	errBadMAC      = errors.New("mac verification failed")
	errBadPassword = errors.New("incorrect master password")
)

// passwordError is a master-password rejection from the identity server.
type passwordError struct{ message string }

func (e *passwordError) Error() string {
	if e.message != "" {
		return e.message
	}
	return errBadPassword.Error()
}

func (e *passwordError) Is(target error) bool { return target == errBadPassword }

// kdfParams are the prelogin KDF settings. Memory is megabytes, matching
// the server; argon2 wants kibibytes.
type kdfParams struct {
	kind        int
	iterations  uint32
	memory      uint32
	parallelism uint32
}

// keys is a Bitwarden symmetric key: 32 bytes of AES-256 and 32 of HMAC-SHA256.
type keys struct {
	enc, mac []byte
}

type identity struct {
	keys         keys
	passwordHash []byte
}

// deriveIdentity stretches email+password the way Bitwarden (and rbw) do.
// email must already be trimmed and lowercased. A 32-byte master key is
// expanded with HKDF into enc/mac keys; the login password is one extra
// PBKDF2 round over the unstretched master key, standard-base64'd on the wire.
func deriveIdentity(email, password string, p kdfParams) (identity, error) {
	if p.iterations == 0 {
		return identity{}, errors.New("kdf iterations is 0")
	}
	if p.iterations > maxPBKDF2Iterations {
		return identity{}, fmt.Errorf("kdf iterations %d exceed the limit of %d", p.iterations, maxPBKDF2Iterations)
	}
	var master []byte
	switch p.kind {
	case kdfPBKDF2:
		master = pbkdf2.Key([]byte(password), []byte(email), int(p.iterations), 32, sha256.New)
	case kdfArgon2id:
		if p.memory == 0 || p.parallelism == 0 {
			return identity{}, errors.New("argon2 kdf is missing memory or parallelism")
		}
		if p.memory > maxArgon2MemoryMB {
			return identity{}, fmt.Errorf("argon2 memory %d MB exceeds the limit of %d", p.memory, maxArgon2MemoryMB)
		}
		if p.parallelism > 255 {
			return identity{}, fmt.Errorf("argon2 parallelism %d is too high", p.parallelism)
		}
		// rbw hashes the email and feeds argon2 memory as kibibytes.
		salt := sha256.Sum256([]byte(email))
		master = argon2.IDKey([]byte(password), salt[:], p.iterations, p.memory*1024, uint8(p.parallelism), 32)
	default:
		return identity{}, fmt.Errorf("unsupported kdf %d", p.kind)
	}
	hash := pbkdf2.Key(master, []byte(password), 1, 32, sha256.New)
	k, err := keysFromMaterial(master)
	clear(master)
	if err != nil {
		clear(hash)
		return identity{}, err
	}
	return identity{keys: k, passwordHash: hash}, nil
}

// keysFromMaterial accepts a raw 32-byte key (stretched with HKDF, info
// "enc" and "mac") or an already-split 64-byte enc||mac key.
func keysFromMaterial(b []byte) (keys, error) {
	switch len(b) {
	case 32:
		return keys{enc: hkdfExpand(b, []byte("enc"), 32), mac: hkdfExpand(b, []byte("mac"), 32)}, nil
	case 64:
		return keys{enc: append([]byte(nil), b[:32]...), mac: append([]byte(nil), b[32:]...)}, nil
	default:
		return keys{}, fmt.Errorf("unexpected key length %d", len(b))
	}
}

func (k keys) clear() {
	clear(k.enc)
	clear(k.mac)
}

// hkdfExpand is HKDF-Expand (RFC 5869) with SHA-256 and no extract step.
// Bitwarden uses the master key directly as the PRK.
func hkdfExpand(prk, info []byte, length int) []byte {
	h := hmac.New(sha256.New, prk)
	var t, okm []byte
	for i := byte(1); len(okm) < length; i++ {
		h.Reset()
		h.Write(t)
		h.Write(info)
		h.Write([]byte{i})
		t = h.Sum(nil)
		okm = append(okm, t...)
	}
	out := make([]byte, length)
	copy(out, okm)
	return out
}

type cipherString struct {
	typ    byte
	iv, ct []byte
	mac    []byte
}

func parseCipherString(s string) (cipherString, error) {
	i := strings.IndexByte(s, '.')
	if i != 1 || s[0] < '0' || s[0] > '9' {
		return cipherString{}, errors.New("invalid cipherstring")
	}
	typ := s[0] - '0'
	rest := s[i+1:]
	switch typ {
	case 2:
		parts := strings.Split(rest, "|")
		if len(parts) < 2 || len(parts) > 3 {
			return cipherString{}, errors.New("invalid type 2 cipherstring")
		}
		iv, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			return cipherString{}, fmt.Errorf("cipherstring iv: %w", err)
		}
		ct, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return cipherString{}, fmt.Errorf("cipherstring ciphertext: %w", err)
		}
		var mac []byte
		if len(parts) == 3 && parts[2] != "" {
			mac, err = base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				return cipherString{}, fmt.Errorf("cipherstring mac: %w", err)
			}
		}
		return cipherString{typ: typ, iv: iv, ct: ct, mac: mac}, nil
	case 4, 6:
		// Type 6 appends an HMAC that rbw ignores; the ciphertext is RSA-OAEP.
		b64 := rest
		if typ == 6 {
			b64, _, _ = strings.Cut(rest, "|")
		}
		ct, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return cipherString{}, fmt.Errorf("cipherstring ciphertext: %w", err)
		}
		return cipherString{typ: typ, ct: ct}, nil
	default:
		return cipherString{}, fmt.Errorf("unsupported cipherstring type %d", typ)
	}
}

func encryptSymmetric(k keys, plain []byte) (string, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	m := hmac.New(sha256.New, k.mac)
	m.Write(iv)
	m.Write(ct)
	return fmt.Sprintf("2.%s|%s|%s",
		base64.StdEncoding.EncodeToString(iv),
		base64.StdEncoding.EncodeToString(ct),
		base64.StdEncoding.EncodeToString(m.Sum(nil))), nil
}

func decryptBytes(k keys, s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty cipherstring")
	}
	cs, err := parseCipherString(s)
	if err != nil {
		return nil, err
	}
	if cs.typ != 2 {
		return nil, fmt.Errorf("unsupported cipherstring type %d", cs.typ)
	}
	return decryptSymmetric(k, cs)
}

func decryptString(k keys, s string) (string, error) {
	b, err := decryptBytes(k, s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

const maxCipherBytes = 1 << 20

func decryptSymmetric(k keys, cs cipherString) ([]byte, error) {
	if len(cs.mac) == 0 {
		return nil, errors.New("cipherstring has no mac")
	}
	if len(cs.ct) == 0 || len(cs.ct) > maxCipherBytes || len(cs.ct)%aes.BlockSize != 0 || len(cs.iv) != aes.BlockSize {
		return nil, errors.New("invalid ciphertext")
	}
	m := hmac.New(sha256.New, k.mac)
	m.Write(cs.iv)
	m.Write(cs.ct)
	if !hmac.Equal(m.Sum(nil), cs.mac) {
		return nil, errBadMAC
	}
	block, err := aes.NewCipher(k.enc)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(cs.ct))
	cipher.NewCBCDecrypter(block, cs.iv).CryptBlocks(plain, cs.ct)
	return pkcs7Unpad(plain, aes.BlockSize)
}

// decryptOrgKey unwraps an organization key. Personal vaults encrypt it
// with the account RSA key (type 4 or 6); some servers use the account
// symmetric key (type 2) instead.
func decryptOrgKey(user keys, priv *rsa.PrivateKey, enc string) (keys, error) {
	cs, err := parseCipherString(enc)
	if err != nil {
		return keys{}, err
	}
	var raw []byte
	switch cs.typ {
	case 2:
		raw, err = decryptSymmetric(user, cs)
	case 4, 6:
		if priv == nil {
			return keys{}, errors.New("organization key is encrypted with RSA but the account has no private key")
		}
		// Bitwarden's type 4 is RSA-2048 OAEP with SHA-1. SHA-1 is the protocol, not a choice.
		raw, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, cs.ct, nil)
	default:
		err = fmt.Errorf("unsupported organization key type %d", cs.typ)
	}
	if err != nil {
		return keys{}, err
	}
	return keysFromMaterial(raw)
}

func parsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		if k, err2 := x509.ParsePKCS1PrivateKey(der); err2 == nil {
			return k, nil
		}
		return nil, err
	}
	rk, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("account private key is not RSA")
	}
	return rk, nil
}

func pkcs7Pad(b []byte, n int) []byte {
	pad := n - len(b)%n
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(b []byte, n int) ([]byte, error) {
	if len(b) == 0 || len(b)%n != 0 {
		return nil, errors.New("invalid padding")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > n {
		return nil, errors.New("invalid padding")
	}
	for _, c := range b[len(b)-pad:] {
		if int(c) != pad {
			return nil, errors.New("invalid padding")
		}
	}
	return b[:len(b)-pad], nil
}
