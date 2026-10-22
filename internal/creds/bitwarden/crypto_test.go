package bitwarden

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestDerivePBKDF2MatchesIndependentVector(t *testing.T) {
	// Computed with Python's hashlib.pbkdf2_hmac and an independent HKDF-Expand,
	// email user@example.com, password "correct horse battery staple", 1000 iterations.
	id, err := deriveIdentity("user@example.com", "correct horse battery staple", kdfParams{kind: kdfPBKDF2, iterations: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(id.passwordHash); got != "8vx9APjb5Q1wtLcQUtQiEautn2Wd5oBGzkZeyYe9tV4=" {
		t.Fatalf("password hash %s", got)
	}
	if hex.EncodeToString(id.keys.enc) != "a9737f1c8acc561ea1243e4884b3e6e2d29f40db8eaa86627a25f690541f410c" {
		t.Fatalf("enc key %x", id.keys.enc)
	}
	if hex.EncodeToString(id.keys.mac) != "33609f2687de4539dc4038091a460dc9146eb68f1c7bc01d6816fa69c5711cc5" {
		t.Fatalf("mac key %x", id.keys.mac)
	}
}

func TestDeriveArgon2Stretch(t *testing.T) {
	// kdfMemory is megabytes, so 8 must reach argon2 as 8*1024 KiB.
	// The digest is argon2id(password, sha256(email), t=1, m=8192 KiB, p=1).
	email := "user@example.com"
	id, err := deriveIdentity(email, "password", kdfParams{kind: kdfArgon2id, iterations: 1, memory: 8, parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(email))
	master := argon2.IDKey([]byte("password"), sum[:], 1, 8*1024, 1, 32)
	if hex.EncodeToString(master) != "957117176630530b004986b6971e959b78da576af89d4c4eebae54a7df001d3f" {
		t.Fatalf("argon2 vector drifted: %x", master)
	}
	k, err := keysFromMaterial(master)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id.keys.enc, k.enc) || !bytes.Equal(id.keys.mac, k.mac) {
		t.Fatal("argon2 identity was not stretched with HKDF")
	}
}

func TestSymmetricRoundTripAndBadMAC(t *testing.T) {
	k, err := keysFromMaterial(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encryptSymmetric(k, []byte("secret-token"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptString(k, enc)
	if err != nil || got != "secret-token" {
		t.Fatalf("got %q, %v", got, err)
	}
	other, _ := keysFromMaterial(bytes.Repeat([]byte{8}, 32))
	if _, err := decryptString(other, enc); !errors.Is(err, errBadMAC) {
		t.Fatalf("err = %v", err)
	}
	raw := bytes.Repeat([]byte{9}, 64)
	split, err := keysFromMaterial(raw)
	if err != nil || len(split.enc) != 32 || !bytes.Equal(split.mac, raw[32:]) {
		t.Fatalf("split: %x %v", split.mac, err)
	}
}

func TestEndpoints(t *testing.T) {
	api, id, err := endpoints("")
	if err != nil || api != "https://api.bitwarden.com" || id != "https://identity.bitwarden.com" {
		t.Fatalf("%s %s %v", api, id, err)
	}
	api, id, err = endpoints("https://vault.bitwarden.eu/")
	if err != nil || api != "https://api.bitwarden.eu" || id != "https://identity.bitwarden.eu" {
		t.Fatalf("eu: %s %s %v", api, id, err)
	}
	api, id, err = endpoints("https://vault.example.com/bw")
	if err != nil || api != "https://vault.example.com/bw/api" || id != "https://vault.example.com/bw/identity" {
		t.Fatalf("self-hosted: %s %s %v", api, id, err)
	}
	if _, _, err := endpoints("https://user:pass@vault.example.com"); err == nil {
		t.Fatal("expected userinfo to be rejected")
	}
}

func TestDecodePascalCasePrelogin(t *testing.T) {
	var res preloginResponse
	body := []byte(`{"Kdf":"1","KdfIterations":3,"KdfMemory":null,"KdfParallelism":4}`)
	if err := decodeBW(body, &res); err != nil {
		t.Fatal(err)
	}
	if res.KDF != 1 || res.KDFIterations != 3 || res.KDFMemory != 0 || res.KDFParallel != 4 {
		t.Fatalf("%+v", res)
	}
}
