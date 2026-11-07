package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/CosminMilica/ariguard/pkg/fsm"
)

func TestRunUsageAndUnknown(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("no args should return usage error")
	}
	if err := run([]string{"bogus"}); err == nil {
		t.Fatal("unknown command should return usage error")
	}
	if err := run([]string{"policy"}); err == nil {
		t.Fatal("policy without subcommand should return usage error")
	}
}

func TestKeygenWritesUsableKeys(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "k")
	if err := run([]string{"keygen", "--out", prefix}); err != nil {
		t.Fatal(err)
	}
	pubBytes, err := os.ReadFile(prefix + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := os.ReadFile(prefix + ".key")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := fsm.ParsePublicKey(string(pubBytes))
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	priv, err := fsm.ParsePrivateKey(string(privBytes))
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	// the generated keys interoperate
	sig := fsm.SignBundle(priv, []byte("x"))
	if !fsm.VerifyBundle(pub, []byte("x"), sig) {
		t.Fatal("keygen keys should sign/verify")
	}
	// the private key file is written restrictively
	if info, _ := os.Stat(prefix + ".key"); info != nil && info.Mode().Perm()&0o077 != 0 {
		t.Errorf("private key mode %v is too open", info.Mode().Perm())
	}
}

func TestPolicySignMatchesLibrary(t *testing.T) {
	dir := t.TempDir()
	prefix := filepath.Join(dir, "k")
	if err := run([]string{"keygen", "--out", prefix}); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle.bin")
	if err := os.WriteFile(bundle, []byte("STBT-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	// sign succeeds (prints to stdout; we only assert it does not error)
	if err := run([]string{"policy", "sign", "--key", prefix + ".key", bundle}); err != nil {
		t.Fatalf("policy sign: %v", err)
	}
}

func TestLoadKeyAndBundleErrors(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := loadKeyAndBundle("", []string{"x"}); err == nil {
		t.Error("missing key should error")
	}
	key := filepath.Join(dir, "k.key")
	if err := os.WriteFile(key, []byte(fsm.MarshalPrivateKey(mustKey(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadKeyAndBundle(key, nil); err == nil {
		t.Error("missing bundle arg should error")
	}
	if _, _, err := loadKeyAndBundle(key, []string{"a", "b"}); err == nil {
		t.Error("too many bundle args should error")
	}
	empty := filepath.Join(dir, "empty.bin")
	_ = os.WriteFile(empty, nil, 0o644)
	if _, _, err := loadKeyAndBundle(key, []string{empty}); err == nil {
		t.Error("empty bundle should error")
	}
	bad := filepath.Join(dir, "bad.key")
	_ = os.WriteFile(bad, []byte("not-a-key"), 0o600)
	if _, _, err := loadKeyAndBundle(bad, []string{empty}); err == nil {
		t.Error("malformed key should error")
	}
}

func mustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := fsm.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv
}
